"""One endpoint, one submission, then it is gone.

A :class:`Relay` opens a local HTTP server on a random port, optionally puts a
Cloudflare quick tunnel in front of it, hands the resulting one-time URL to a
notifier, and blocks until a single submission arrives or the wait expires.
Whichever happens first, the endpoint is closed and the tunnel is torn down.

Intended use is *your own* automation asking *you* for one input: a release
gate, an on-call confirmation, a value only a human can read off their own
device. See the "Intended use" section of the README before deploying this
anywhere.

Example::

    from oneshot_relay import Field, relay_once

    answer = relay_once(
        "Deploy 2026.09 to production?",
        [Field.text("decision", "yes or no", pattern=r"^(yes|no)$")],
        wait_seconds=300,
    )
    print(answer)  # {'decision': 'yes'} or None on timeout
"""
from __future__ import annotations

import functools
import secrets
import socket
import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .fields import Field, project_submission, validate_submission
from .notify import Notifier, StdoutNotifier, build_message
from .page import (
    SEAL_FIELD,
    SECURITY_HEADERS,
    render_accepted,
    render_closed,
    render_form,
)
from .tunnel import DEFAULT_BINARY, DEFAULT_STARTUP_TIMEOUT, QuickTunnel

__all__ = [
    "Relay",
    "Outcome",
    "relay_once",
    "discover_lan_ip",
    "SUBMITTED",
    "TIMEOUT",
    "LOCKED_OUT",
    "MAX_BODY_BYTES",
]

#: Terminal statuses of a relay.
SUBMITTED = "submitted"
TIMEOUT = "timeout"
LOCKED_OUT = "locked_out"

_OPEN = "open"
_DONE = "done"
_CLOSED = "closed"

#: ~128 bits of entropy in the URL path. Guessing it is not a viable attack.
TOKEN_BYTES = 16
#: 6 hex characters = 16.7M combinations, retried at most ``seal_attempts`` times.
SEAL_BYTES = 3
DEFAULT_SEAL_ATTEMPTS = 5
DEFAULT_WAIT_SECONDS = 300.0
MAX_FIELDS = 8

#: Reject oversized posts before reading them into memory.
MAX_BODY_BYTES = 8 * 1024
#: Upper bound on how much of an oversized body is drained so that the client
#: can still read our 413 instead of hitting a connection reset.
_DRAIN_LIMIT = 64 * 1024
#: Cap simultaneous handler threads so a flood cannot exhaust the process.
MAX_CONCURRENT = 8

LAN_PROBE_HOST = "1.1.1.1"
LAN_PROBE_PORT = 53


def discover_lan_ip() -> str:
    """Best-effort primary LAN address, used only when ``expose_lan=True``.

    Connects a UDP socket without sending anything, which is enough for the OS
    to pick the outbound interface. Falls back to loopback.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((LAN_PROBE_HOST, LAN_PROBE_PORT))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def _parse_form(body: bytes) -> dict[str, str]:
    """Decode an ``application/x-www-form-urlencoded`` body, first value wins."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
    return {key: (values[0] if values else "").strip() for key, values in parsed.items()}


@dataclass(frozen=True)
class Outcome:
    """What a relay ended up with.

    Truthy only when a submission was accepted, so ``if outcome:`` reads well.
    """

    status: str
    data: dict[str, str] = field(default_factory=dict)
    reason: str = ""

    def __bool__(self) -> bool:
        return self.status == SUBMITTED

    @property
    def submitted(self) -> bool:
        return self.status == SUBMITTED

    def get(self, name: str, default: str | None = None) -> str | None:
        return self.data.get(name, default)


class Relay:
    """A disposable one-submission endpoint.

    Args:
        prompt: Heading shown on the form and in the notification.
        fields: Declared inputs. Only these keys are ever returned.
        wait_seconds: How long :meth:`wait` blocks before giving up.
        notifier: Where the link goes. Defaults to printing locally.
        note: Optional one-line context under the heading.
        extra_lines: Extra lines appended to the notification.
        use_tunnel: Put a Cloudflare quick tunnel in front of the port. When
            ``cloudflared`` is absent the relay quietly stays local-only.
        tunnel_binary: Tunnel executable name or path.
        tunnel_timeout: Hard deadline for the tunnel to publish its URL.
        expose_lan: Also listen on every interface. **Off by default** — the
            loopback bind plus the tunnel already covers remote access, and an
            open LAN bind lets any device on the network reach the form.
        bind_port: Fixed port; ``0`` lets the OS pick.
        require_seal: Demand a short seal that is printed on the machine
            running the script and *never* sent to the notifier. This is the
            mitigation for a link that leaks into a group chat: whoever only
            has the link cannot burn the relay.
        seal_attempts: Wrong-seal tries before the relay locks itself.
    """

    def __init__(
        self,
        prompt: str,
        fields: list[Field],
        *,
        wait_seconds: float = DEFAULT_WAIT_SECONDS,
        notifier: Notifier | None = None,
        note: str = "",
        extra_lines: list[str] | None = None,
        use_tunnel: bool = True,
        tunnel_binary: str = DEFAULT_BINARY,
        tunnel_timeout: float = DEFAULT_STARTUP_TIMEOUT,
        expose_lan: bool = False,
        bind_port: int = 0,
        require_seal: bool = False,
        seal_attempts: int = DEFAULT_SEAL_ATTEMPTS,
    ) -> None:
        if not str(prompt).strip():
            raise ValueError("prompt must not be empty")
        if not fields:
            raise ValueError("at least one field is required")
        if len(fields) > MAX_FIELDS:
            raise ValueError("at most %d fields are supported" % MAX_FIELDS)
        names = [f.name for f in fields]
        if len(set(names)) != len(names):
            raise ValueError("field names must be unique: %r" % (names,))
        for item in fields:
            if not isinstance(item, Field):
                raise TypeError("fields must be Field instances, got %r" % type(item).__name__)
        if float(wait_seconds) <= 0:
            raise ValueError("wait_seconds must be positive")
        if int(seal_attempts) < 1:
            raise ValueError("seal_attempts must be at least 1")

        self.prompt = str(prompt)
        self.fields = list(fields)
        self.wait_seconds = float(wait_seconds)
        self.notifier = notifier if notifier is not None else StdoutNotifier()
        self.note = str(note)
        self.extra_lines = list(extra_lines or [])
        self.use_tunnel = bool(use_tunnel)
        self.tunnel_binary = tunnel_binary
        self.tunnel_timeout = float(tunnel_timeout)
        self.expose_lan = bool(expose_lan)
        self.bind_port = int(bind_port)
        self.require_seal = bool(require_seal)

        self.token = secrets.token_urlsafe(TOKEN_BYTES)
        self.path = "/r/" + self.token
        self.seal = secrets.token_hex(SEAL_BYTES) if self.require_seal else None

        self._lock = threading.RLock()
        self._status = _OPEN
        self._attempts_left = int(seal_attempts) if self.require_seal else 0
        self._data: dict[str, str] = {}
        self._reason = ""
        self._event = threading.Event()
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)
        self._server: ThreadingHTTPServer | None = None
        self._tunnel: QuickTunnel | None = None
        self._port = 0
        self.delivered: bool | None = None

    # ------------------------------------------------------------------ state

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._status == _OPEN

    @property
    def port(self) -> int:
        return self._port

    @property
    def public_url(self) -> str | None:
        """Tunnel base URL, or ``None`` when running local-only."""
        return self._tunnel.url if self._tunnel is not None else None

    @property
    def local_url(self) -> str:
        return "http://127.0.0.1:%d%s" % (self._port, self.path)

    @property
    def links(self) -> list[str]:
        """Every way in, most useful first."""
        out = []
        base = self.public_url
        if base:
            out.append("Public:   %s%s" % (base, self.path))
        if self.expose_lan:
            out.append("LAN:      http://%s:%d%s" % (discover_lan_ip(), self._port, self.path))
        out.append("Loopback: %s" % self.local_url)
        return out

    # -------------------------------------------------------------- lifecycle

    def open(self) -> "Relay":
        """Bind the port, start serving, open the tunnel, deliver the link."""
        if self._server is not None:
            raise RuntimeError("relay is already open")

        bind_host = "0.0.0.0" if self.expose_lan else "127.0.0.1"
        handler = functools.partial(_RequestHandler, relay=self)
        server = ThreadingHTTPServer((bind_host, self.bind_port), handler)
        server.daemon_threads = True
        self._server = server
        self._port = int(server.server_address[1])
        threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.2},
            name="oneshot-relay-http",
            daemon=True,
        ).start()

        if self.use_tunnel:
            self._tunnel = QuickTunnel(
                self._port,
                binary=self.tunnel_binary,
                startup_timeout=self.tunnel_timeout,
            )
            self._tunnel.start()  # None is fine; loopback access still works

        if self.seal is not None:
            print(
                "[oneshot-relay] seal: %s  (printed here only, never sent to the notifier)"
                % self.seal,
                flush=True,
            )

        message = build_message(
            self.prompt, self.links, note=self.note, extra_lines=self.extra_lines
        )
        self.delivered = self.notifier.deliver(message)
        return self

    def wait(self) -> Outcome:
        """Block until a submission arrives, the seal runs out, or time is up."""
        if self._server is None:
            raise RuntimeError("relay is not open; call open() first")
        self._event.wait(self.wait_seconds)
        with self._lock:
            status, data, reason = self._status, dict(self._data), self._reason
        if status == _DONE:
            return Outcome(SUBMITTED, data)
        if status == LOCKED_OUT:
            return Outcome(LOCKED_OUT, {}, reason or "seal attempts exhausted")
        return Outcome(TIMEOUT, {}, reason or "no submission within %.0fs" % self.wait_seconds)

    def close(self) -> None:
        """Shut the endpoint down and stop the tunnel. Idempotent."""
        with self._lock:
            server, tunnel = self._server, self._tunnel
            self._server = None
            self._tunnel = None
            if self._status == _OPEN:
                self._status = _CLOSED
        if server is not None:
            server.shutdown()
            server.server_close()
        if tunnel is not None:
            tunnel.stop()
        self._event.set()

    def run(self) -> Outcome:
        """``open`` + ``wait`` + ``close`` in one call."""
        self.open()
        try:
            return self.wait()
        finally:
            self.close()

    def __enter__(self) -> "Relay":
        return self.open()

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ------------------------------------------- internals used by the handler

    def _form_page(self, error: str = "") -> str:
        return render_form(
            self.prompt,
            self.fields,
            note=self.note,
            error=error,
            seal_required=self.seal is not None,
            attempts_left=self._attempts_left if self.seal is not None else None,
        )

    def _check_seal(self, presented: str) -> tuple[bool, bool]:
        """Compare in constant time. Returns ``(accepted, locked_out)``."""
        with self._lock:
            if self._status != _OPEN:
                return False, True
            if self.seal is not None and secrets.compare_digest(presented, self.seal):
                return True, False
            self._attempts_left -= 1
            if self._attempts_left <= 0:
                self._status = LOCKED_OUT
                self._reason = "seal attempts exhausted"
                self._event.set()
                return False, True
            return False, False

    def _record(self, data: dict[str, str]) -> bool:
        """Claim the single submission slot. Only the first caller wins."""
        with self._lock:
            if self._status != _OPEN:
                return False
            self._status = _DONE
            self._data = dict(data)
            return True

    def _signal(self) -> None:
        """Wake the waiting caller — only after the response has been written."""
        self._event.set()


class _RequestHandler(BaseHTTPRequestHandler):
    """Thin HTTP layer. Every state transition belongs to :class:`Relay`."""

    server_version = "oneshot-relay"
    sys_version = ""

    def __init__(self, *args, relay: Relay, **kwargs) -> None:
        # Bound before super().__init__, which handles the request inline.
        # Instances are created through functools.partial(_RequestHandler, relay=...).
        self.relay = relay
        super().__init__(*args, **kwargs)

    def log_message(self, fmt, *args) -> None:
        """Silenced on purpose: access logs would capture the one-time URL."""

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self._guarded(self._get)

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        self._guarded(self._post)

    def _guarded(self, action) -> None:
        if not self.relay._slots.acquire(timeout=2.0):
            self._plain(503, "busy")
            return
        try:
            action()
        finally:
            self.relay._slots.release()

    def _get(self) -> None:
        if not self._on_route():
            self._plain(404, "not found")
        elif self.relay.is_open:
            self._html(200, self.relay._form_page())
        else:
            self._html(410, render_closed())

    def _post(self) -> None:
        relay = self.relay
        if not self._on_route():
            self._plain(404, "not found")
            return
        if not relay.is_open:
            self._html(410, render_closed())
            return

        body = self._read_body()
        if body is None:
            return  # an error response was already sent
        form = _parse_form(body)

        if relay.seal is not None:
            accepted, locked_out = relay._check_seal(form.get(SEAL_FIELD, ""))
            if locked_out:
                self._html(410, render_closed())
                return
            if not accepted:
                self._html(403, relay._form_page(error="Seal does not match."))
                return

        reason = validate_submission(relay.fields, form)
        if reason is not None:
            self._html(400, relay._form_page(error=reason))
            return

        if not relay._record(project_submission(relay.fields, form)):
            self._html(410, render_closed())  # lost the race with another submitter
            return
        try:
            self._html(200, render_accepted(relay.prompt))
        finally:
            # Signal only after the reply is on the wire, otherwise the caller
            # can tear the server down while the phone is still reading.
            relay._signal()

    def _on_route(self) -> bool:
        """Exact path match. Substring matching would accept ``/x/r/<token>?y``."""
        return urllib.parse.urlsplit(self.path).path == self.relay.path

    def _read_body(self) -> bytes | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._plain(411, "length required")
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self._plain(400, "malformed Content-Length")
            return None
        if length < 0:
            self._plain(400, "malformed Content-Length")
            return None
        if length > MAX_BODY_BYTES:
            if length <= _DRAIN_LIMIT:
                try:
                    self.rfile.read(length)
                except OSError:
                    pass
            self._plain(413, "payload too large")
            return None
        try:
            return self.rfile.read(length) if length else b""
        except OSError:
            self._plain(400, "unreadable body")
            return None

    def _html(self, code: int, body: str) -> None:
        self._emit(code, body, "text/html; charset=utf-8")

    def _plain(self, code: int, body: str) -> None:
        self._emit(code, body, "text/plain; charset=utf-8")

    def _emit(self, code: int, body: str, content_type: str) -> None:
        raw = body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)
        except OSError:
            pass  # the client hung up; there is nothing useful left to do


def relay_once(prompt: str, fields: list[Field], **kwargs) -> dict[str, str] | None:
    """Open a relay, wait for one submission, close it, return the data or ``None``.

    The one-call form for scripts. Keyword arguments are passed to :class:`Relay`.
    """
    with Relay(prompt, fields, **kwargs) as relay:
        outcome = relay.wait()
    return outcome.data if outcome else None
