"""Cloudflare quick tunnel with a hard startup deadline.

``cloudflared tunnel --url http://127.0.0.1:<port>`` dials *out* over TLS and
prints an ephemeral ``https://<label>.trycloudflare.com`` address. No account,
no config file and no inbound firewall rule are involved.

Reading that stdout inline is a trap: the deadline can only be checked after a
line arrives, so a stalled process would block forever. The reader therefore
lives in a worker thread and the caller waits on a queue with a real timeout.
"""
from __future__ import annotations

import queue
import re
import shutil
import subprocess
import threading
import time

__all__ = ["QuickTunnel", "TUNNEL_URL_PATTERN", "DEFAULT_BINARY"]

TUNNEL_URL_PATTERN = re.compile(
    r"https://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.trycloudflare\.com"
)

DEFAULT_BINARY = "cloudflared"
DEFAULT_STARTUP_TIMEOUT = 25.0

_STOP_GRACE = 3.0


def _drain(stream, out: "queue.Queue[str | None]") -> None:
    """Copy process stdout into a queue; ``None`` marks end of stream."""
    try:
        for line in stream:
            out.put(line)
    except (OSError, ValueError):
        pass
    finally:
        out.put(None)
        try:
            stream.close()
        except (OSError, ValueError):
            pass


class QuickTunnel:
    """An ephemeral public URL pointing at a local port.

    The object is inert until :meth:`start` is called, and :meth:`stop` is
    idempotent, so it is safe to use from ``finally`` blocks.
    """

    def __init__(
        self,
        port: int,
        *,
        binary: str = DEFAULT_BINARY,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
        target_host: str = "127.0.0.1",
    ) -> None:
        self.port = int(port)
        self.binary = binary
        self.startup_timeout = float(startup_timeout)
        self.target_host = target_host
        self._proc: subprocess.Popen | None = None
        self._url: str | None = None
        self._lock = threading.Lock()

    @property
    def url(self) -> str | None:
        """Public base URL, or ``None`` when no tunnel is up."""
        return self._url

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> str | None:
        """Open the tunnel and wait for its URL.

        Returns the public base URL, or ``None`` if the binary is missing, the
        process fails to spawn, or no URL shows up within ``startup_timeout``.
        Never raises for those conditions: a tunnel is an optional upgrade over
        loopback access, so callers degrade instead of failing.
        """
        with self._lock:
            if self._url is not None:
                return self._url

            resolved = shutil.which(self.binary)
            if not resolved:
                return None

            target = "http://%s:%d" % (self.target_host, self.port)
            try:
                proc = subprocess.Popen(
                    [resolved, "tunnel", "--url", target, "--no-autoupdate"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
            except OSError:
                return None

            lines: "queue.Queue[str | None]" = queue.Queue()
            threading.Thread(target=_drain, args=(proc.stdout, lines), daemon=True).start()

            deadline = time.monotonic() + self.startup_timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    line = lines.get(timeout=remaining)
                except queue.Empty:
                    break
                if line is None:  # process exited before publishing a URL
                    break
                match = TUNNEL_URL_PATTERN.search(line)
                if match:
                    self._proc = proc
                    self._url = match.group(0)
                    return self._url

            _stop(proc)
            return None

    def stop(self) -> None:
        """Tear the tunnel down. Safe to call twice or before :meth:`start`."""
        with self._lock:
            proc, self._proc = self._proc, None
            self._url = None
        if proc is not None:
            _stop(proc)

    def __enter__(self) -> "QuickTunnel":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def _stop(proc: subprocess.Popen) -> None:
    """Terminate, then kill if the process ignores the request."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=_STOP_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
        proc.wait(timeout=_STOP_GRACE)
    except (OSError, subprocess.TimeoutExpired):
        pass
