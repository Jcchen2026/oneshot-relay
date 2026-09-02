"""Delivery of the one-time link.

This package is transport-agnostic. It composes a plain-text message and hands
it to a :class:`Notifier`; it does not know or care which chat system, mail
gateway or log sink sits behind it. The default notifier prints locally, so
nothing leaves the machine unless you ask for it.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

__all__ = [
    "Notifier",
    "StdoutNotifier",
    "WebhookNotifier",
    "build_message",
    "redact_url",
]

DEFAULT_TIMEOUT = 15.0


def build_message(prompt: str, links: list[str], *, note: str = "",
                  extra_lines: list[str] | None = None) -> str:
    """Compose the plain-text message handed to a notifier."""
    lines = [prompt]
    if note:
        lines.append(note)
    lines.extend(links)
    lines.extend(extra_lines or [])
    lines.append("Single use: the endpoint closes right after one submission.")
    return "\n".join(lines)


def redact_url(url: str) -> str:
    """Strip the query string, which is where webhook secrets usually live.

    Use this before putting a webhook URL into a log line or an exception.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparsable-url>"
    query = "?<redacted>" if parts.query else ""
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")) + query


def _require_https(url: str, allow_insecure: bool) -> None:
    """Refuse to carry a one-time credential over a plaintext channel."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return
    loopback = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if loopback and allow_insecure:
        return
    raise ValueError(
        "webhook URL must use https:// (a one-time link is a bearer credential); "
        "got %s — pass allow_insecure=True only for a loopback test double"
        % redact_url(url)
    )


class Notifier:
    """Somewhere to send the one-time link."""

    def deliver(self, message: str) -> bool:
        """Hand over the message. Return True when delivery is believed to have worked."""
        raise NotImplementedError


class StdoutNotifier(Notifier):
    """Print the link on the machine running the script. Nothing is sent anywhere."""

    def __init__(self, prefix: str = "[oneshot-relay] ") -> None:
        self.prefix = prefix

    def deliver(self, message: str) -> bool:
        for line in message.splitlines():
            print(self.prefix + line, flush=True)
        return True


class WebhookNotifier(Notifier):
    """POST the message as JSON to an incoming-webhook endpoint.

    ``payload_builder`` turns the message into the JSON body, which is how any
    chat platform is supported without this package naming it. Recipes are in
    the README.

    The URL is treated as a secret: it is never logged, and error messages only
    ever contain :func:`redact_url` output.
    """

    def __init__(
        self,
        url: str,
        *,
        payload_builder=None,
        timeout: float = DEFAULT_TIMEOUT,
        headers: dict[str, str] | None = None,
        allow_insecure: bool = False,
    ) -> None:
        _require_https(url, allow_insecure)
        self.url = url
        self.payload_builder = payload_builder or (lambda text: {"text": text})
        self.timeout = float(timeout)
        self.headers = {"Content-Type": "application/json"}
        if headers:
            self.headers.update(headers)

    def deliver(self, message: str) -> bool:
        try:
            body = self.payload_builder(message)
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            print("[oneshot-relay] webhook payload is not JSON-serialisable: %s" % exc,
                  flush=True)
            return False

        request = urllib.request.Request(self.url, data=raw, headers=self.headers,
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if not 200 <= response.status < 300:
                    print("[oneshot-relay] webhook returned HTTP %s" % response.status,
                          flush=True)
                    return False
                return True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # exc may embed the URL, so report the type and the redacted target only.
            print("[oneshot-relay] webhook delivery to %s failed: %s"
                  % (redact_url(self.url), type(exc).__name__), flush=True)
            return False
