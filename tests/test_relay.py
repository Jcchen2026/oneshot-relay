"""Tests for oneshot_relay. Standard library only::

    python3 -m unittest discover -s tests -v

Nothing here needs ``cloudflared``: every relay is opened with
``use_tunnel=False`` and reached over loopback.
"""
from __future__ import annotations

import ast
import os
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oneshot_relay import (  # noqa: E402
    LOCKED_OUT,
    MAX_BODY_BYTES,
    SUBMITTED,
    Field,
    Relay,
    relay_once,
)
from oneshot_relay.notify import Notifier, WebhookNotifier, redact_url  # noqa: E402
from oneshot_relay.page import SEAL_FIELD, render_form  # noqa: E402


class CollectNotifier(Notifier):
    """Records messages instead of sending them anywhere."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def deliver(self, message: str) -> bool:
        self.messages.append(message)
        return True


def http_post(url: str, data: dict) -> tuple:
    body = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read().decode("utf-8", "replace")
        finally:
            exc.close()


def http_get(url: str) -> tuple:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status, dict(response.headers), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")
        finally:
            exc.close()


def raw_request(port: int, request_line: str, headers: list, body: bytes = b"") -> tuple:
    """Speak HTTP by hand, so malformed requests can be exercised."""
    head = "\r\n".join([request_line] + headers) + "\r\n\r\n"
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10)
    try:
        sock.sendall(head.encode("utf-8") + body)
        chunks = []
        while True:
            block = sock.recv(4096)
            if not block:
                break
            chunks.append(block)
    finally:
        sock.close()
    raw = b"".join(chunks).decode("utf-8", "replace")
    head_part, _, body_part = raw.partition("\r\n\r\n")
    parts = head_part.split("\r\n", 1)[0].split(" ") if head_part else []
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return code, head_part, body_part


class RelayTestCase(unittest.TestCase):
    """Shared plumbing: open a tunnel-less relay and always close it."""

    def open_relay(self, fields: list, **kwargs) -> tuple:
        notifier = kwargs.pop("notifier", None) or CollectNotifier()
        # Keep the wait short: a broken relay should fail fast, not hang.
        kwargs.setdefault("wait_seconds", 10)
        relay = Relay("Test prompt", fields, use_tunnel=False, notifier=notifier, **kwargs)
        relay.open()
        self.addCleanup(relay.close)
        return relay, notifier

    def submit_in_background(self, url: str, data: dict) -> None:
        threading.Thread(target=http_post, args=(url, data), daemon=True).start()


class FieldTests(unittest.TestCase):
    def test_code_field_accepts_six_digits_only(self):
        field = Field.code("code")
        self.assertIsNone(field.validate("123456"))
        for bad in ("12345", "1234567", "12345a", ""):
            self.assertIsNotNone(field.validate(bad), bad)

    def test_optional_field_accepts_empty_but_still_checks_pattern(self):
        field = Field.text("ticket", required=False, max_length=8, pattern=r"^[A-Z]+-[0-9]+$")
        self.assertIsNone(field.validate(""))
        self.assertIsNone(field.validate("ABC-12"))
        self.assertIsNotNone(field.validate("nope"))
        self.assertIsNotNone(field.validate("ABCDEFGHI"))

    def test_field_name_is_constrained(self):
        for bad in ("", "1abc", "a-b", "_seal", "x" * 40):
            with self.assertRaises(ValueError, msg=bad):
                Field.text(bad)

    def test_seal_field_name_cannot_collide_with_a_declared_field(self):
        with self.assertRaises(ValueError):
            Field.text(SEAL_FIELD)


class PageTests(unittest.TestCase):
    def test_prompt_and_labels_are_escaped(self):
        # Field *names* are constrained by a regex, so the injection vector that
        # remains is caller-supplied free text: prompt, label and error.
        page = render_form(
            "<script>alert(1)</script>",
            [Field.text("answer", 'x" onmouseover="alert(2)')],
            error="<b>boom</b>",
        )
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<b>boom</b>", page)
        self.assertNotIn('onmouseover="alert(2)"', page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&lt;b&gt;boom&lt;/b&gt;", page)
        self.assertIn("onmouseover=&quot;alert(2)", page)

    def test_seal_input_rendered_only_when_required(self):
        fields = [Field.code("code")]
        self.assertNotIn(SEAL_FIELD, render_form("p", fields))
        self.assertIn(SEAL_FIELD, render_form("p", fields, seal_required=True))


class NotifierTests(unittest.TestCase):
    def test_plaintext_webhook_is_refused(self):
        with self.assertRaises(ValueError):
            WebhookNotifier("http://chat.example.com/hooks/secret-key")

    def test_loopback_plaintext_allowed_for_test_doubles(self):
        notifier = WebhookNotifier("http://127.0.0.1:9/hooks/x", allow_insecure=True)
        self.assertFalse(notifier.deliver("nobody is listening"))

    def test_redact_url_drops_the_secret_query(self):
        redacted = redact_url("https://chat.example.com/hooks/send?key=abc123")
        self.assertNotIn("abc123", redacted)
        self.assertIn("chat.example.com/hooks/send", redacted)


class ConstructionTests(unittest.TestCase):
    def test_empty_prompt_rejected(self):
        with self.assertRaises(ValueError):
            Relay("   ", [Field.text("a")])

    def test_no_fields_rejected(self):
        with self.assertRaises(ValueError):
            Relay("p", [])

    def test_duplicate_field_names_rejected(self):
        with self.assertRaises(ValueError):
            Relay("p", [Field.text("a"), Field.text("a")])

    def test_wait_before_open_raises(self):
        with self.assertRaises(RuntimeError):
            Relay("p", [Field.text("a")], use_tunnel=False).wait()


class RelayHttpTests(RelayTestCase):
    def test_roundtrip_code_submission(self):
        relay, notifier = self.open_relay([Field.code("code")])
        self.assertIn(relay.local_url, notifier.messages[0])
        self.submit_in_background(relay.local_url, {"code": "123456"})
        outcome = relay.wait()
        self.assertEqual(outcome.status, SUBMITTED)
        self.assertEqual(outcome.data, {"code": "123456"})
        self.assertTrue(outcome)

    def test_undeclared_fields_never_reach_the_caller(self):
        relay, _ = self.open_relay([Field.text("answer")])
        self.submit_in_background(relay.local_url, {"answer": "go", "evil": "payload"})
        self.assertEqual(relay.wait().data, {"answer": "go"})

    def test_unknown_token_is_404(self):
        relay, _ = self.open_relay([Field.text("answer")])
        status, _, _ = http_get("http://127.0.0.1:%d/r/not-the-token" % relay.port)
        self.assertEqual(status, 404)

    def test_route_requires_an_exact_path_match(self):
        relay, _ = self.open_relay([Field.text("answer")])
        self.assertEqual(http_get(relay.local_url + "/extra")[0], 404)
        self.assertEqual(http_get("http://127.0.0.1:%d/x%s" % (relay.port, relay.path))[0], 404)
        self.assertEqual(http_get(relay.local_url + "?utm=tracker")[0], 200)

    def test_response_refuses_caching_and_referrers(self):
        relay, _ = self.open_relay([Field.text("answer")])
        status, headers, body = http_get(relay.local_url)
        self.assertEqual(status, 200)
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Test prompt", body)

    def test_invalid_input_does_not_consume_the_relay(self):
        relay, _ = self.open_relay([Field.code("code")])
        status, body = http_post(relay.local_url, {"code": "abc"})
        self.assertEqual(status, 400)
        self.assertIn("does not match", body)
        self.assertTrue(relay.is_open)
        self.submit_in_background(relay.local_url, {"code": "654321"})
        self.assertEqual(relay.wait().data, {"code": "654321"})

    def test_second_submission_gets_410(self):
        relay, _ = self.open_relay([Field.text("answer")])
        self.submit_in_background(relay.local_url, {"answer": "one"})
        self.assertEqual(relay.wait().status, SUBMITTED)
        self.assertEqual(http_post(relay.local_url, {"answer": "two"})[0], 410)
        self.assertEqual(http_get(relay.local_url)[0], 410)

    def test_oversized_body_is_rejected_without_consuming(self):
        relay, _ = self.open_relay([Field.text("answer", max_length=1000)])
        body = b"answer=" + b"a" * (MAX_BODY_BYTES + 16)
        code, _, text = raw_request(
            relay.port,
            "POST %s HTTP/1.0" % relay.path,
            ["Content-Type: application/x-www-form-urlencoded",
             "Content-Length: %d" % len(body)],
            body,
        )
        self.assertEqual(code, 413)
        self.assertIn("too large", text)
        self.assertTrue(relay.is_open)

    def test_malformed_content_length_is_rejected(self):
        relay, _ = self.open_relay([Field.text("answer")])
        code, _, _ = raw_request(
            relay.port,
            "POST %s HTTP/1.0" % relay.path,
            ["Content-Type: application/x-www-form-urlencoded",
             "Content-Length: not-a-number"],
        )
        self.assertEqual(code, 400)
        self.assertTrue(relay.is_open)

    def test_missing_content_length_is_rejected(self):
        relay, _ = self.open_relay([Field.text("answer")])
        code, _, _ = raw_request(relay.port, "POST %s HTTP/1.0" % relay.path,
                                 ["Content-Type: application/x-www-form-urlencoded"])
        self.assertEqual(code, 411)

    def test_timeout_yields_none(self):
        data = relay_once("Timeout test", [Field.text("answer")],
                          wait_seconds=0.3, use_tunnel=False, notifier=CollectNotifier())
        self.assertIsNone(data)


class SealTests(RelayTestCase):
    def test_wrong_seal_is_rejected_and_does_not_consume(self):
        relay, _ = self.open_relay([Field.code("code")], require_seal=True, seal_attempts=3)
        status, body = http_post(relay.local_url, {"code": "123456", SEAL_FIELD: "nope"})
        self.assertEqual(status, 403)
        self.assertIn("Seal does not match", body)
        self.assertTrue(relay.is_open)

    def test_correct_seal_is_accepted_and_not_returned(self):
        relay, _ = self.open_relay([Field.code("code")], require_seal=True)
        self.submit_in_background(relay.local_url, {"code": "123456", SEAL_FIELD: relay.seal})
        outcome = relay.wait()
        self.assertEqual(outcome.status, SUBMITTED)
        self.assertEqual(outcome.data, {"code": "123456"})

    def test_seal_is_never_part_of_the_notification(self):
        relay, notifier = self.open_relay([Field.code("code")], require_seal=True)
        self.assertIsNotNone(relay.seal)
        self.assertNotIn(relay.seal, notifier.messages[0])

    def test_exhausted_seal_locks_the_relay_out(self):
        relay, _ = self.open_relay([Field.code("code")], require_seal=True, seal_attempts=2)
        codes = [http_post(relay.local_url, {"code": "123456", SEAL_FIELD: "bad"})[0]
                 for _ in range(2)]
        self.assertEqual(codes, [403, 410])
        outcome = relay.wait()
        self.assertEqual(outcome.status, LOCKED_OUT)
        self.assertFalse(outcome)
        self.assertFalse(relay.is_open)


class Python39CompatibilityTests(unittest.TestCase):
    """``requires-python = ">=3.9"`` has to be true, not just declared.

    Parses every source file with ``feature_version=(3, 9)`` and checks the
    ``__future__`` import that keeps PEP 585/604 annotation syntax out of
    runtime evaluation - without it, ``str | None`` in a signature is a
    ``TypeError`` on 3.9 at import time.
    """

    def test_sources_parse_as_python_39_and_defer_annotations(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sources = []
        for base in ("oneshot_relay", "examples", "tests"):
            directory = os.path.join(root, base)
            for name in sorted(os.listdir(directory)):
                if name.endswith(".py"):
                    sources.append(os.path.join(directory, name))
        self.assertTrue(sources, "no sources found")

        for path in sources:
            with open(path, encoding="utf-8") as handle:
                source = handle.read()
            try:
                tree = ast.parse(source, filename=path, feature_version=(3, 9))
            except SyntaxError as exc:
                self.fail("%s does not parse as Python 3.9: %s" % (path, exc))
                return
            defers = any(
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
                and any(alias.name == "annotations" for alias in node.names)
                for node in tree.body
            )
            self.assertTrue(defers, "%s lacks 'from __future__ import annotations'" % path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
