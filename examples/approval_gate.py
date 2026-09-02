#!/usr/bin/env python3
"""Release gate: block a deploy until a human answers on their phone.

    python3 examples/approval_gate.py 2026.09
    RELAY_WEBHOOK=https://chat.example.com/hooks/xxxx python3 examples/approval_gate.py
    RELAY_SEAL=1 python3 examples/approval_gate.py        # also demand the local seal

``RELAY_SEAL`` is worth setting whenever the link travels through a channel
other people can read: the seal is printed on the machine running the script
and is never part of the notification, so a leaked link alone cannot burn the
relay or fake an approval.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oneshot_relay import Field, Relay, WebhookNotifier  # noqa: E402


def build_notifier():
    """Webhook when configured, otherwise print the link locally."""
    url = os.environ.get("RELAY_WEBHOOK")
    if not url:
        return None
    return WebhookNotifier(url, payload_builder=lambda text: {"text": text})


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "the next build"
    with Relay(
        "Deploy %s to production?" % target,
        [
            Field.text("decision", "yes or no", max_length=3, pattern=r"^(yes|no)$"),
            Field.text("ticket", "change ticket", max_length=32, required=False),
        ],
        wait_seconds=float(os.environ.get("RELAY_WAIT", "300")),
        notifier=build_notifier(),
        note="Unattended build machine, behind NAT.",
        require_seal=bool(os.environ.get("RELAY_SEAL")),
    ) as relay:
        outcome = relay.wait()

    if not outcome:
        print("No approval (%s: %s) - aborting deploy." % (outcome.status, outcome.reason))
        return 1
    if outcome.get("decision") != "yes":
        print("Rejected by operator: %r" % outcome.get("decision"))
        return 2

    print("Approved. ticket=%s" % (outcome.get("ticket") or "-"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
