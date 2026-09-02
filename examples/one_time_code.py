#!/usr/bin/env python3
"""Relay a six-digit second factor from your phone to a headless script.

Intended use: *you* run *your own* automation against *your own* account, the
second factor lives on your phone, and the script runs somewhere you cannot
type on. Never aim this at somebody else's credentials, and never publish the
link — see "Intended use" in the README.

    python3 examples/one_time_code.py
    RELAY_WEBHOOK=https://chat.example.com/hooks/xxxx python3 examples/one_time_code.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oneshot_relay import Field, WebhookNotifier, relay_once  # noqa: E402


def main() -> int:
    webhook = os.environ.get("RELAY_WEBHOOK")
    result = relay_once(
        "Second factor needed",
        [Field.code("code", "6-digit code")],
        wait_seconds=float(os.environ.get("RELAY_WAIT", "180")),
        notifier=WebhookNotifier(webhook) if webhook else None,
        note="The script is waiting on the build machine.",
        # The seal stays on the machine running the script, so a link that
        # leaks into a group chat cannot be used to burn this relay.
        require_seal=True,
    )
    if not result:
        print("Timed out waiting for the code.")
        return 1

    print("code: %s" % result["code"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
