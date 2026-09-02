"""oneshot-relay — collect exactly one human input during an unattended run.

A script that needs one value from a human, on a machine behind NAT, with no
public address and no inbound firewall rule::

    from oneshot_relay import Field, relay_once

    answer = relay_once(
        "Deploy 2026.09 to production?",
        [Field.text("decision", "yes or no", pattern=r"^(yes|no)$")],
        wait_seconds=300,
    )

The endpoint closes after one submission or after the wait expires. Read the
"Intended use" and "Security model" sections of the README before wiring this
into anything important.
"""
from __future__ import annotations

from .fields import CODE_PATTERN, DEFAULT_MAX_LENGTH, Field
from .notify import Notifier, StdoutNotifier, WebhookNotifier, build_message, redact_url
from .relay import (
    LOCKED_OUT,
    MAX_BODY_BYTES,
    SUBMITTED,
    TIMEOUT,
    Outcome,
    Relay,
    discover_lan_ip,
    relay_once,
)
from .tunnel import QuickTunnel

__all__ = [
    "Relay",
    "Outcome",
    "Field",
    "relay_once",
    "Notifier",
    "StdoutNotifier",
    "WebhookNotifier",
    "QuickTunnel",
    "build_message",
    "redact_url",
    "discover_lan_ip",
    "SUBMITTED",
    "TIMEOUT",
    "LOCKED_OUT",
    "CODE_PATTERN",
    "DEFAULT_MAX_LENGTH",
    "MAX_BODY_BYTES",
    "__version__",
]

__version__ = "0.1.0"
