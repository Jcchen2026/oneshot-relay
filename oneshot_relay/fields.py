"""Field declarations and server-side validation.

A relay only ever accepts the fields it declared: anything else a client sends
is dropped before it reaches the caller. Validation runs on the server because
the browser-side checks are advisory only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "Field",
    "DEFAULT_MAX_LENGTH",
    "CODE_PATTERN",
    "validate_submission",
    "project_submission",
]

DEFAULT_MAX_LENGTH = 100

#: Six digits, the shape most authenticator apps produce.
CODE_PATTERN = r"^[0-9]{6}$"

_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")


@dataclass(frozen=True)
class Field:
    """One input on the disposable form.

    Attributes:
        name: Form key, also the key in the returned dict. ``[A-Za-z][A-Za-z0-9_]*``.
        label: Human-readable caption rendered above the input.
        kind: ``"text"`` for free-form input, ``"code"`` for a numeric one-time
            code that auto-submits once complete.
        max_length: Hard cap enforced on the server, mirrored into the HTML.
        pattern: Optional regular expression the value must match in full.
        required: When False the field may be left empty; length and pattern
            are still enforced on whatever value does arrive.
    """

    name: str
    label: str = ""
    kind: str = "text"
    max_length: int = DEFAULT_MAX_LENGTH
    pattern: str | None = None
    required: bool = True

    def __post_init__(self) -> None:
        if not _FIELD_NAME_RE.match(self.name):
            raise ValueError(
                "field name must match [A-Za-z][A-Za-z0-9_]{0,31}, got %r" % (self.name,)
            )
        if self.kind not in ("text", "code"):
            raise ValueError("field kind must be 'text' or 'code', got %r" % (self.kind,))
        if not 1 <= int(self.max_length) <= 1000:
            raise ValueError("max_length must be between 1 and 1000")
        if self.pattern is not None:
            re.compile(self.pattern)  # fail fast on a broken expression

    @classmethod
    def text(
        cls,
        name: str,
        label: str | None = None,
        *,
        max_length: int = DEFAULT_MAX_LENGTH,
        pattern: str | None = None,
        required: bool = True,
    ) -> Field:
        """Free-form single-line input."""
        return cls(name=name, label=label or name, kind="text",
                   max_length=max_length, pattern=pattern, required=required)

    @classmethod
    def code(cls, name: str, label: str | None = None) -> Field:
        """Numeric one-time code: six digits, auto-submits when complete."""
        return cls(name=name, label=label or "6-digit code", kind="code",
                   max_length=6, pattern=CODE_PATTERN)

    @property
    def caption(self) -> str:
        return self.label or self.name

    def validate(self, value: str) -> str | None:
        """Return ``None`` when the value is acceptable, else a short reason."""
        if not value:
            return "empty" if self.required else None
        if len(value) > self.max_length:
            return "longer than %d characters" % self.max_length
        if self.pattern and not re.match(self.pattern, value):
            return "does not match %s" % self.pattern
        return None


def validate_submission(fields: list[Field], form: dict[str, str]) -> str | None:
    """Validate a parsed form against the declaration.

    Returns ``None`` when every declared field is present and well formed,
    otherwise a reason string safe to show on the form page.
    """
    for field in fields:
        reason = field.validate(form.get(field.name, ""))
        if reason:
            return "%s: %s" % (field.caption, reason)
    return None


def project_submission(fields: list[Field], form: dict[str, str]) -> dict[str, str]:
    """Narrow a raw form down to the declared fields, in declaration order."""
    return {field.name: form.get(field.name, "") for field in fields}
