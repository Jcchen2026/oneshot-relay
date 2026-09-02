"""Server-rendered HTML for the disposable form.

Every caller-supplied string is passed through :func:`html.escape`. The
stylesheet and the auto-submit script are fixed literals that never contain
interpolated data, so there is no path from a prompt string to script
execution inside the page.
"""
from __future__ import annotations

import html

from .fields import Field

__all__ = [
    "SEAL_FIELD",
    "SECURITY_HEADERS",
    "render_form",
    "render_accepted",
    "render_closed",
]

#: Name of the optional anti-preemption input. Underscore-prefixed so it cannot
#: collide with a declared field name (those must start with a letter).
SEAL_FIELD = "_seal"

#: Sent on every response. ``no-store`` keeps the one-time URL out of caches,
#: ``no-referrer`` keeps its token out of third-party Referer headers.
SECURITY_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; img-src 'none'; "
        "style-src 'unsafe-inline'; script-src 'unsafe-inline'"
    ),
}

_VIEWPORT = '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'

_STYLE = """
body{margin:0;background:#f5f6f8;color:#1c1e21;
     font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:22rem;margin:0 auto;padding:3.5rem 1.25rem}
h1{font-size:1.25rem;margin:0 0 .25rem}
.card{background:#fff;border-radius:.75rem;padding:1.5rem 1.25rem;
      box-shadow:0 1px 3px rgba(0,0,0,.08),0 8px 24px rgba(0,0,0,.05)}
.note{color:#5b6270;font-size:.875rem;margin:.25rem 0 0}
label{display:block;color:#5b6270;font-size:.8125rem;margin:1rem 0 .25rem}
input{width:100%;box-sizing:border-box;padding:.625rem .75rem;font-size:1.125rem;
      border:1px solid #ccd0d6;border-radius:.5rem;background:#fff;color:inherit}
input[data-kind="code"]{letter-spacing:.4em;text-align:center;font-size:1.5rem}
input:focus{outline:2px solid #2f6feb;outline-offset:1px;border-color:#2f6feb}
button{width:100%;margin-top:1.25rem;padding:.75rem;font-size:1rem;font-weight:600;
       border:0;border-radius:.5rem;background:#2f6feb;color:#fff;cursor:pointer}
button:active{background:#255fd4}
.error{margin:1rem 0 0;padding:.625rem .75rem;font-size:.875rem;
       border-radius:.5rem;background:#fdecec;color:#a3232b}
.hint{margin:.75rem 0 0;font-size:.8125rem;color:#8a9099}
.done{text-align:center;padding:3rem 1rem}
.done h1{font-size:1.5rem}
""".strip()

_SCRIPT = """
(function () {
  var codes = document.querySelectorAll('input[data-kind="code"]');
  function complete() {
    for (var i = 0; i < codes.length; i++) {
      if (codes[i].value.length < Number(codes[i].getAttribute('maxlength'))) return false;
    }
    return codes.length > 0;
  }
  for (var i = 0; i < codes.length; i++) {
    codes[i].addEventListener('input', function (event) {
      event.target.value = event.target.value.replace(/[^0-9]/g, '');
      if (complete()) event.target.form.submit();
    });
  }
  var first = document.querySelector('input');
  if (first) first.focus();
})();
""".strip()


def _page(title: str, body: str, *, script: bool = False) -> str:
    parts = [
        "<!doctype html><html lang=\"en\"><head>",
        _VIEWPORT,
        "<title>", html.escape(title, quote=False), "</title>",
        "<style>", _STYLE, "</style>",
        "</head><body><main>",
        body,
        "</main>",
    ]
    if script:
        parts += ["<script>", _SCRIPT, "</script>"]
    parts.append("</body></html>")
    return "".join(parts)


def _input(field: Field) -> str:
    caption = html.escape(field.caption)
    name = html.escape(field.name, quote=True)
    if field.kind == "code":
        attrs = (
            ' type="text" inputmode="numeric" autocomplete="one-time-code"'
            ' data-kind="code" maxlength="6" pattern="[0-9]{6}"'
        )
    else:
        attrs = ' type="text" autocomplete="off" data-kind="text" maxlength="%d"' % field.max_length
    return '<label for="%s">%s</label><input id="%s" name="%s"%s>' % (name, caption, name, name, attrs)


def render_form(
    prompt: str,
    fields: list[Field],
    *,
    note: str = "",
    error: str = "",
    seal_required: bool = False,
    attempts_left: int | None = None,
) -> str:
    """Render the submission page.

    Args:
        prompt: Heading shown to the person on the phone.
        fields: Declared inputs, rendered in order.
        note: Optional one-line context under the heading.
        error: Validation or seal failure to display; empty renders nothing.
        seal_required: Whether to render the anti-preemption seal input.
        attempts_left: Remaining seal attempts, shown only when a seal is used.
    """
    body = ['<div class="card"><h1>', html.escape(prompt, quote=False), "</h1>"]
    if note:
        body += ['<p class="note">', html.escape(note), "</p>"]
    if error:
        body += ['<p class="error" role="alert">', html.escape(error), "</p>"]
    body.append('<form method="post">')
    body += [_input(field) for field in fields]
    if seal_required:
        body.append(
            '<label for="%s">Relay seal</label>'
            '<input id="%s" name="%s" type="text" autocomplete="off" '
            'data-kind="text" maxlength="16">' % (SEAL_FIELD, SEAL_FIELD, SEAL_FIELD)
        )
        if attempts_left is not None:
            body.append(
                '<p class="hint">Printed on the machine running the script. '
                "%d attempt(s) left.</p>" % max(0, attempts_left)
            )
        else:
            body.append(
                '<p class="hint">Printed on the machine running the script.</p>'
            )
    body.append('<button type="submit">Submit</button></form></div>')
    return _page(prompt, "".join(body), script=True)


def render_accepted(prompt: str) -> str:
    """Shown once, right after the submission was accepted."""
    body = (
        '<div class="done"><h1>Received</h1>'
        '<p class="note">Thanks &mdash; <strong>%s</strong> got your answer. '
        "This page is now closed.</p></div>" % html.escape(prompt, quote=False)
    )
    return _page("Received", body)


def render_closed() -> str:
    """Shown when the relay has already ended. Leaks nothing about the prompt."""
    body = (
        '<div class="done"><h1>Closed</h1>'
        '<p class="note">This relay is no longer accepting submissions.</p></div>'
    )
    return _page("Closed", body)
