# oneshot-relay

Collect **exactly one** human input from a phone during an unattended script run —
on a machine behind NAT, with no public address and no inbound firewall rule.
The endpoint tears itself down after a single submission, or after the wait expires.

```
script blocks ──▶ local form on a random port + cloudflared quick tunnel
              ──▶ one-time URL delivered to you (stdout by default, or a webhook)
              ──▶ you open it on your phone and submit once
              ──▶ script receives a dict, port closes, tunnel dies
```

Standard library only, Python 3.9+. `cloudflared` is an optional external binary.

## Intended use

This is a human-in-the-loop primitive for **your own** automation, where the
script runs somewhere you cannot type and the answer lives in your head or on
your own device.

Fine:

- a release or deploy gate that needs one explicit `yes`
- an on-call acknowledgement during a long unattended job
- feeding a second factor from **your own** authenticator into **your own** headless job
- "pick one of these options before I continue"

Not fine, and not what this is built for:

- collecting codes or credentials **from other people** — that is phishing, and
  nothing in this design makes it safe for them or for you
- anything that must stay reachable (one submission and it is gone)
- file upload, two-way sessions, high concurrency
- compliance-grade MFA — if a service offers an API or CLI for this, use that instead

**The URL is a bearer credential.** Anyone holding it can submit. Choose the
delivery channel accordingly, and turn on `require_seal` whenever the link
travels somewhere other people can read.

## Install

```bash
pip install "git+https://github.com/Jcchen2026/oneshot-relay.git"

# optional, for public reachability through a Cloudflare quick tunnel
brew install cloudflared          # macOS
```

> **Not on PyPI.** This project is not published there, so any package named
> `oneshot-relay` on PyPI is not this project. Install from the git URL above.

Without `cloudflared` the relay still works and simply stays local-only
(loopback, plus LAN if you opt in) — it degrades instead of failing.

## Quick start

```python
from oneshot_relay import Field, relay_once

answer = relay_once(
    "Deploy 2026.09 to production?",
    [Field.text("decision", "yes or no", pattern=r"^(yes|no)$")],
    wait_seconds=300,
)

if answer and answer["decision"] == "yes":
    print("deploying")
else:
    print("no approval, aborting")     # answer is None on timeout
```

By default the link is printed on the machine running the script. Nothing is
sent anywhere until you pass a notifier.

### Full control: the `Relay` object

```python
import os
from oneshot_relay import LOCKED_OUT, Field, Relay, WebhookNotifier

with Relay(
    "Restart the staging database?",
    [Field.code("code"), Field.text("reason", required=False)],
    wait_seconds=600,
    notifier=WebhookNotifier(os.environ["RELAY_WEBHOOK"]),
    note="Unattended migration job, host behind NAT.",
    require_seal=True,          # seal printed locally, never sent to the webhook
    use_tunnel=True,            # False = local only, handy in CI
) as relay:
    outcome = relay.wait()

if outcome:
    print(outcome.data)                    # {'code': '123456', 'reason': ''}
elif outcome.status == LOCKED_OUT:
    print("someone had the link but not the seal; relay locked itself")
else:
    print("timed out:", outcome.reason)
```

`Outcome` is truthy only when a submission was accepted, and carries `status`
(`submitted` / `timeout` / `locked_out`), `data` and `reason`.

## Fields

```python
Field.text(name, label=None, *, max_length=100, pattern=None, required=True)
Field.code(name, label=None)      # six digits, auto-submits when complete
```

| Argument | Effect |
|---|---|
| `name` | Form key and key in the returned dict. Must match `[A-Za-z][A-Za-z0-9_]{0,31}` |
| `label` | Caption rendered above the input; defaults to `name` |
| `max_length` | Enforced server-side and mirrored into the HTML |
| `pattern` | Regular expression the value must match in full |
| `required` | `False` allows an empty value; length and pattern still apply to what arrives |

Only declared fields are returned — any other key a client posts is dropped
before it reaches your code. Validation always runs server-side; the browser
checks are convenience only.

## Notifiers

| Notifier | Behaviour |
|---|---|
| `StdoutNotifier()` | Prints the links locally. The default |
| `WebhookNotifier(url, ...)` | POSTs the message as JSON to an incoming webhook |
| your own `Notifier` | Subclass it and implement `deliver(message) -> bool` |

`WebhookNotifier` does not know about any specific chat platform; `payload_builder`
shapes the JSON body, which is how anything is supported:

```python
WebhookNotifier(url)                                                    # {"text": "..."}
WebhookNotifier(url, payload_builder=lambda t: {"text": t})             # Slack-style
WebhookNotifier(url, payload_builder=lambda t: {"msg_type": "text",
                                                "content": {"text": t}})  # Lark/Feishu-style
```

The URL must be `https://` — a one-time link is a bearer credential, so
plaintext is refused at construction (loopback `http://` only with
`allow_insecure=True`, for test doubles). The URL is never logged; failures
print `redact_url()`, which drops the query string where webhook secrets live.

## Security model

| Concern | Handling |
|---|---|
| URL guessing | `secrets.token_urlsafe(16)` (~128 bits) in the path |
| Loose routing | Exact path match; anything else is a bare 404 |
| Endpoint lingering | Closes on first accepted submission or on timeout; tunnel `terminate` → `kill` → `wait` |
| HTML/script injection | Every caller-supplied string escaped; CSS and JS are fixed literals; CSP `default-src 'none'` |
| Cache and Referer leaks | `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` |
| Token in logs | Access logging disabled; seal printed locally only |
| Oversized / malformed body | 8 KiB cap → 413; bad `Content-Length` → 400; missing → 411 |
| Connection flood | Bounded at 8 concurrent handlers → 503 beyond that |
| LAN exposure | Binds `127.0.0.1` by default; `expose_lan=True` is opt-in |
| Link leaked into a group chat | `require_seal=True`: the seal is printed on the script's machine and never sent to the notifier; wrong attempts are capped (default 5), then the relay locks itself |
| Tunnel hang | Reader thread + queue, so `tunnel_timeout` is a real deadline |
| Early teardown | The caller is woken only *after* the 200 has been written, so the phone always gets its answer |

### What it does not protect against

- **Whoever has the link *and* the seal.** The seal raises the cost of a
  drive-by submission; it is not identity authentication.
- **A notifier channel readable by others.** Without a seal, anyone in that
  channel can submit first and your script will act on their value. Validate
  what comes back before doing anything destructive.
- **The tunnel provider.** Public traffic traverses Cloudflare's edge.
- **Repudiation.** Submissions are neither signed nor attributable.

## How it works

1. `ThreadingHTTPServer` binds `127.0.0.1:0`; the OS picks the port, the route is `/r/<token>`.
2. `QuickTunnel` runs `cloudflared tunnel --url http://127.0.0.1:<port> --no-autoupdate`
   and parses `https://<label>.trycloudflare.com` out of its stdout. A worker
   thread drains stdout into a queue, because an inline `for line in proc.stdout`
   loop can only check its deadline *after* a line arrives and would block
   forever on a stalled process.
3. The notifier receives a plain-text message with every way in (public, LAN if
   enabled, loopback).
4. `POST` → exact route → optional seal → server-side validation → claim the
   single submission slot → respond 200 → wake the caller.
5. `close()` runs `server.shutdown()`, `server_close()`, and stops the tunnel.
   It is idempotent and safe in `finally`.

## Non-goals

Long-lived services, fixed domains, authentication, high concurrency, large
uploads, bidirectional sessions. This is a temporary, single-use, low-volume
hand-off between a script and one human.

## Development

```bash
python3 -m unittest discover -s tests -v
```

The suite is stdlib-only and needs no `cloudflared`: every relay is opened with
`use_tunnel=False` and reached over loopback. It covers routing, escaping,
validation, one-shot semantics, body limits, seal lock-out and webhook URL
policy — and it fails if any source file stops parsing as Python 3.9.

## License

MIT — see [LICENSE](LICENSE). Vulnerability reports: see [SECURITY.md](SECURITY.md).
