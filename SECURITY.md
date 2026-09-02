# Security policy

## Scope and threat model

`oneshot-relay` exposes a temporary HTTP endpoint that accepts **one** form
submission and then closes. The design assumes:

- the URL path token is a bearer credential, and whoever presents it may submit;
- the person submitting is the operator of the machine running the script;
- the tunnel is provided by a third party (Cloudflare quick tunnels), so public
  traffic traverses their edge;
- the value returned to the caller is **untrusted input** until the caller
  validates it.

Behaviour that follows from those assumptions is not a vulnerability: a leaked
link can be used to submit, an unsealed relay can be pre-empted by anyone who
sees the link, and a submission cannot be attributed to a specific person.
`require_seal` exists to raise the cost of drive-by submissions; it is not
authentication. See the README's "What it does not protect against".

## What I want to hear about

- Any path from caller-supplied strings (`prompt`, `label`, `note`,
  `extra_lines`) to script execution or markup injection in the served page
- Route matching that accepts anything other than the exact `/r/<token>` path
- A relay that stays reachable after `submitted`, `locked_out` or `close()`
- Body-size, header-parsing or concurrency limits that can be bypassed to
  exhaust memory or file descriptors
- The one-time URL, the seal, or a webhook URL reaching a log, an exception
  message or a notifier payload
- Anything that lets a second submission be accepted, or the returned dict
  contain undeclared fields

## Reporting

Please do **not** open a public issue for a flaw that could be exploited in
deployments that are running right now.

- Preferred: GitHub private vulnerability reporting on this repository —
  **Security → Report a vulnerability**.
- Alternative: contact the maintainer via <https://github.com/Jcchen2026>.

Please include:

1. version or commit, and Python version;
2. minimal reproduction;
3. what the attacker needs to start with — the URL, the seal, LAN access, or
   nothing at all;
4. the impact you believe it has.

## Response

- Acknowledge within 7 days.
- Ship a fix, or document the mitigation and the exact conditions in the
  README's security model — whichever is honest about the risk.
- Credit reporters in the release notes unless they ask not to be named.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

There is no LTS commitment: this is a small single-purpose library, and the
answer to a serious flaw may be a breaking change with a version bump.
