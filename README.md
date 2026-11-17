# Lurewall

**In development — not ready for use.** Nothing here should be deployed.

Lurewall is a defensive, open-source tool for studying one question in a lab:
can harmless canaries planted in a web page's non-rendered content, combined
with ordinary attack signals, pick out a naive AI agent that is probing a site?

Created by Paul Charydczak.

## Scope

- **Defensive only.** Lurewall never sends traffic to a visitor, never scans
  back, never serves a payload and never tries to trace or identify anyone. A
  canary's only effect is one logged request to a decoy path, which returns a
  fixed body that holds no data.
- **Lab only.** v1 runs on a throwaway site in an isolated container on a
  private network, with the author's own test agents as the only traffic. It
  makes no claim about protecting real sites.
- **Narrow claim.** A canary hit means a client read a page's non-rendered
  content and acted on it. It does not prove the client is an AI, and it does
  not mean the visitor is hostile. v1 is expected to catch naive agents only;
  an attacker who ignores the canaries is logged, not blocked.

## Planned design

A source is blocked only when two kinds of evidence agree: a canary hit bound
to that source, and two or more distinct attack signals. Blocks expire. Every
event goes into a hash-chained, Ed25519-signed log whose checkpoints are
anchored off the box, and a `verify` command checks it.

None of the parts is new. Prompt injection as an agent detector, log tailing
with expiring bans, and tamper-evident logs all exist already; this project
combines them behind one gate and reports what a lab test shows.

## Status

This repository currently holds the project scaffold only: packaging, CI and
policies. There is no detector, no log and no command to run yet.

## Development

Requires Python 3.11 or newer.

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/pytest
```

CI runs the same lint and tests, plus a gitleaks secret scan, on every pull
request. Changes reach `main` only through pull requests.

## Security

See [SECURITY.md](SECURITY.md). No secrets, signing keys or per-installation
canary values belong in this repository.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
