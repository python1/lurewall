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

Built so far: the project scaffold, the signed event log and the access-log
reader. There is no detector, no canary and no blocking yet, and no command
that runs the reader as a service.

## The signed log

Every event is one line of canonical JSON holding `seq`, `ts`, `type`,
`source`, `detail`, `prev_hash` and `sig`. Each line carries the SHA-256 of the
line before it and an Ed25519 signature, so editing, removing or reordering a
line breaks the chain at that line. Signing reuses
[eureka_protocol](https://github.com/python1/eureka_protocol)'s scheme.

Every so often the writer signs the hash of the newest entry into a small
checkpoint file. A checkpoint holds a sequence number, a hash, a time and a
signature, and nothing about any visitor. Copies kept somewhere the lab box
cannot change are called anchors.

```sh
lurewall keygen --key /path/outside/the/repo/lurewall.key   # prints the public key
lurewall verify --log events.log --pubkey <public key> --anchors <file or directory>
```

`verify` prints the first bad entry, if any, and exits 0 only if the log
verifies. Its output never includes log content, because that text is
attacker-controlled.

**What a pass proves, and what it doesn't.** Entries up to the last anchor
that matches have not been edited, removed or reordered since that anchor was
made. Entries after the last anchor are signed and chained, but whoever holds
the signing key, the operator included, could rewrite or remove them without
detection. Without anchors, `verify` cannot detect entries removed from the
end of the log at all. The log shows what Lurewall recorded; it is not
independent proof of what happened on the network. `verify` checks checkpoint
signatures, not OpenTimestamps proofs.

Flood and failure behaviour: repeats of one event from one source are counted
and written as one `rollup` entry per window; the roll-up table has a fixed
size; below a free-disk floor the writer records that it stopped, and on
resuming records how many events it dropped.

## The log reader

Lurewall never sits in the request path. It tails a JSON access log that nginx
writes (the format is in `deploy/nginx/lurewall-log.conf`) and treats every
field as untrusted data.

- **No line is dropped silently.** A line becomes a record, or a signed
  `parse_failure` event holding its offset, length and hash, never its text.
  Past a per-minute budget, failures are counted in one `parse_failure_rollup`
  event with a digest of the lines it covers.
- **Hostile bytes.** nginx's `escape=json` leaves bytes above 126 alone, so
  invalid UTF-8 can reach the log. The reader decodes it with replacement
  characters and marks the record. This has been tested against lines built to
  nginx's documented escaping, not yet against a real nginx.
- **Rotation and restart.** The reader follows logrotate by inode, finishes the
  old file before moving on, and resumes from a saved offset. If lines can no
  longer be read (the rotated file is gone, or the file was cut short), it
  writes an event saying so. Delivery is at-least-once: after a crash, lines
  are read again rather than skipped.
- **Lag and staleness.** The reader logs how far it is behind the access log.
  Records more than 5 minutes old, or as far in the future, are marked stale so
  that nothing enforces on a backlog.

Known limits: a rotated file that was compressed or deleted before the reader
caught up is a logged gap, so use logrotate's `delaycompress`. With
`copytruncate`, a file cut and refilled past the reader's position between two
polls is not noticed; use the default rename-and-reopen rotation.

## Development

Requires Python 3.11 or newer and a clone with submodules:

```sh
git clone --recurse-submodules https://github.com/python1/lurewall.git
cd lurewall
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/pytest
```

In an existing clone, run `git submodule update --init`. Lurewall runs from a
source checkout (an editable install); a built wheel does not include the
eureka signing code.

CI runs the same lint and tests, plus a gitleaks secret scan, on every pull
request. Changes reach `main` only through pull requests.

## Third-party code

`third_party/eureka_protocol` is a git submodule pinned to commit
`7f29b208d1da54ebf5963e9b409f79d483979f74` (v0.3.0). Lurewall loads one file
from it, `src/eureka_daemon/crypto.py`, which is AGPL-3.0-only, copyright Paul
Charydczak. The loader checks that file's SHA-256 and refuses any other
version.

## Security

See [SECURITY.md](SECURITY.md). No secrets, signing keys or per-installation
canary values belong in this repository.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
