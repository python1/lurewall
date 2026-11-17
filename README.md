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

Built so far: the project scaffold, the signed event log, the access-log
reader, the canaries with their throwaway lab site, the attack and behavior
signals, the decision engine, the nftables adapter, the sweeper and the
service command. Everything runs in dry-run by default. The adapter is tested
against a real `nft` in CI, but no block has been checked on a live host yet,
and the systemd units are untested reference files.

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
  invalid UTF-8 reaches the log as raw bytes. The reader decodes it with
  replacement characters and marks the record. CI checks this against a real
  nginx (1.24 on the test runner) as well as against built fixtures; the lab's
  own nginx is still to be checked when it exists.
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

## Canaries and the lab site

A canary is a short piece of non-rendered page content naming a decoy path. A
client that reads it and acts on it makes one request to that path. The decoy
answers 200 with a fixed body that holds no data, and the request is logged.
That is the whole effect.

```sh
lurewall lab-site build --state /outside/any/repo/canaries.json --out /outside/any/repo/lab-site
lurewall canaries list --state /outside/any/repo/canaries.json
lurewall canaries rotate --state /outside/any/repo/canaries.json --id api_doc.bait
```

`lab-site build` creates the installation's canary set on first use, then
writes a small fictional static site and an nginx `server` block for it.

- **Per installation.** Decoy paths, lure wording, the canary header's name
  and the decoy bodies are drawn at random for each installation and kept in a
  state file outside any git repository; Lurewall refuses to read or write one
  inside a repository. This repository holds only the generator, its word
  banks and one example file that the loader refuses.
- **Two lure types, measured apart.** An *instruction* lure addresses the
  reader ("confirm access at ..."). A *bait* lure gives no instruction: it is
  something a probing agent wants, such as a commented-out backup link. Every
  canary carries its label.
- **Seven placements.** HTML comments (one of each type), a visually hidden
  element, a robots.txt comment, an unlinked `noindex` API page, the error
  pages and a response header.
- **No shared fingerprint.** Decoy paths look like ordinary paths and no two
  share a first segment. A path outside the table gets the site's normal 404.
  robots.txt has no `Disallow` line for decoys; they send `X-Robots-Tag`.
- **Never a real route.** The build fails if a decoy path collides with a real
  site path, and the check runs on every build.
- **Tied to the page that served it.** nginx's `sub_filter` writes each
  request's `$request_id` into the canary references on the page it serves,
  with no proxy. A hit carries the ID of the page that showed it.
- **Not read aloud.** A canary is either an HTML comment or an element with
  `aria-hidden="true"` and nothing focusable inside. This is checked on the
  markup; a real screen reader, reader modes and AI page describers are still
  to be tested in the lab before any public use.
- **Rotation only on leak.** Nothing rotates on a schedule. Two fetches of a
  page differ only in the request ID.

Limits: the word banks are public and each placement has roughly 2^27 to 2^33
possible paths, so a determined attacker can enumerate them. A guessed path
does not carry a request ID issued to the guesser, which is what the scoring
(not built yet) will require. Many fetch tools strip comments, hidden elements
and headers before a model sees the page, so those lures may never arrive.

## Signals

Each logged request is classified into signals of two classes. Only *attack*
signals can ever count toward a block. *Behavior* signals (library user agent,
missing Accept-Language, prose in a URL, steady timing, no asset loads,
alphabetical order) are context in the log and count for nothing, so speed
alone can never block anyone.

```sh
lurewall signals check --config deploy/signals/lab-site.toml --state /outside/any/repo/canaries.json
```

- **What counts is in a plain file.** `deploy/signals/lab-site.toml` lists the
  attack paths (`/.env`, `/.git`, `/admin`, ...), the injection pattern
  families and the abused verbs for the lab site. The file's schema is closed:
  it has no key for a body signal, and the threshold cannot be set below 2.
- **Never a decoy, never a real page.** The config is checked against the
  canary table and the site's routes. A decoy path that matches an attack-path
  rule in any spelling, or a real route that does, fails the check, and no
  classifier can be built from a config that fails. A request nginx answers
  with a decoy is also never treated as a sensitive-path probe at run time.
- **Raw and normalized.** Every URI is matched as sent and in a normalized
  form (percent-decoded once, slashes merged, dot segments resolved,
  lowercased), so `/%2eenv`, `//.env` and `/.ENV` are all the `/.env` probe,
  and they are one signal, not three. Attack-path rules are also matched on
  the path decoded a second time, so `/%252eenv` is the same probe; injection
  patterns are not, because query strings carry double-encoded URLs honestly.
- **Path and query only.** Injection patterns look at the path and query
  string. No request body is logged, so nothing reads one.
- **Cross-site counts for nothing.** A request marked `Sec-Fetch-Site:
  cross-site`, or with a Referer from another host, yields no attack signal
  and no canary hit. It is logged as `cross_site`, and the probes it carried
  are kept per source so a decision can say they were seen.
- **Plain HTTP.** Browsers send `Sec-Fetch-Site` only to secure origins. The
  config says whether the site is HTTPS; on a plain-HTTP site, such as the
  lab's, the header is ignored and its presence is logged as a behavior signal.
- **Two distinct attack signals, two requests.** The attack threshold is two
  or more distinct signals from one source inside 15 minutes, from at least
  two separate requests. Repeats and spelling variants of one probe are one
  signal, and one request that raises two signals is not enough.
- **Sources.** A source is an IPv4 address or an IPv6 /64. The per-source
  table has a fixed size; the source idle longest is dropped first and every
  drop is logged.
- **Shared addresses.** A source that also shows ordinary browsing in the
  window (a successful asset load, or browser fetch metadata on a clean
  request) is marked, so the engine will not double a block's TTL for it.

Nothing in this part decides or blocks. It writes `attack_signal`,
`attack_threshold_met`, `behavior_signal`, `cross_site` and
`signal_state_evicted` events, none of which holds text from a request.

Limits: a client can send a Referer from another host (or, on an HTTPS site,
`Sec-Fetch-Site: cross-site`) and have its probes count for nothing. That is
deliberate: a source that really read the site holds a canary hit for days,
and if cross-site probes counted, any page with two image tags could get that
source blocked. The filter protects third parties; it does not catch attackers.
Fetch metadata is easy to fake, which only ever stops a TTL from doubling. At the table's size limit a flood of new sources
pushes out older ones, attack state included.

## The decision engine

A small, deterministic rule set over per-source state. No ML: every decision
can be explained from the log.

| Counted canary hit in the last 7 days | Attack threshold met | Outcome |
|---|---|---|
| no | no | nothing |
| yes | no | logged as a content reader; no block |
| no | yes | logged as an attack with no canary hit; no block in v1 |
| yes | yes | block with a TTL |

- **Request-ID binding.** A canary hit counts only when the request ID it
  carries was issued to the same source, on a page nginx served it in the last
  24 hours. An ID issued to another source is logged as `canary_relayed` and
  counts for nobody. A missing, made-up or guessed ID is `canary_unbound`.
- **Sticky hit.** A counted hit stays on its source for 7 days, so waiting out
  the 15-minute attack window does not help.
- **Before any block.** Sources inside the configured provider ranges are
  log-only, matched by address and never by user agent. The allowlist is
  checked next and logs `would_block`. Nothing older than 5 minutes is acted on.
- **Dry-run is the default.** It logs `would_block` and enforces nothing. It
  stays on until `dry_run = false` is written in the config.
- **TTL.** 24 hours first, doubling on each repeat up to 7 days. It does not
  double when the source also showed ordinary browsing. A new block needs
  fresh evidence: the signals that caused a block are spent.
- **Cap.** At most 1,000 active blocks. At the cap new blocks are refused, a
  `cap_reached` event is logged, an error-level line goes to the journal, and
  `lurewall status` shows a warning (and exits 1) until `lurewall alerts clear`.
  No block is evicted early.
- **Bounded.** The tables of issued IDs and counted hits have fixed sizes, and
  one source can only rotate out its own IDs.

```sh
lurewall status --state /outside/any/repo/engine.json
lurewall alerts clear --state /outside/any/repo/engine.json
```

The config is `deploy/engine/lab.toml`. Counted hits, blocks, TTL history and
the alert are saved to a state file (mode 0600, refused inside a repository).

## Enforcement: nftables and the sweeper

```sh
lurewall run --access-log ... --reader-state ... --event-log ... --key ... \
    --canaries ... --signals ... --engine ... --engine-state ...
lurewall sweep --event-log /outside/any/repo/sweeper.log --key ...
```

Nothing is enforced unless the engine config has both `dry_run = false` and
`adapter = "nftables"`. The shipped config has neither.

- **Expiry stored with each entry, twice.** A block is one element in an
  nftables set matched by a drop rule. It carries nftables' own timeout, so
  the kernel removes it with Lurewall stopped, and its absolute expiry time in
  the element's comment, so anything can tell when it is due. The same time is
  in Lurewall's state file.
- **Reconcile on startup.** `lurewall run` compares its state file with the
  live sets. It removes entries that are expired, unknown or carry a different
  expiry, and puts back unexpired blocks that are missing (sets are lost on
  reboot) with the time they have left. In dry-run it touches nothing.
- **The sweeper is separate.** `lurewall sweep` is run by its own systemd
  timer (`deploy/systemd/`), not by the service. It reads expiry times from
  the live entries only, so it works with the service stopped and its state
  lost. It removes what is past due and anything that cannot show when it is
  due. It writes to its own signed log, because the service's log has one
  writer. A run with nothing to remove writes nothing.
- **Stale events.** A backlog read after downtime is logged and enforces
  nothing.
- **Failures.** If `nft` fails, the decision is still logged, the failure is
  logged, and the block is retried. Nothing from `nft`'s output is logged.
- **Only addresses reach `nft`.** Every command is built from fixed words and
  addresses that have been parsed and written back out. The adapter refuses
  loopback, unspecified and multicast addresses.

The nftables adapter is for the isolated lab container and direct traffic. A
site behind Cloudflare must not use it: the origin sees Cloudflare's addresses.

Limits: issued request IDs are kept in memory only, so after a restart a hit on
a page served before it is unbound and does not count. Pages read from one
address and probes sent from another are not blocked. A stale canary hit (from
a backlog) is logged but not counted. Cross-site probes never count, so a
client that forges a Referer hides its probes; the engine logs that it saw
them (`content_reader_cross_site_probes_not_counted`).

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
