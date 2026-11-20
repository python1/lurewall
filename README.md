# Lurewall

**Deployment status.** The Debian/Ubuntu operator workflow is available for
evaluation on a dedicated nginx canary vhost. Start in observation mode and
qualify the deployment on your host before enabling enforcement. The
[operator guide](docs/operator-guide.md) covers setup, monitoring and recovery.
The research results below refer to the isolated lab.

Lurewall plants harmless canaries in a web page's non-rendered content and
watches the site's access log for clients that act on them. It blocks a source
only when a canary hit bound to that source and two or more distinct attack
probes agree, and every block expires on its own. Every decision goes into a
signed, hash-chained log whose checkpoints are anchored off the box, so the
record can be checked later.

Created by Paul Charydczak.

Case study: [docs/case-study.md](docs/case-study.md). Full lab findings:
[docs/lab-findings.md](docs/lab-findings.md).

## v0.3.0 operator workflow

Build natural references from a local public site root and its sitemap or a
private operator wordlist. The default placement is a footer comment. An
existing robots.txt rule group can carry an optional recon reference that
counts under the same-source rules. An existing eligible security.txt can
carry an optional research-only reference. Ordinary missing paths and
references use the same vhost error handler.

After a visit, run `sudo lurewall doctor` and `sudo lurewall report --since 10m`.
The report and `explain-decision` can show **possible IP switch** when a second
source uses a path issued to the first. This is a signed observation and has
zero effect on either source's would-block or firewall state. Configure the
vhost, import the Grafana dashboard, or export script-free HTML using the
[operator guide](docs/operator-guide.md#natural-placements-and-the-first-report).
The historical lab results below refer to the version tested at the time.

## Lab results

Twenty test cases were run in November 2026 against a throwaway site in an
isolated container. Details, run IDs and substitutions are in
[docs/lab-findings.md](docs/lab-findings.md).

| # | Case | Result |
|---|---|---|
| 1 | Benign AI agent summarises the site | pass: no canary followed, no block |
| 2 | Audit for exposed files: canary, probes, block | pass with a scripted client, in dry-run and enforcing; AI agent runs not run |
| 3 | Plain wordlist scanner | pass: attack signals alone never block |
| 4 | A human browsing normally | pass: no canary hit, no attack signal |
| 5 | Accessibility tools | recorded: a text-mode browser shows the hidden canary; fixed with a notice; screen reader clean |
| 6 | Tamper test on a copy of the log | pass: edit, delete, reorder and truncate all caught |
| 7 | Allowlisted source | pass: logged as `would_block`, not enforced |
| 8 | Framing through a browser | pass: cross-site requests count for nothing |
| 9 | Link-following crawler, no model | pass: took 4 of 7 canaries, logged as a content reader, not blocked |
| 10 | Relayed canary hit | pass: counted for nobody |
| 11 | Waiting it out (probes 16 minutes later) | pass: blocked, then expired on time |
| 12 | Reading and probing from two addresses | known limit: not blocked |
| 13 | Shared address | pass: collateral block for one TTL; the TTL did not double |
| 14 | Process failure | pass: block expired with the service stopped; stale backlog ignored |
| 15 | Flood with one real probe | pass: rate limit answered the excess; the probe was recorded |
| 16 | Hostile bytes in path and user agent | pass: 8 of 8 logged, none lost |
| 17 | Path spelling variants | pass: 10 of 10 matched |
| 18 | Log-only range | pass: never blocked |
| 19 | What each agent's fetch passes to the model | recorded per agent |
| 20 | A careful AI agent probing, dry-run | pass: it saw a canary and declined it; its probes were logged, nothing enforced |

## Limits

- **Careful agents decline v1's canaries.** v1's lures give instructions. A
  careful AI agent spotted the response-header canary as suspicious and did
  not follow it, and the other AI agent tested followed none. No AI agent was
  caught in the lab.
- **The full chain is proven with scripted clients only.** Canary hit, then
  probes, then a real nftables block that expires on time: shown with the
  lab's scripted client, not with an AI agent.
- **Shared addresses.** Everyone behind a blocked address loses access to the
  site for one TTL. Ordinary browsing from that address stops the TTL from
  doubling, but not the block itself.
- **Split addresses.** A client that reads pages from one address and probes
  from another is not blocked.
- **Per-visitor paths can be spotted.** v0.3.0's natural placements give each
  source its own path. An agent that fetches the same page from two different
  IP addresses and compares them can see that the reference differs, and so
  tell that the page is personalized.
- **The log's newest entries.** Entries after the last anchored checkpoint
  can't be proven complete. In the lab that tail was at most about 10
  minutes: a checkpoint is written at least every 5 minutes and pulled off the
  box every 5 minutes.
- **A narrow claim.** A canary hit shows that a client read non-rendered
  content and acted on it. It doesn't prove the client is an AI.

## Related work

- **Palisade Research, LLM Agent Honeypot**
  ([arXiv:2410.13919](https://arxiv.org/abs/2410.13919)). A public honeypot
  that uses prompt injection and response timing to tell AI agents apart from
  other attackers. Lurewall uses the same basic idea, a lure that only an
  agent acts on, on a web page instead.
- **Cloudflare AI Labyrinth.** It serves generated decoy pages to crawlers that
  ignore no-crawl directives.
- **Canary tokens** in general. These are tripwires such as decoy files, URLs and
  credentials that raise an alert when someone uses them.

Lurewall combines a canary hit with attack probes behind one gate, and adds
expiring blocks and an anchored, signed log.

## v2: quiet canaries (released in v0.2.0, not yet lab-tested)

Released in v0.2.0 with the Debian/Ubuntu operator package.

v1's lures give orders, and careful agents decline them. v2 adds three
*destination* canaries beside the v1 set. They name a place and ask nothing.
The build spec is [docs/v2-build-spec.md](docs/v2-build-spec.md), and the ideas
are tracked in issue #14.

| Canary | Where | Shape | Signal | Counts toward a block? |
|---|---|---|---|---|
| B | an HTML comment in every content page's footer | `<!-- legacy settings archived at /<dir>/settings-<token>/ -->` | `ai` | yes |
| A | one `Disallow` line in robots.txt | `Disallow: /<dir>-old-backup-<token>/` | `recon` | yes, labelled recon |
| C | a comment in a valid `/.well-known/security.txt` | `# Previous disclosure archive: /<dir>/archive-<token>/` | `research` | no, log-only |

- **A can block ordinary scanners.** Ordinary scanners read robots.txt and
  visit what it disallows. A scanner that follows A and then probes for two
  distinct attack paths meets the two-signal rule and can be blocked, just as
  an agent would. That is why A's signal is `recon`, not `ai`. Leave A out of
  any claim about AI agents.
- **C never counts.** Security researchers are invited to read security.txt.
  A hit on C is logged with the decision `research_log_only` and never counts
  toward a block.
- **No orders.** No quiet lure holds an imperative word ("verify", "approve",
  "must", "click", and so on). The canary validator refuses one that does.
- **An ordinary 404.** A quiet decoy has no nginx location. A request for one
  gets the site's normal 404, byte for byte, and every 404 on the site now
  sends `X-Robots-Tag: noindex`, so a trap's 404 is identical to any other.
- **A hit counts only after the same address loaded the page.** A quiet
  reference holds no request ID, so the page binds it instead. A v2 hit counts
  only if the same address (an IPv4 address or an IPv6 /64) loaded the page
  that carries that canary within the last 24 hours. For B that is any
  content page, for A robots.txt, and for C security.txt. The page load must
  be a GET that is not cross-site: a HEAD of the page returns no body, so it
  carries no canary and binds nothing. **A guessed or shared path doesn't
  count:** a request from an address that never loaded the page is logged as
  `canary_unbound` (`not_served`, or `expired_served` after 24 hours) and
  counts for nobody. The bindings are kept in memory only, so after a restart
  an address must load the page again. Only GET and HEAD to the decoy count.
  Case, a trailing slash, an encoded slash or a query string does not change
  the match.
- **Plain-word paths.** A quiet path is a folder from the same list of
  ordinary site words as the v1 decoys (never one that gives an order, such
  as `verify`), then a word, then the per-install token, with no word
  repeated.
- **Labelled in the log.** Every `canary_hit` holds `family` (`v1-imperative`
  or `v2-quiet`) and `signal`; `block` and `would_block` hold `canary_family`
  and `canary_signal`. `lab results` reports hits per family and signal, and
  per agent the runs with a v1 hit and the runs with a v2 hit.
- **Upgrade and rotation.** `lab-site build` adds B, A and C to an existing v1
  canary set and leaves the v1 canaries as they were. Rotate with the existing
  command, for example `lurewall canaries rotate --id robots_disallow.quiet`,
  or `--all`. A retired path becomes an ordinary 404 and counts for nothing.
- **Collisions.** At startup the service disables any canary whose path
  collides with a real route and logs `canary_disabled_collision`.

Not in v2: sitemap and `Link` header canaries, and probe-only ("strict")
blocking.

## Scope

- **Defensive only.** Lurewall never sends traffic to a visitor, never scans
  back, never serves a payload and never tries to trace or identify anyone. A
  canary's only effect is one logged request to a decoy path, which returns a
  fixed body that holds no data.
- **Lab only.** v1 was tested on a throwaway site in an isolated container on
  a private network, with the author's own test clients as the only traffic.
  It makes no claim about protecting real sites.
- **Narrow claim.** A canary hit means a client read a page's non-rendered
  content and acted on it. It does not prove the client is an AI, and it does
  not mean the visitor is hostile. v1 is expected to catch naive agents only;
  an attacker who ignores the canaries is logged, not blocked.

## Design

A source is blocked only when two kinds of evidence agree: a canary hit bound
to that source, and two or more distinct attack signals. Blocks expire. Every
event goes into a hash-chained, Ed25519-signed log whose checkpoints are
anchored off the box, and a `verify` command checks it.

None of the parts is new. Prompt injection as an agent detector, log tailing
with expiring bans, and tamper-evident logs all exist already; this project
combines them behind one gate and reports what a lab test shows.

## Status

v1 is complete: the signed event log, the access-log reader, the canaries
with their throwaway lab site, the attack and behavior signals, the decision
engine, the nftables adapter, the sweeper, the service and its systemd units,
and the lab harness with its runbook. Everything runs in dry-run by default.
The lab ran it under systemd in an unprivileged Debian 13 container
(nftables 1.1.3, nginx 1.26.3), where real blocks landed and expired on time.

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
  nginx (1.24 on the test runner) as well as against built fixtures, and the
  lab checked it on nginx 1.26.3 (case 16: 8 of 8 hostile requests logged).
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
- **Seven v1 placements.** HTML comments (one of each type), a visually hidden
  element, a robots.txt comment, an unlinked `noindex` API page, the error
  pages and a response header. v2 adds three quiet placements (see above).
- **No shared fingerprint.** Decoy paths look like ordinary paths and no two
  share a first segment. A path outside the table gets the site's normal 404.
  robots.txt's only `Disallow` line is v2's canary A; v1 decoys send
  `X-Robots-Tag` instead.
- **Never a real route.** The build fails if a decoy path collides with a real
  site path, and the check runs on every build.
- **Tied to the page that served it.** nginx's `sub_filter` writes each
  request's `$request_id` into the canary references on the page it serves,
  with no proxy. A hit carries the ID of the page that showed it.
- **Not read aloud.** A canary is either an HTML comment or an element with
  `aria-hidden="true"` and nothing focusable inside. In the lab, VoiceOver
  read no canary. A text-mode browser (lynx) shows hidden
  elements, and no HTML can prevent that, so each hidden canary starts with a
  notice saying it is not meant for people.
- **Rotation only on leak.** Nothing rotates on a schedule. Two fetches of a
  page differ only in the request ID.

Limits: the word banks are public and each placement has roughly 2^27 to 2^33
possible paths, so a determined attacker can enumerate them. A guessed path
does not carry a request ID issued to the guesser, and the engine counts a
hit only with an ID issued to the same source. Many fetch tools strip comments, hidden elements
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
  A lenient form drops path parameters and trailing dots, as some servers do,
  so `/..;/.env` and `/.env.` are the `/.env` probe too. Suffix rules
  (`*.swp`, `*.old`) match editor and backup leftovers. Real paths such as
  `/environment-guide/` match nothing.
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

## The lab harness

The lab runbook is [docs/lab-runbook.md](docs/lab-runbook.md). It covers
install in the lab container, the lab cases and the results export.

```sh
lurewall lab list                                   # all available cases
lurewall lab case 3 --from machine-b                # run one, record it in the ledger
lurewall checkpoint pull --pubkey KEY --repo DIR    # test machine A job: fetch, check, commit
lurewall lab results --log LOG --pubkey KEY --anchors DIR --ledger L --out OUT
lurewall lab tamper --log COPY --pubkey KEY --anchors DIR --work DIR   # case 6
```

- **Requests.** The harness sends plain GET and HEAD requests. It sends them
  only to a private or loopback address over HTTP and refuses anything else.
- **Ledger.** Each run is written to a ledger on the client with its source
  address and time window. The signed log holds no request text, so the
  ledger is what ties events to a case.
- **Results.** `lab results` verifies the log first and exports nothing from
  a log that fails. It escapes every string it writes.
- **Case 20.** A careful AI agent runs from the operator's own machine, with
  every request approved by hand. It is dry-run only, and the export fails the
  run unless the log shows dry-run for the whole of it.

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
