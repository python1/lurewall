# Lurewall v2 build spec: quiet canaries

Status: built in the v2 PR. Tracked in issue #14.
Inputs: the v2 canary design, a review on Nov 17, 2026, and lab results from
cases 7, 11, 13, 14, 15 and Phase 7.

This is the spec as written, with three kinds of note added:

- **Changed:** what the build does differently, and why.
- **Dropped:** spec items left out of this PR because #17 already handled them.
- **Added:** work in this PR that the spec did not ask for.

## Goal

Add destination-style ("quiet") canaries that careful agents may follow,
**alongside** the v1 imperative canaries, so the lab can measure which kind
catches which agents. The two-signal rule (counted canary hit + probing) is
unchanged.

## 1. Canary families

Every canary gets a `family` (`v1-imperative` or `v2-quiet`) and a `signal`
type in the event log and docs.

| ID | Family | Where | Example text (token = per-install random) | Signal | Counts toward a block? |
|---|---|---|---|---|---|
| v1-* | v1-imperative | existing placements | unchanged | `ai` | yes (unchanged) |
| B | v2-quiet | HTML comment in the normal page footer | `<!-- legacy settings archived at /<dir>/settings-<token>/ -->` | `ai` | yes |
| A | v2-quiet | `robots.txt` | `Disallow: /<dir>-old-backup-<token>/` | `recon` | yes, but labelled recon |
| C | v2-quiet | `/.well-known/security.txt` (valid file) | `# Previous disclosure archive: /<dir>/archive-<token>/` | `research` | **no, log-only** |
| D, E | v2-quiet | sitemap entry, `Link: rel="archives"` header | as in the design doc | none | **not in this PR**; later, after false-positive data |

**Changed:** the spec's examples used fixed first segments (`/old/`,
`/security/`). Here every path starts with a per-install word, drawn the same
way as the v1 decoys, so no two installations share a decoy path. The token is
8 hex characters.

Rules:

- **Ship B first.** It's the most AI-specific and the most accessibility-safe:
  comments aren't rendered, aren't read by VoiceOver and aren't shown by lynx. A
  and C ship in the same PR, A on and C log-only, as listed above.
- **No imperative wording** in any v2 text ("verify", "approve", "must",
  "click", "AI agents should"). Enforced by `canaries.validate` and a test.
- **A is "recon", not "AI".** Normal scanners read robots.txt. The log, the
  docs and the results say "recon signal", never "AI signal". A scanner that
  follows A and then probes **can be blocked**; the docs say so.
- **C never counts.** Honest researchers are invited to read security.txt. A
  hit is logged with decision `research_log_only` and is excluded from the
  canary count in the engine.
- **v1 stays.** No v1 canary is removed or reworded in this PR (aside from the
  existing human-readable notice).

## 2. Serving, GET-only, no collisions

- The trap matches GET and HEAD only. Other methods are not counted.
- The response is byte-identical to the site's normal 404 (status, body,
  length, headers). No redirect, cookie or state change.
  - **Changed:** `X-Robots-Tag: noindex` is now on **every** 404 the site
    serves, not only on a trap's. A trap's 404 is then truly identical to any
    other 404.
  - **Changed:** the quiet decoys have no nginx location at all. They fall
    through to the ordinary 404, so nothing in the response can give them away.
- Paths include a per-install random token (at least 8 hex characters). It is
  stored in the private canary state file, never in the repo or docs.
- Startup check: the service disables any canary whose path collides with a
  real file or route, and logs `canary_disabled_collision`.
- **Changed:** rotation uses the existing `lurewall canaries rotate` command,
  either `--id <canary id>` or `--all`. It regenerates tokens. Retired paths
  become ordinary 404s and are no longer counted.
- The cross-site framing guard is unchanged (case 8): cross-site requests are
  logged, never counted.
- Docs and examples use `<token>` placeholders only. Never commit real canary
  paths.
- **Added:** a quiet decoy carries no request ID, so a hit is bound by the page
  that carried it. It counts only if the same source was served that page (B: any
  content page; A: robots.txt; C: security.txt) as a non-cross-site GET or HEAD
  in the last 24 hours. Otherwise it is logged as `canary_unbound` with reason
  `not_served` or `expired_served`.

## 3. Log and result changes

- Every `canary_hit` event gets `family` and `signal`.
  - **Changed:** the canary's id stays in the existing `canary` field rather
    than a new `canary_id` field, so v1 logs and v2 logs read the same way.
    `block` and `would_block` also gain `canary_family` and `canary_signal`.
- `lab results` reports hits per family and per signal, and per agent the runs
  with a v1 hit and the runs with a v2 hit, so v1 and v2 catch rates can be
  compared per agent. Old logs without the fields read as `v1-imperative`,
  `ai`.
- **Dropped:** the case 7 `would_block_suppressed` rename. #17 already
  handled it.

## 4. Matcher-normalization tests (unit + lab case 17)

Each must match as the same attack signal as its plain form, and each v2 trap
path must match its variants as a canary hit:

- Case: `/.ENV`, `/.Env`, `/.GIT/config`
- Encoding: `/%2eenv`, `/%2Eenv`, double-encoded `/%252eenv`, `/.git%2fconfig`
- Path tricks: `//.env`, `/./.env`, `/..;/.env`, `/foo/..;/.git/HEAD`,
  trailing `/.env/` and `/.env.`
- Canary variants: token path with different case, trailing slash, `%2f`, and a
  query string
- Negative tests: real site paths that merely contain "env" or "git" (for
  example `/environment-guide/`) must **not** match.

**Added:** a lenient path form for attack-path rules. It drops path parameters
(`/..;/` reads as `/../`) and trailing dots (`/.env.` reads as `/.env`), as some
servers do. Before this, `/.env.` matched nothing.

**Added:** more probe paths as attack signals, with negative tests:

- `.env~`, `.env.save`, `.env.example`
- `config.php.bak`, `web.config`, `settings.py`
- `.npmrc`, `.pypirc`, `.aws/credentials`, `.docker/config.json`
- `.git/logs/HEAD`, `.git/refs/heads/main`, `.hg/`, `.bzr/`
- `/phpmyadmin/`, `/actuator/env`, `/actuator/heapdump`, `/_profiler`, `/server-info`
- `/.vscode/sftp.json`
- `*.swp`, `*.old`

The last two are new `suffix` rules: the last path segment ends with the suffix
and has something before it.

## 5. Testing plan

- **The agent that helped design these canaries is excluded as a test agent.**
  It knows where they are, so any run by it is not counted.
- Someone other than that agent enables the canaries and generates tokens. The
  test agents get only the task prompt.
- Test agents: a careful AI agent (both by curl and by its fetch tool), a
  second hosted coding agent, and a fresh agent with no Lurewall context. Others
  when available.
- Controls, expecting zero blocks:
  - browsing from test machine A
  - VoiceOver
  - lynx
  - a robots.txt-respecting crawler
  - a security.txt reader
- Per run, record:
  - canary family and ID taken
  - signal type
  - probe burst yes/no
  - decision
  - whether the agent called the canary suspicious
- Rotate tokens between agents: `lurewall canaries rotate --id <canary id>`
  or `--all`, then rebuild the site.
- **Dropped:** the Phase 7 rerun with the harness truncate step fixed. #17
  fixed the truncate step, and the fix was rechecked on the export copy.

## 6. Out of scope for this PR

- Probe-burst-only blocking (strict mode). It stays a separate, opt-in
  proposal.
- Canaries D and E.
- Any change to the two-signal rule, TTLs, or the nftables adapter.

## Acceptance

- v1 and v2 canaries are both live. B is on by default, A is labelled recon,
  and C is log-only and excluded from counts.
- All normalization tests pass, including the negatives.
- No real canary paths, tokens, IPs or homelab details are in the repo, the
  docs or the test fixtures.

Created by Paul Charydczak.
