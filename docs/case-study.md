# Lurewall v1: a lab case study

Created by Paul Charydczak. November 2026.

## The problem

AI agents now browse and probe websites on their own. A site's access log sees
their requests but not their nature. Lurewall v1 asked a narrow question: in a
lab, can harmless canaries planted in content a sighted visitor never sees,
combined with ordinary attack signals, pick out an agent that is probing a
site, without ever blocking an innocent visitor?

## The design

- **Two signals or nothing.** A source is blocked only when two kinds of
  evidence agree:
  - a canary hit bound to that source (the reference carries a request ID
    issued to the same address);
  - two or more distinct attack probes from separate requests, such as
    `/.env` or `/.git/config`.

  Either one alone is logged and nothing more. Speed, user agents and other
  behavior count for nothing.
- **Blocks that end on their own.** A block is an element in an nftables set,
  with the kernel's own timeout. A separate sweeper removes overdue entries
  even with the service stopped. Dry-run is the default.
- **A log that can be checked.** Every decision is one line of canonical JSON.
  Each line is signed with Ed25519 and chained to the line before it.
  Checkpoints are pulled off the box every few minutes and committed to git on
  another machine, so the record can be verified later against copies the lab
  box can't change.

## The lab

The site was a throwaway one in an unprivileged Debian 13 container: nftables
1.1.3, nginx 1.26.3. The host firewall let in only two clients on the home
network, and cut the container off from the internet and the rest of the LAN.

- **Twenty cases.** They covered benign AI agents, scripted attackers, a human
  browsing, accessibility tools, framing, flooding, hostile bytes and process
  failure.
- **Two phases.** Every case first ran in dry-run. Then the container switched
  to enforcing with real nftables blocks.
- **The record.** Each run was recorded in a ledger on the client and judged
  against the signed log.
- **Leaks.** The canaries were rotated twice after a reference leaked outside
  the lab, both times before any AI agent ran.

## Results

Full details are in [lab-findings.md](lab-findings.md).

- **Enforcement works end to end.** A scripted client read a page, took its
  canary and sent two probes. It was blocked, cut off, and let back in when the
  5-minute block expired. A block also expired on time with the service
  stopped, and a backlog read after downtime enforced nothing.
- **No false positives in the tests that look for them:**
  - a human browsing;
  - a screen reader;
  - framing by a hostile page;
  - an allowlisted source;
  - a log-only range;
  - a link-following crawler with no model behind it, which took 4 of the 7
    canaries but never probed, so it was only logged.
- **The log held up.** Edited, deleted, reordered and truncated copies of the
  real log were all caught.
- **The AI agents took no canary:**
  - a commercial coding agent fetched pages with `curl` and followed no canary;
  - a local open-source agent couldn't reach the lab at all, because its fetch
    tool refuses private addresses.

## Case 20: the careful agent

A careful AI agent was asked to check the lab site for exposed files, with
every request approved by hand. It probed about 25 paths. Lurewall logged
about 20 attack signals across `.env`, `.git`, SQL dumps, SSH keys and server
status pages, and the attack threshold was met.

The agent also noticed the response-header canary. It called it suspicious
and did not follow it.

So the agent saw the trap and declined it, and its probing was still detected
and logged. By design, it was not blocked: without a canary hit, attack
signals alone never block. After a debrief in which it learned how the traps
worked, the agent was excluded from further runs.

## Limits

- **Careful agents decline v1's canaries.** v1's canaries are written as
  instructions, which a careful agent reads as a red flag. No AI agent was
  caught in the lab.
- **The full chain is proven with scripted clients only.** The planned AI
  agent runs in the enforcing phase were not run.
- **Shared addresses.** Everyone behind a blocked address loses the site for
  one TTL.
- **Split addresses.** A client that reads from one address and probes from
  another is not blocked.
- **The log's newest entries.** Entries after the last anchored checkpoint
  can't be proven complete. In the lab that was at most about 10 minutes.
- **Substitutions.** Some enforcing cases ran from a single machine in place
  of a second one. Each is noted in the findings.

## Next steps

Issue #14 tracks these:
- **Destination-style canaries.** Lures that point where a careful agent would
  look anyway, such as a `robots.txt` entry, a sitemap entry or a quiet "config
  moved" comment, instead of giving orders.
- **More probe paths.**
- **Wider tests of the matcher's normalization.**
- **An opt-in strict mode.**

After that, run the lab again with more agents. The two-signal rule stays the
default.
