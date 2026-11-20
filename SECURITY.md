# Security policy

The operator workflow is intended for evaluation on a dedicated nginx canary
vhost. Initial installs observe only. Before enabling enforcement on a server,
qualify the deployment against the [operator guide](docs/operator-guide.md).
The project provides no production support commitment.

## Reporting a vulnerability

Please report privately, not in a public issue:

1. Open the repository's **Security** tab on GitHub.
2. Choose **Report a vulnerability** and describe the problem.

Useful details: what you did, what happened, what you expected, and the commit
you tested. Do not include real secrets or anyone's personal data.

Reports are read by the maintainer, Paul Charydczak. This is a one-person
project with no bounty and no guaranteed response time.

## What counts

- A way to get an innocent source blocked.
- A way to edit, drop, reorder or forge signed log entries without `verify`
  noticing, within the limits the README states.
- A way to make the log reader drop or misread a line, or to hide an event in
  a flood.
- A secret or per-installation canary value committed to this repository.

## What Lurewall will never do

Lurewall is defensive only. It never scans visitors back, serves an executable
payload or associates an address with a named individual. An optional notifier contacts only the
operator-configured webhook and sends fixed event types. Nginx logs requests
to decoys. A v1 request gets a fixed decoy body holding no data, and a v2
quiet decoy gets the same ordinary 404 response as other missing paths. A
change that breaks any of these is a security bug.

## Secrets

No secret belongs in this repository. Signing keys and API tokens load from the
environment or from a file outside the repo, and CI scans every push and pull
request with gitleaks.


## Address correlation and retention

A private carrier response can bind a local path to a source (IPv4 address or
IPv6 /64). During its 3–7 day validity window the detector can recognize a
reuse from another source, including a client with no cookies. The detector
compares the address used by nginx for personalization with its trusted source
resolution. Ambiguity, cross-site framing and mismatched attribution do not
supply a positive link. Same-source rules, thresholds and allowlists still
control enforcement. Cross-IP reuse contributes zero enforcement evidence.

The nginx lease files contain a keyed source tag and start/expiry timestamps.
Expired leases cease to apply immediately and are reclaimed when their bucket
is next written. The detector keeps its issuance index in memory and saves
the newest live receipts to `/var/lib/lurewall/engine.json.receipts`. That
file is mode 0600 and bounded at 10,000 receipts and 4 MiB. Each receipt holds
the issued path, its source key, placement, issuance and expiry times, the page
request ID and a line digest. Expired receipts are dropped when the file is
next written and are never restored. Private
nginx access logs can contain both source and full paths. The shipped rotation
keeps seven prior access-log files, rotating daily or on size.

Signed relay events retain the two source keys, placement, request references,
line digests and timing when available. Candidates are computed on demand
from this history. There is no persistent link graph or background lookup.
The 3–7 day window bounds issuance, not retention of signed evidence. Signed
history, backups and exported reports persist until the operator archives or
removes them under local policy. Protect verification anchors when archiving
a chain. Report output can disclose both source keys and evidence times.
HTML omits raw request targets and canary paths. Grafana uses aggregate
metrics. Store reports privately and redact source identifiers before sharing.

A path can be copied, published, forwarded by a crawler, or served from a
misconfigured shared cache. A third address following the same issuance can
create another candidate. None of these events proves who operated the client.
