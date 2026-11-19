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
payload or tries to identify anyone. An optional notifier contacts only the
operator-configured webhook and sends fixed event types. Nginx logs requests
to decoys. A v1 request gets a fixed decoy body holding no data, and a v2
quiet decoy gets the same ordinary 404 response as other missing paths. A
change that breaks any of these is a security bug.

## Secrets

No secret belongs in this repository. Signing keys and API tokens load from the
environment or from a file outside the repo, and CI scans every push and pull
request with gitleaks.
