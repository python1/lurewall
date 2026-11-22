# Lurewall operator guide

Created by Paul Charydczak.

Use a dedicated nginx vhost on Debian 13 or Ubuntu 24.04 LTS with systemd.
The package uses system Python and the distro's cryptography package. It
requires cryptography 40 or newer, which excludes the stock Debian 12
package. nginx needs the HTTP sub and real-IP modules. The
installer adds a service account, a private event log and a separate nginx
access log. It starts in dry-run, keeps active nginx configuration under your
control, and gives the detector no firewall capability initially.

The bundled site is a standalone static canary vhost. Keep its access log
exclusive to that vhost. Existing application vhosts and their log formats can
stay in place. Evaluate in a disposable VM or isolated vhost before depending
on enforcement. Maintain console access while you qualify firewall settings.

## Install and connect nginx

Download the `.deb`, `SHA256SUMS`, `SHA256SUMS.sig`, and
`lurewall-release.pub` for the same [GitHub release](https://github.com/python1/lurewall/releases).
Get the expected Ed25519 key fingerprint from the maintainer through a
trusted channel. Check it before trusting the public key downloaded with the
package. Use a directory that contains only the release files.

```sh
sudo apt install openssh-client
ssh-keygen -lf lurewall-release.pub
```

Once the fingerprint matches, verify the signed manifest and the package
checksum before asking APT to install it.

```sh
awk 'NR == 1 {print "lurewall-release", $1, $2}' lurewall-release.pub > allowed-signers
ssh-keygen -Y verify -f allowed-signers -I lurewall-release \
  -n lurewall-release -s SHA256SUMS.sig < SHA256SUMS &&
  sha256sum --check --strict SHA256SUMS &&
  sudo apt install "./$(awk 'NR == 1 {print $2}' SHA256SUMS)"
sudo lurewall status
```

The manifest contains the package filename. APT resolves its dependencies
from the configured distro repositories. The package performs no pip build
or download on the server.

If you staged the package in an offline image and received an offline-install
warning, run `sudo dpkg-reconfigure lurewall` on the booted host before
enabling nftables enforcement.

For a system previously installed from source, detach and reload nginx as
described under uninstall, then use that checkout's `deploy/manage uninstall`
before installing the package. Keep the retained signing key and evidence.
Remove any retained systemd enforcement drop-in and return the retained
configuration to dry-run before installing from the package.

The installed launcher runs ordinary `sudo lurewall` commands as the
detector account. The allowlist editor is the privileged exception. It uses
trusted application source and the standard library without loading built
packages.

Set `VHOST` to the exact dedicated DNS hostname you will use. Set the same
hostname in `[site].hosts` in `/etc/lurewall/signals.toml`. The generated
configuration uses a plain HTTP listener. Add TLS using your normal nginx
configuration and set `[site].https = true` when the browser-facing origin is
HTTPS. Set `--listen` explicitly if you need an isolated test port, and use that
same port if you later enable firewall enforcement.

```sh
VHOST=canary.example.test
sudo install -d -o lurewall -g lurewall -m 0755 /srv/lurewall/site
sudo -u lurewall lurewall lab-site build \
  --state /var/lib/lurewall/canaries.json \
  --out /srv/lurewall/site --server-name "$VHOST"
sudo ln -s /etc/lurewall/nginx/operator-format.conf \
  /etc/nginx/conf.d/lurewall-operator-format.conf
sudo install -m 0600 /srv/lurewall/site/nginx/lurewall-site.conf \
  /etc/nginx/sites-available/lurewall-operator
sudo ln -s /etc/nginx/sites-available/lurewall-operator \
  /etc/nginx/sites-enabled/lurewall-operator
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl restart lurewall.service
```

The include belongs in nginx's `http` context. On a server with other vhosts,
keep the catch-all vhost deliberately configured and confirm the new exact
hostname resolves to the intended server block. Review the generated config
and keep the canary lookup, generated configuration and key out of Git.

## Natural placements and the first report

The earlier build command recreates the v0.2 lab fixture. For v0.3 use the
public document root of a dedicated static vhost. Supply only content meant
to be served. Route names and a local sitemap provide vocabulary and URL
shapes. If the site is small, pass `--wordlist FILE` with locally chosen
words. The build never downloads a sitemap. Use a fresh private staging
directory outside the public root and outside Git.

Natural placements need nginx's njs module, `libnginx-mod-http-js` 0.8.2 or
newer. The Debian package only suggests it, so a default install does not add
it. Debian enables an installed nginx module for every vhost and reloads nginx,
so install it only when you choose natural placements. On Ubuntu it comes from
the universe component. `lab-site build --site-root` and `doctor` refuse
natural mode and name the fix if the module is missing or too old. With
`PUBLIC_ROOT` and `VHOST` set for your site:

```sh
sudo apt install libnginx-mod-http-js
sudo install -d -o lurewall -g lurewall -m 0700 /var/lib/lurewall/build-v3
sudo -u lurewall lurewall lab-site build --site-root "$PUBLIC_ROOT" \
  --server-name "$VHOST" --state /var/lib/lurewall/canaries.json \
  --out /var/lib/lurewall/build-v3 --deploy-root /etc/lurewall/natural
sudo install -d -m 0755 /etc/lurewall/natural/nginx
sudo install -o root -g root -m 0600 /var/lib/lurewall/build-v3/nginx/* /etc/lurewall/natural/nginx/
sudo install -d -o www-data -g www-data -m 0700 /etc/lurewall/natural/leases
```

The nginx master reads the private module and includes. Keep them root-owned.
Only the leases directory needs nginx worker write access. In the nginx
`http` context include `/etc/lurewall/natural/nginx/lurewall-natural-format.conf`.
Use the generated `lurewall-site.conf` in place of the old dedicated server
block, or incorporate its log directive and exact carrier locations in the
dedicated vhost while retaining your error pages and access policy. Review
location precedence, keep the access log exclusive to this vhost, run
`sudo nginx -t`, reload nginx and restart `lurewall.service`. Do not put
the generated JS module, access logs, state or lease files under the public root.

Only the existing landing page receives a footer by default. To enable the
other placements use `--placements footer,robots,security`. The builder
preserves the resource's existing text and skips unavailable or unsupported
carriers. Signed, malformed or expired security files stay untouched. Source
windows are jittered from three to seven days. A conditional GET whose
`If-None-Match` or `If-Modified-Since` matches gets a 304 with no body. A 304
carries no path, so it is not logged as an issuance. The 200 that first
delivered the path stays valid until its window ends. Check online cache
bypass, ordinary 404 handling, and conditional GETs after deployment. Changed
carrier files are served without injection until the next build.

```sh
sudo lurewall doctor
sudo lurewall report --since 10m
(umask 077 && sudo lurewall report --since 24h --html > report.html)
sudo lurewall explain-decision "$SOURCE"
```

The signed report distinguishes qualifying bait, research hits and probes by
configured rule. A quiet window may have no signed events. Check the access
log and metrics freshness in `doctor`. A possible switch shows the issuer,
requester and signed event reference. It does not affect either address's
enforcement. There is no live dashboard service. Import the packaged
`/usr/share/doc/lurewall/grafana/lurewall.json` or source install's
`/opt/lurewall/current/grafana-dashboard.json` into Grafana and select the
Prometheus source scraping the existing textfile metrics.

**Limits.** Comparing carrier bodies from two IPs can reveal personalization.
A pool rotating addresses on every request cannot be linked into a single
agent. A third address reusing a copied path produces fan-out and ambiguous
attribution. The detector saves issuance receipts in the private
`/var/lib/lurewall/engine.json.receipts`, so they survive a restart. It keeps
at most the 10,000 most recently issued live receipts, in at most 4 MiB. On a
busier site, an older path issued before a restart is an ordinary 404 until
that source loads the carrier again. These are observations about requests, not
verified identities. See [privacy and retention](../SECURITY.md#address-correlation-and-retention).

## Verify and operate

Load the dedicated site's ordinary landing page from an authorized client.
Check the service, parser, timestamps and signed log next.

```sh
sudo systemctl status --no-pager lurewall.service
sudo journalctl -u lurewall.service -n 30 --no-pager
sudo lurewall doctor
sudo lurewall status --json
sudo lurewall pubkey --key /var/lib/lurewall/keys/lurewall.key
```

`doctor` samples the actual access log and validates the installed configs,
local paths, recent timestamps, nftables visibility and the checkpoint.
The standalone doctor runs as the service account without the unit's
firewall capability. If its nftables probe is unavailable, use
`sudo /usr/sbin/nft -j list tables` for the independent read-only kernel
check. When enabling enforcement, also verify startup under the systemd
drop-in.
An empty access log gives no evidence of nginx integration. Generate ordinary
traffic first and confirm the records counter and metrics timestamp advance.

`status` shows engine intent, not a kernel ruleset check.
`sudo lurewall explain-decision "$CLIENT_ADDRESS"` verifies the signed history
and shows recent decisions for one address. IPv6 addresses use their /64
source key. Retain the public key and copies of checkpoints on a separate
trusted system. Supply those copies with `--anchors` when you need independent
verification. Restrict access to the raw nginx access log and signed evidence
under your retention and privacy policy.

Use `sudo lurewall allowlist list`, `allowlist add "$MANAGEMENT_RANGE"` or
`allowlist remove "$MANAGEMENT_RANGE"` to manage protected ranges. Restart the
service after changing the file. TOML allowlist entries are also effective.
`sudo lurewall unblock "$CLIENT_ADDRESS"` queues a removal for the running
service. Confirm the signed decision before treating it as applied. Allowlist
a source first if future observations should never block it.

## Enable direct-host blocking

Review dry-run decisions with your operators and allowlist your management and
health-check ranges first. Set `dry_run = false` and
`[enforcement].adapter = "nftables"` in `/etc/lurewall/engine.toml`. Set
`[enforcement].tcp_ports` to the TCP listeners you intend to protect. The
installed policy starts with 5-minute blocks, a 30-minute ceiling and a
256-source cap.

```sh
sudo install -d -m 0755 /etc/systemd/system/lurewall.service.d
sudo install -m 0644 /etc/lurewall/systemd/50-enforcement.conf \
  /etc/systemd/system/lurewall.service.d/50-enforcement.conf
sudo systemctl daemon-reload
sudo systemctl restart lurewall.service
sudo systemctl enable --now lurewall-sweeper.timer
sudo lurewall doctor
```

The rules apply in the host INPUT hook to the chosen TCP ports across vhosts
that share those ports. UDP and forwarded container traffic are outside this
mode. A source block can affect everyone sharing its IPv4 address or IPv6
/64. Use an isolated listener where that impact would be unacceptable.

For a CDN or reverse proxy, leave the service in observation mode and set
`[sources].trusted_proxies` to the exact connecting proxy CIDRs. Each trusted
proxy must set or append the address it received. Lurewall reads the original
socket peer logged by nginx and uses forwarded addresses only when that peer
is trusted. It follows the trusted chain from the right and stops at the
first untrusted address. Proxy configuration and nftables enforcement are
incompatible because the firewall sees the proxy connection. nginx must
support `$realip_remote_addr` for the operator format.
[nginx real-IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)

## Alerts and health

The service writes `/var/lib/lurewall/telemetry/lurewall.prom`. Give the
collector read-only access to a copy or to this textfile without opening up
the signing key or operator control directory. Monitor metric freshness,
`lurewall_up`, log lag, access-log parse failures, `lurewall_signed_log_stopped`
and enforcement failures.
The enforcing gauge reports configured mode. Inspect the journal and the
systemd unit if the metrics stop updating.

To opt into webhook alerts, put `LUREWALL_WEBHOOK_URL` in
`/etc/lurewall/alerts.env` owned by root with mode 0600, and enable
`lurewall-notify.timer`. Only the separate notifier contacts the configured
HTTPS endpoint. It shares the detector's `lurewall` service user and has its
own systemd sandbox. Its messages carry fixed event types and can coalesce
repeated events. Keep the URL private. Protect the journal and metrics as
you would other operational telemetry.

## Rotate, upgrade and recover

To rotate canaries, schedule a maintenance window. Observe only while updating
references. Stop Lurewall, save the existing canary state and generated vhost
privately, and run `sudo -u lurewall lurewall canaries rotate --all --state
/var/lib/lurewall/canaries.json`. Build into a fresh site directory with the
same hostname, install the new vhost configuration, run `nginx -t` and reload.
Start Lurewall with the new canary state. Retain the signed log and reader
cursor. When switching from enforcement to dry-run, stop both firewall units
and remove the installation's reserved `inet lurewall` table if you need to
clear its blocks immediately. Otherwise existing kernel entries expire on
their own.

The natural build adds a private `canaries.json.v3` sidecar. Keep the original
`canaries.json`, engine and signals configs, engine state, signed evidence, and
old vhost configuration.

**Rolling back to v0.2.x after enabling natural placements: nginx first.**
v0.2.x cannot parse the natural log format. If the package is rolled back
while the natural vhost is still logging, v0.2.x records every request as a
parse failure and detects nothing. `doctor` warns about this whenever natural
placements are enabled. Package installs and upgrades print the same warning,
and so does a downgrade below v0.3. Roll back in this order:

1. Restore the previous vhost and log-format include, run `sudo nginx -t`
   and reload nginx.
2. Install the prior package.
3. Restart `lurewall.service`, run `sudo lurewall doctor`, and confirm the
   records counter advances.

The v0.2 executable opens its original state and ignores the sidecar and the
receipts file. After a rollback, any address that took natural bait in the
last seven days is labelled `v1-imperative`/`ai` in later decisions. A
robots-file placement would otherwise be `recon`. To return a v0.3 executable
to legacy rendering,
move the sidecar aside privately and restart the detector with the legacy
vhost. Stage changes while observing and keep the previous generated files
until the new deployment is qualified.

For an upgrade, download and verify the newer release files as above and
install the verified `.deb` with APT. Keep your operator configuration if
prompted about a locally edited conffile. The signing key, checkpoints,
reader cursor, engine state and signed log stay in place. Check the service
and run `doctor` afterward. Keep off-host copies of your key and signed log
before upgrading.

Exit status 3 stops automatic restarts after a signed-log integrity failure.
Preserve the log, published checkpoint and independently retained anchors.
Verify a candidate log against those anchors before restoring it. If no
surviving history matches, document the gap and archive the evidence. Use a
separate signing key and anchor history for a new chain. The
[rollback recovery section](lab-runbook.md#recovering-after-a-signed-log-rollback)
has the verification and restart steps.

## Uninstall and qualify a peer deployment

Detach the operator vhost or remove its Lurewall `access_log` directive.
Remove the format include, run `sudo nginx -t`, and successfully reload
nginx with `sudo systemctl reload nginx`. Then run `sudo apt remove lurewall`.
Package removal checks the nginx configuration on disk and
refuses to proceed if it still references the managed log or format, or if
the check fails. The reload applies the detached config to running workers.
Successful uninstall removes the managed software and units, drops the
reserved nftables table, and immediately lifts active Lurewall blocks.
Config, site content, key, state, checkpoints and logs remain for recovery or audit.
Use APT's remove operation to retain package configuration files. A purge can
delete those files.

If nginx is missing or its configuration cannot be parsed, use
`sudo lurewall uninstall --force` (also `sudo ./deploy/manage uninstall --force`
from a trusted source checkout). Force permits an unavailable nginx inspection.
A successful inspection finding an attached Lurewall configuration still stops
removal. Firewall ownership and evidence retention checks remain in effect.
Inspect retained includes before bringing nginx back online.

On a disposable Debian/Ubuntu VM or a peer's authorized staging server:

1. Install, serve ordinary traffic over IPv4 and IPv6, and verify the
   operator metrics and signed checkpoint. Confirm no Lurewall filter is
   installed during observation mode.
2. Check permissions after nginx log rotation. Upgrade and verify that the
   key identity, signed log and reader progress survive. Exercise a rejected
   config, stop the service and confirm metrics staleness is visible.
3. With a private console and direct, isolated listeners, verify the port and
   prefix scope, allowlist behavior, queued unblock and TTL expiry. Use
   controlled lab inputs in isolation for the full canary decision path.
4. Verify notifications with an operator-controlled receiver and a valid
   TLS certificate. Rehearse integrity recovery on copies and confirm an
   uninstall preserves the evidence. GitHub CI covers disposable integration
   fixtures. This checklist qualifies your host's packages and topology.

Production follow-up includes an authenticated APT repository, longer-running
live-host qualification, and deployment-specific consent, monitoring,
retention and capacity policies. A
CDN enforcement adapter merits a separate design for limited credentials,
provider-scoped TTLs, failure handling and independent verification.

## Agent verification

Install the v0.4 reader **before** switching nginx. Omit
`/etc/lurewall/agents.toml` to leave verification off. Start with dry-run.
The main service reads local files and retains its network restrictions.
The on-demand `lurewall-fetch.service` runs as its own system user and uses
system DNS, the system CA bundle and `/var/cache/lurewall-fetch`. Its
timer is opt-in. The helper has no firewall capability or inbound listener.

1. Save the currently active `/etc/lurewall/nginx/operator-format.conf`
   as `/etc/lurewall/nginx/operator-format.conf.pre-v4` before the switch.
   It is a dpkg conffile. The package ships the extended template separately
   as `/etc/lurewall/nginx/operator-format-v4.conf`. Review local differences
   and install its maps and format in the active file after upgrading.
   Natural sites instead save
   `/etc/lurewall/natural/nginx/lurewall-natural-format.conf` as
   `/etc/lurewall/natural/nginx/lurewall-natural-format.conf.pre-v4`
   and install the regenerated format include. Run `nginx -t` and reload.
2. Copy `/etc/lurewall/agents.example.toml` to `/etc/lurewall/agents.toml`.
   List only confirmed client-facing TLS authorities (include a non-default port).
   Check that the original authority, method, target, all signature headers and
   socket peer survive the actual ingress path. Configure trusted proxy CIDRs
   narrowly. Leave rewritten CDN/backend authorities out. Avoid mixing confirmed
   and lossy paths on the same logging vhost.
3. On first setup run `sudo lurewall agent-replay-init`, then
   `sudo systemctl enable --now lurewall-fetch.timer`,
   `sudo systemctl start lurewall-fetch.service` and
   `sudo systemctl restart lurewall.service`. Run `lurewall report --since 10m`
   and check the fetch unit journal. A missing, corrupt, full or locked replay
   store withholds signature credit. To recover, restore the original store.
   If its history is lost, leave verification offline for at least 24 hours plus
   60 seconds before explicitly creating a fresh store.
4. For offline operation omit the timer, and place each trusted public range or
   key document in `/etc/lurewall/pins/FEED.json` under root ownership. Configure
   its lowercase `sha256` and integer Unix `pin_until` in the feed table.
   Transfer key sets from a trusted control plane that fetched the configured
   HTTPS directory. A local digest alone cannot establish publisher provenance.
   Rotate the pins and restart the reader before expiry.

nginx records version 4, the original request line and URI, original authority
including port, scheme, protocol, vhost, request duration and three signature
headers. Fields use JSON escaping. The reader stores duration in integer milliseconds.
Each signature field above 8192 bytes becomes an explicit overflow marker. Keep
`large_client_header_buffers` appropriate for the vhost (for example `4 16k`).
nginx may reject a header larger than one buffer before the request reaches a
location. Keep the access log private and rotate it since a captured signature
may remain reusable until expiry. The signed event records the verdict and
snapshot digests and omits raw signatures. The outer log-line bound is 256 KiB.

The adapter verifies Ed25519 and RSA-PSS-SHA512 on captured RFC 9421 components,
including the agent member bound to its signature label. It accepts deployed
legacy quoted agent headers. It checks published key IDs, key validity at
issuance and use, a maximum 24-hour signature lifetime and 60 seconds of skew.
Replay checks use a persistent per-key nonce or a digest of the signed base.
A minimal authority-only signature provides no assurance about the path or body.

Exact HTTPS feed URLs, the byte limit (256 KiB default), a three-second
deadline, public-only DNS resolution and certificate verification apply to
both kinds of fetch. Redirects are rejected. No content-type assumption is
made. The helper revalidates according to publisher cache directives, capped
at one hour and rate-limited to once per minute. It stores local verification
snapshots with a one-hour lifetime from successful retrieval; publisher
`creationTime` is informational. An unknown key queues a bounded file request
for the next timer run. Each read produces its final verdict without waiting.
Check `alert_after_hours` for persistent retrieval failure alerts.

Only Google's shipped range mappings are authoritative. Other feeds are partial.
An IP match uses the full client address before IPv6 grouping. A valid expected
signature or an in-range address verifies a claim. An authoritative miss with no
valid signature, or a conclusively bad signature for the expected signer, can raise
an impersonation alert. Missing evidence, unsupported families and rewritten
ingress stay indeterminate. Signed browser requests can establish an identity
even with an ordinary browser User-Agent. Set `alert = false` in a claim table to
mute its notification while retaining its signed observation. No identity result
has any enforcement weight.

A range establishes publisher egress at the stated scope. Corporate NAT, CGNAT,
VPNs and Tor can put unrelated visitors behind one address. SEO audit tools
often send a Googlebot User-Agent from an office network. Allowlist your own
office before enabling ordinary enforcement. Consult the evidence method and
source before attributing an alert to an individual.

### Roll back from v0.4 to v0.3

Restore `/etc/lurewall/nginx/operator-format.conf.pre-v4` over
`/etc/lurewall/nginx/operator-format.conf`. For natural sites restore
`/etc/lurewall/natural/nginx/lurewall-natural-format.conf.pre-v4` over
`/etc/lurewall/natural/nginx/lurewall-natural-format.conf`. Run `nginx -t`,
reload and let old nginx workers finish their outstanding requests. Keep v0.4
running until the reader has drained the last extended line across any rotation.
Check the cursor inode/offset against the active access log after a quiet interval
and verify the signed log and checkpoint. Stop the fetch timer and service, then
stop the reader, install the previous release and resume with the **same**
`reader.state`, engine state, signing key, events log and checkpoint. Preserve the
restored local conffile if dpkg prompts. The engine schema stays at version 1.
Verify the chain again and check that the cursor advances on a new legacy line.
