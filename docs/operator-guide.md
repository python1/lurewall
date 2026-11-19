# Lurewall operator guide

Created by Paul Charydczak.

Use a dedicated nginx vhost on a Debian or Ubuntu host that runs systemd and
has Python 3.11 or newer. nginx needs the HTTP sub and real-IP modules. The
installer adds a service account, a private event log and a separate nginx
access log. It starts in dry-run, keeps active nginx configuration under your
control, and gives the detector no firewall capability initially.

The bundled site is a standalone static canary vhost. Keep its access log
exclusive to that vhost. Existing application vhosts and their log formats can
stay in place. Evaluate in a disposable VM or isolated vhost before depending
on enforcement. Maintain console access while you qualify firewall settings.

## Install and connect nginx

Check out the candidate commit you intend to evaluate and initialize its
pinned signing submodule. Run the installer from that trusted checkout.

```sh
sudo apt install nginx nftables logrotate python3-venv git
git submodule update --init
sudo ./deploy/manage install
sudo lurewall status
```

The installer builds a root-owned release in its own virtual environment.
By default, pip resolves build and runtime dependencies from its package
index. For an offline build, supply a wheelhouse for your Python and platform
with `--wheelhouse /path/to/wheels`. It must include runtime dependencies
and the build requirements. The installer verifies the pinned signing code
before switching the release.

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
Check permissions both as root and as the service account where practical.
The unprivileged account in dry-run may be unable to query nftables. When
enforcement is configured, verify startup under the real systemd drop-in.
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
HTTPS endpoint. Its messages carry fixed event types and can coalesce repeated
events. Keep the URL private. Protect the journal and metrics as you would
other operational telemetry.

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

Upgrade with `sudo ./deploy/manage upgrade` from a chosen newer checkout.
Check the service and `doctor` afterward. Updates keep the operator configs,
signing key, checkpoints, reader cursor, engine state and signed log. If
activation fails, the installer restores the previous executable and unit
definitions without rewinding evidence. Keep off-host copies of your key and
signed log before upgrading.

Exit status 3 stops automatic restarts after a signed-log integrity failure.
Preserve the log, published checkpoint and independently retained anchors.
Verify a candidate log against those anchors before restoring it. If no
surviving history matches, document the gap and archive the evidence. Use a
separate signing key and anchor history for a new chain. The
[rollback recovery section](lab-runbook.md#recovering-after-a-signed-log-rollback)
has the verification and restart steps.

## Uninstall and qualify a peer deployment

Detach the operator vhost and format include, run `nginx -t`, and reload
nginx. Then run `sudo ./deploy/manage uninstall`. This removes the managed
software and units and clears their reserved nftables table. Config, site
content, key, state, checkpoints and logs remain for recovery or audit.

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

Production follow-up includes operating-system package pinning and signed
release artifacts, longer-running live-host qualification, and
deployment-specific consent, monitoring, retention and capacity policies. A
CDN enforcement adapter merits a separate design for limited credentials,
provider-scoped TTLs, failure handling and independent verification.
