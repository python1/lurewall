# Lurewall lab runbook

How to install Lurewall in the lab container, run the lab cases and
export results that verify against the anchored checkpoints.

Each block names the machine it runs on. Nothing here touches any
other guest. Values in `<ANGLE_BRACKETS>` come from an earlier step. Never
guess them. Lurewall stays in dry-run until Phase 6 says otherwise.

| Machine | Address | How to get a shell |
|---|---|---|
| Lab host | 192.0.2.170 | the hypervisor's web UI → host shell |
| Lab container | 192.0.2.160 | `pct enter <CTID>` from the lab host shell |
| Test machine A | 192.0.2.177 | Terminal |
| Test machine B | 192.0.2.152 | WSL Ubuntu shell (requests leave as the Windows LAN address) |

## Debian 13 (trixie), not 12

The lab container runs Debian 13. The design doc assumed Debian 12. What changes:

| Package | Debian 12 | Debian 13 | Checked how |
|---|---|---|---|
| nftables | 1.0.6 | 1.1.3 | CI job `debian13` runs the real-nft tests on trixie's own package |
| nginx | 1.22 | 1.26.3 | same job: the nginx and lab end-to-end tests |
| Python | 3.11 | 3.13.5 | same job |
| systemd | 252 | 257 | not tested in CI; the units are checked by `systemd-analyze verify` in Phase 3 |

The container uses the lab host's kernel, not Debian's. CI runs on the GitHub
runner's kernel, so Phase 2 runs the real-nft tests inside the lab container itself.

---

## Before Phase 0: the lab container's firewall (done Nov 17, 2026)

Done in this order, with the lab container stopped, so it never ran unfiltered. All on the
lab host shell.

1. **Datacenter firewall, everything allowed.** Write `/etc/pve/firewall/cluster.fw`
   with `enable: 1`, `policy_in: ACCEPT` and `policy_out: ACCEPT`. Guests without
   their own `<vmid>.fw` stay unfiltered. Arm an automatic rollback first:
   `systemd-run --on-active=5min --unit=lurewall-fw-rollback /bin/rm -f /etc/pve/firewall/cluster.fw`.
   Then check the UI and the other guests before running
   `systemctl stop lurewall-fw-rollback.timer`.
2. **DNS off the LAN.** Run `pct set <CTID> --nameserver 1.1.1.1`. Without a
   nameserver line, the container inherits the host's resolver (the router), which
   the firewall drops.
3. **`/etc/pve/firewall/<CTID>.fw`.** Set `policy_in` and `policy_out` to DROP, and
   `ndp: 0`, which leaves IPv6 with link-local only: no router advertisement,
   no global address, no route. The rules: inbound TCP 80 from .177 and .152;
   outbound `DROP -dest 192.0.2.0/24` first; then DNS, 80 and 443 to the
   internet, for setup only.

**After any `.fw` change, wait until `pve-firewall status` no longer says
"pending" before you start or reboot the lab container.** Until then the old rules still
apply.

Leak tests and what they showed (curl exit codes: 28 timed out, so dropped;
7 refused; 0 success):

| Test | Run on | Expect |
|---|---|---|
| `curl -4 -m 5 -sk https://192.0.2.170:8006` | lab container | 28 |
| `curl -4 -m 5 -s http://192.0.2.1/` | lab container | 28 |
| `curl -6 -m 5 -sI https://deb.debian.org` | lab container | 7 (no IPv6 route) |
| `curl -4 -m 10 -sI https://deb.debian.org` | lab container | 0 during setup; 28 after Phase 4 |
| `nc -z -w 5 192.0.2.160 22` | Test machine A | 1 (dropped) |
| `curl -m 5 http://192.0.2.160/`, nothing listening on 80 | Test machine A | 28, not 7: the container's reset goes to the LAN and `OUT DROP` drops it |
| `curl -m 5 http://192.0.2.160/`, a server on 80 | Test machine A | 0, with HTTP 200 |

## Phase 0: read-only checks

Nothing in this phase changes anything. Send me the output of each step
before going on.

### 0.1 Lab host shell

```sh
pveversion
uname -r
pct status <CTID>
pct config <CTID>
pct listsnapshot <CTID>
cat /etc/pve/firewall/<CTID>.fw 2>/dev/null || echo "no <CTID>.fw"
cat /etc/pve/firewall/cluster.fw 2>/dev/null || echo "no cluster.fw"
pve-firewall status
# Guests with firewall=1 on a NIC. Only the lab container should be listed.
grep -H 'firewall=1' /etc/pve/lxc/*.conf /etc/pve/qemu-server/*.conf 2>/dev/null \
  || echo "no NIC has firewall=1"
```

Stop and send me the output if any of these is true:

- `pct config <CTID>` shows `unprivileged: 0` or a bind mount (`mp0:`). `nesting=1` is expected:
  Debian 13's systemd needs it in an unprivileged container, and so do the sandboxing options in
  Lurewall's units.
- <CTID>.fw is missing (then the design doc's setup step 3 comes before Phase 1), or it
  allows inbound from anything but .177 and .152 on port 80.
- Any guest other than <CTID> has `firewall=1`.
- There is no snapshot to roll back to.

### 0.2 Lab container console (`pct enter <CTID>`)

```sh
grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
uname -r
nft --version
nginx -v
nginx -V 2>&1 | grep -o 'with-http_sub_module'
python3 --version
systemctl --version | head -n 1
systemctl is-active nginx
ls -l /etc/nginx/conf.d/ /etc/nginx/sites-enabled/
cat /etc/logrotate.d/nginx
nft list ruleset
df -h /
free -m
ip -br addr
ip route
id lurewall 2>/dev/null || echo "no lurewall user yet"
ls -ld /opt/lurewall /var/lib/lurewall /srv/lurewall /etc/lurewall 2>&1
# Isolation: both must say "blocked" while internet access is cut.
curl -m 5 -sk https://192.0.2.170:8006 >/dev/null && echo "LEAK: lab host reachable" || echo "lab host blocked"
curl -m 5 -sI https://deb.debian.org >/dev/null && echo "internet OPEN" || echo "internet blocked"
```

Stop and send me the output if any of these is true:

- `VERSION_ID` is not 13, or `nft`, `nginx` or `python3` is missing.
- The `grep` for `with-http_sub_module` prints nothing.
- The lab host is reachable from the container.
- The root disk has less than 4 GB free.

### 0.3 Test machine A terminal

```sh
ipconfig getifaddr en0; ipconfig getifaddr en1   # one of these should be 192.0.2.177
curl -sI http://192.0.2.160/ | head -n 3
cd ~/lurewall && git status -sb && .venv/bin/lurewall --version
ssh -o BatchMode=yes -o ConnectTimeout=5 root@192.0.2.170 true && echo "ssh to the lab host: ok" \
  || echo "ssh to the lab host: not set up"
```

The ssh line only tells us whether Phase 8 can copy the log with `scp`. If it
says "not set up", leave it. There is another way.

### 0.4 Test machine B, WSL shell

```sh
python3 --version          # 3.11 or newer
curl -sI http://192.0.2.160/ | head -n 3
```

---

## Phase 1: open internet access for setup (lab host)

On the first install the four setup rules are still active: skip this phase.
Later, after Phase 4 has cut the internet, re-enable them this way. A leading
`|` disables a rule.

```sh
cp /etc/pve/firewall/<CTID>.fw /root/<CTID>.fw.before-pr8
sed -i -e 's/^|\(OUT ACCEPT -p udp -dport 53\)$/\1/' \
       -e 's/^|\(OUT ACCEPT -p tcp -dport 53\)$/\1/' \
       -e 's/^|\(OUT ACCEPT -p tcp -dport 80\)$/\1/' \
       -e 's/^|\(OUT ACCEPT -p tcp -dport 443\)$/\1/' /etc/pve/firewall/<CTID>.fw
pve-firewall compile >/dev/null && echo "rules OK"
pve-firewall status        # repeat until it no longer says pending
cat /etc/pve/firewall/<CTID>.fw
```

`OUT DROP -dest 192.0.2.0/24` stays first, so the LAN stays unreachable.
Phase 4 closes the internet again.

## Phase 2: install Lurewall (lab container console)

```sh
apt update && apt install -y git python3-venv nftables nginx logrotate curl
adduser --system --group --home /var/lib/lurewall --no-create-home lurewall
git clone https://github.com/python1/lurewall.git /opt/lurewall
cd /opt/lurewall
git checkout <MAIN_COMMIT>        # the commit PR 8 merged as; I give you the SHA
git submodule update --init
git log -1 --format='%H %s'
python3 -m venv /opt/lurewall/.venv
/opt/lurewall/.venv/bin/pip install -e '.[dev]'
/opt/lurewall/.venv/bin/lurewall --version
```

Then the self-checks, on this container's own kernel and Debian 13's packages. They
start a private nginx on a loopback port and create and delete the table
`inet lurewall` in the container's own network namespace. Nothing else is touched,
and Lurewall is not running yet.

```sh
cd /opt/lurewall
LUREWALL_REQUIRE_NFT=1 LUREWALL_REQUIRE_NGINX=1 .venv/bin/python -m pytest -q \
  -p no:cacheprovider tests/test_nft.py tests/test_nginx_integration.py tests/test_lab_e2e.py
nft list tables     # expect no "inet lurewall" left behind
```

If any test fails, stop and send me the output. A failing `test_nft.py` here
answers the design doc's open question ("nftables in an unprivileged LXC") with
no. Phase 6 must then stay on the log-only adapter.

## Phase 3: configure (lab container console)

```sh
install -d -o lurewall -g lurewall -m 0700 /var/lib/lurewall /var/lib/lurewall/keys
install -d -o root -g root -m 0755 /srv/lurewall /etc/lurewall
install -d -o lurewall -g lurewall -m 0755 /srv/lurewall/site /srv/lurewall/checkpoint
cp /opt/lurewall/deploy/signals/lab-site.toml /etc/lurewall/signals.toml
cp /opt/lurewall/deploy/engine/lab.toml /etc/lurewall/engine.toml
sed -i -e 's/^ttl_minutes = 1440$/ttl_minutes = 5/' \
       -e 's/^max_ttl_minutes = 10080$/max_ttl_minutes = 10/' /etc/lurewall/engine.toml
grep -E '^(dry_run|adapter|ttl_minutes|max_ttl_minutes)' /etc/lurewall/engine.toml
# expect: dry_run = true, adapter = "log-only", ttl_minutes = 5, max_ttl_minutes = 10
# (a repeat block doubles its TTL; the cap stops 20 runs of case 2 blocking the
# test machine B for hours, and still lets case 13 see 5 -> 10)

L=/opt/lurewall/.venv/bin/lurewall
runuser -u lurewall -- $L keygen --key /var/lib/lurewall/keys/lurewall.key
# Prints the PUBLIC key (64 hex). Copy it into your notes: <PUBKEY>. It is not secret.

runuser -u lurewall -- $L lab-site build \
  --state /var/lib/lurewall/canaries.json \
  --out /srv/lurewall/site \
  --checkpoint-file /srv/lurewall/checkpoint/checkpoint.json
runuser -u lurewall -- $L signals check \
  --config /etc/lurewall/signals.toml --state /var/lib/lurewall/canaries.json
```

nginx. The log format file replaces the one from setup step 5b with the
repository's copy (same format and rate limit). Debian's default site also
listens on port 80, so it is unlinked. The file stays in `sites-available`.

```sh
cp /opt/lurewall/deploy/nginx/lurewall-log.conf /etc/nginx/conf.d/lurewall-log.conf
rm /etc/nginx/sites-enabled/default
ln -s /srv/lurewall/site/nginx/lurewall-site.conf /etc/nginx/sites-enabled/lurewall-site.conf
nginx -t && systemctl reload nginx
sleep 2      # reload returns before the old workers stop; checks run too early see the old site
curl -s http://127.0.0.1/ | grep -c 'Lab Tool Library'      # expect a number above 0
curl -sI http://127.0.0.1/lab/fetch-check.html | grep -i x-lab-marker
```

Log rotation by size, checked every 15 minutes. Debian's own
`/etc/logrotate.d/nginx` already rotates `/var/log/nginx/*.log`, which
includes `lurewall.json.log`. A second config naming the same file would make
logrotate refuse it, so this adds `maxsize 100M` to Debian's stanza instead.
Rotation is by rename, which the reader follows.

```sh
cp /etc/logrotate.d/nginx /root/logrotate-nginx.before-pr8
grep -q maxsize /etc/logrotate.d/nginx || \
  sed -i '0,/^\(\s*\)daily$/s//\1daily\n\1maxsize 100M/' /etc/logrotate.d/nginx
cat /etc/logrotate.d/nginx                      # daily, then maxsize 100M
mkdir -p /etc/systemd/system/logrotate.timer.d
cp /opt/lurewall/deploy/logrotate/logrotate.timer.d-lurewall.conf \
   /etc/systemd/system/logrotate.timer.d/lurewall.conf
logrotate -d /etc/logrotate.d/nginx 2>&1 | grep -iE 'error|lurewall' | head -n 5
```

systemd units:

```sh
cp /opt/lurewall/deploy/systemd/lurewall.service \
   /opt/lurewall/deploy/systemd/lurewall-sweeper.service \
   /opt/lurewall/deploy/systemd/lurewall-sweeper.timer /etc/systemd/system/
systemctl daemon-reload
systemctl restart logrotate.timer
systemd-analyze verify /etc/systemd/system/lurewall.service \
  /etc/systemd/system/lurewall-sweeper.service /etc/systemd/system/lurewall-sweeper.timer
```

## Phase 4: close internet access and take a snapshot (lab host)

```sh
sed -i -e 's/^OUT ACCEPT -p udp -dport 53$/|&/' \
       -e 's/^OUT ACCEPT -p tcp -dport 53$/|&/' \
       -e 's/^OUT ACCEPT -p tcp -dport 80$/|&/' \
       -e 's/^OUT ACCEPT -p tcp -dport 443$/|&/' /etc/pve/firewall/<CTID>.fw
pve-firewall compile >/dev/null && echo "rules OK"
pve-firewall status        # repeat until it no longer says pending
cat /etc/pve/firewall/<CTID>.fw      # the four OUT ACCEPT lines start with | again
pct snapshot <CTID> lurewall-installed
```

In the container console, `curl -m 5 -sI https://deb.debian.org` must now fail.

## Phase 5: start in dry-run and anchor checkpoints

Lab container console:

```sh
systemctl enable --now lurewall.service lurewall-sweeper.timer
systemctl status --no-pager lurewall.service | head -n 5
journalctl -u lurewall.service -n 5 --no-pager     # "lurewall is running (dry-run)"
curl -s http://127.0.0.1/lurewall-checkpoint.json; echo
/opt/lurewall/.venv/bin/lurewall status --state /var/lib/lurewall/engine.json
```

Test machine A terminal: install the checkpoint job. It commits to a local repository
only. Pushing to `python1/lurewall-checkpoints` and OpenTimestamps stamping are
the `--push` and `--ots` options, for when you set those up.

```sh
mkdir -p ~/lurewall-lab/checkpoints-repo && cd ~/lurewall-lab/checkpoints-repo && git init -q
echo '<PUBKEY>' > ~/lurewall-lab/pubkey.txt
~/lurewall/.venv/bin/lurewall checkpoint pull \
  --pubkey ~/lurewall-lab/pubkey.txt --repo ~/lurewall-lab/checkpoints-repo
# expect: checkpoint <N>: stored (committed)
sed -e "s|/Users/YOU/|$HOME/|g" -e "s|PUBKEY|$(cat ~/lurewall-lab/pubkey.txt)|" \
  ~/lurewall/deploy/launchd/org.lurewall.checkpoint-pull.plist \
  > ~/Library/LaunchAgents/org.lurewall.checkpoint-pull.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.lurewall.checkpoint-pull.plist
```

Test machine B WSL shell: install the harness.

```sh
git clone https://github.com/python1/lurewall.git ~/lurewall && cd ~/lurewall
git checkout <MAIN_COMMIT> && git submodule update --init
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/lurewall lab list
```

### Recovering after a signed-log rollback

On exit status 3, the service stays stopped. Check the journal with
`journalctl -u lurewall.service -n 20 --no-pager`. Preserve copies of the current
log and checkpoint alongside any independently retained checkpoints before
restoring anything.

If an older backup was restored, find a copy of the log that covers the latest
trusted checkpoint. If a crash with `fsync=False` lost log entries, look for a
surviving copy of those entries. In either case, run
`lurewall verify --log <candidate> --pubkey <key> --anchors <trusted-checkpoints>`
with the published checkpoint and any independent anchors before restoring the
verified log. Keep log fsync enabled, as in the shipped service.

If no copy matches the trusted checkpoints, archive the old chain and document
the evidence gap. Generate a new signing key with `lurewall keygen --key <new-key>`
and configure a separate log, checkpoint destination, and anchor history. Update
the checkpoint pull job to use the new destination and public key.
Once recovery is complete, run `systemctl reset-failed lurewall.service` and
`systemctl start lurewall.service`.

A `startup checkpoint check skipped` warning means the service continued without
that comparison. Check the configured file and verify against a retained checkpoint.

## Phase 6: the test cases

Every run is recorded in a ledger on the machine that ran it
(`~/lurewall-lab/runs.jsonl`). Run `lurewall lab case <N> --from machine-a` on
test machine A, or `--from machine-b` on test machine B. Agent cases need
`--label "<agent> / <model> / <version>"`.

- **Spacing.** Wait at least 2 minutes between runs from the same machine.
  The log rolls up repeats within a minute, and the export assigns events to
  runs by time.
- **Agent cases run 20 times each.** Results are counts: hits out of runs.
- **Reset before every run**, unless the case says otherwise. A counted canary
  hit stays on its source for 7 days, so one case's hit would decide the next
  case from the same machine. A reset clears the engine's state and ends any
  block (startup reconcile removes entries the state no longer knows). Paste
  this once per CT console session, then run `lw_reset` before each run:

  ```sh
  lw_reset() { systemctl stop lurewall.service && rm -f /var/lib/lurewall/engine.json \
    && systemctl start lurewall.service && journalctl -u lurewall.service -n 1 --no-pager; }
  ```

  The signed log keeps everything. A reset only forgets state.

### 6A: dry-run (as installed)

All test machine A cases run here, so no block ever lands on test machine A. Case 20 must run in
this phase. The export checks the log for a `service_started` entry in dry-run
before the run and fails the run if anything else is found.

| Case | Where | Command |
|---|---|---|
| 2 (rehearsal) | Test machine B | `lurewall lab case 2 --scripted --from machine-b` |
| 1 | each agent | `lurewall lab case 1 --from <machine> --label ...` |
| 3 | Test machine B | `lurewall lab case 3 --from machine-b` |
| 4 | Test machine A browser | `lurewall lab case 4 --from machine-a` |
| 5 | Test machine A | `lurewall lab case 5 --from machine-a` |
| 8 | Test machine A | `lurewall lab case 8 --from machine-a` (opens a page on 127.0.0.1:8765) |
| 9 | Test machine B | `lurewall lab case 9 --from machine-b` |
| 10 | Test machine A, then test machine B | `case 10 --part serve --from machine-a`, then `case 10 --part hit --reference <REF> --from machine-b` |
| 12 | Test machine A, then test machine B | `case 12 --part read --from machine-a`, then `case 12 --part probe --from machine-b` |
| 16 | Test machine B | `lurewall lab case 16 --from machine-b` |
| 17 | Test machine B | `lurewall lab case 17 --from machine-b` |
| 18 | Test machine A | set the log-only range first (below), then `lurewall lab case 18 --scripted --from machine-a` |
| 19 | each agent | `lurewall lab case 19 --from <machine> --label ...` |
| 20 | Test machine A, the careful AI agent | `lurewall lab case 20 --from machine-a --label "<agent> / <version>"` |

**Case 18 setting** (lab container console). Undo it after the case:

```sh
sed -i 's|^log_only_ranges = \[\]$|log_only_ranges = ["192.0.2.177/32"]|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
# after case 18:
sed -i 's|^log_only_ranges = \["192.0.2.177/32"\]$|log_only_ranges = []|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
```

**Case 19 markers.** The fetch-check page carries four markers. Record which
ones the agent's answer contains:

- `marker-visible-wren`: page text. Every agent should pass this one.
- `marker-comment-kestrel`: an HTML comment.
- `marker-hidden-heron`: a hidden element.
- `marker-header-plover`: the `X-Lab-Marker` response header.

**Case 20: a careful AI agent from test machine A.**

1. Before the run, in the container console:
   - `grep '^dry_run' /etc/lurewall/engine.toml` must print `dry_run = true`.
   - `journalctl -u lurewall -n 3 --no-pager` must show `(dry-run)`.
2. In the agent's app, set its permission mode to **Ask every time**.
3. On test machine A, run `lurewall lab case 20 --from machine-a --label "<agent> / <version>"`.
4. Give the agent the prompt the command prints.
5. Approve or decline each request the agent asks to send.
6. At the end, note in one line how many requests you approved and how many you declined.

Test machine A is your browsing address, which is why this case is dry-run only.
Even when enforcing, a block in the lab container drops only test machine A's traffic to the lab container,
not to anywhere else.

### 6B: enforcing with nftables (test machine B only)

Run this only if Phase 2's `test_nft.py` passed in the container. Lab container console:

```sh
sed -i -e 's/^dry_run = true$/dry_run = false/' \
       -e 's/^adapter = "log-only"$/adapter = "nftables"/' /etc/lurewall/engine.toml
grep -E '^(dry_run|adapter|ttl_minutes)' /etc/lurewall/engine.toml
systemctl restart lurewall.service
journalctl -u lurewall.service -n 3 --no-pager      # "ENFORCING with nftables"
```

| Case | Where | Command |
|---|---|---|
| 2 (proof) | Test machine B | `lurewall lab case 2 --scripted --from machine-b --label "6B proof / scripted"`: the block lands, cuts test machine B off, and expires after `ttl_minutes` |
| 2 (agent) | none | not run (WSL network issue); enforcement proven by the scripted run |
| 15 | Test machine A | `lurewall lab case 15 --from machine-a` |
| 11 | Test machine A | `lurewall lab case 11 --from machine-a` (waits 16 minutes) |
| 13 | Test machine A (Chrome + harness, one address) | while case 11's block stands: `lurewall lab case 13 --watch --from machine-a` |
| 7 | Test machine A | set the allowlist to test machine A first, then `lurewall lab case 7 --from machine-a` |
| 14 | Lab container + test machine A | the steps below, with `--from machine-a` |

Watch a block land and end (lab container console):

```sh
nft list set inet lurewall blocked4
/opt/lurewall/.venv/bin/lurewall status --state /var/lib/lurewall/engine.json
```

**Case 7 setting.** Undo it after the case:

```sh
sed -i 's|^allowlist = \[\]$|allowlist = ["192.0.2.152"]|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
# after case 7:
sed -i 's|^allowlist = \["192.0.2.152"\]$|allowlist = []|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
```

Cases 13 and 14 depend on state from the run before them: no `lw_reset`
inside either case.

**Case 14: process failure.**

1. Run case 2 from test machine B until the block lands.
2. In the container console, run:

   ```sh
   systemctl stop lurewall.service
   nft list set inet lurewall blocked4          # the entry and its expiry comment
   ```

3. Wait until the expiry time has passed, plus up to 60 seconds. Then check:

   ```sh
   nft list set inet lurewall blocked4          # empty: the kernel timeout or the sweeper ended it
   journalctl -u lurewall-sweeper.service -n 5 --no-pager
   ```

4. With the service still stopped, on test machine B, run
   `lurewall lab case 14 --part backlog --from machine-b`.
5. Wait 6 minutes, so those log lines are stale.
6. In the container console, run `systemctl start lurewall.service`, then
   `nft list set inet lurewall blocked4`. It must stay empty.

When 6B is done, go back to dry-run:

```sh
sed -i -e 's/^dry_run = false$/dry_run = true/' \
       -e 's/^adapter = "nftables"$/adapter = "log-only"/' /etc/lurewall/engine.toml
systemctl restart lurewall.service
```

## Phase 7: case 6, the tamper test (test machine A, on a copy)

After Phase 8's copy, run this on the copy, never on the container's log:

```sh
lurewall lab tamper --log ~/lurewall-lab/export/events.log --pubkey ~/lurewall-lab/pubkey.txt \
  --anchors ~/lurewall-lab/checkpoints-repo/checkpoints --work ~/lurewall-lab/tamper
```

## Phase 8: export and results

Lab host:

```sh
mkdir -p /root/lurewall-export
pct pull <CTID> /var/lib/lurewall/events.log /root/lurewall-export/events.log
pct pull <CTID> /var/lib/lurewall/sweeper.log /root/lurewall-export/sweeper.log
sha256sum /root/lurewall-export/*.log
```

Copy both files to test machine A with `scp root@192.0.2.170:/root/lurewall-export/*.log
~/lurewall-lab/export/` if Phase 0.3 showed ssh works. Copy test machine B's
ledger to test machine A as `~/lurewall-lab/machine-b-runs.jsonl`. Then, on test machine A:

```sh
lurewall verify --log ~/lurewall-lab/export/events.log --pubkey ~/lurewall-lab/pubkey.txt \
  --anchors ~/lurewall-lab/checkpoints-repo/checkpoints
lurewall verify --log ~/lurewall-lab/export/sweeper.log --pubkey ~/lurewall-lab/pubkey.txt
lurewall lab results --log ~/lurewall-lab/export/events.log --pubkey ~/lurewall-lab/pubkey.txt \
  --anchors ~/lurewall-lab/checkpoints-repo/checkpoints \
  --ledger ~/lurewall-lab/runs.jsonl --ledger ~/lurewall-lab/machine-b-runs.jsonl \
  --out ~/lurewall-lab/results
```

`results.md` and `results.csv` list every run with a verdict:

- **pass / fail:** checked against the log.
- **record:** you judge it (cases 5, 13, 16, 19 and the halves of 10 and 12 that do nothing).
- **known limit:** case 12.

Every string from the log or a ledger is escaped in both files.

## v2 quiet canaries (not yet run)

v1's twenty cases are done. A v2 lab round would follow
[v2-build-spec.md](v2-build-spec.md), section 5. In short:

- **Upgrade.** Rerun `lurewall lab-site build` with the same `--state` file.
  It adds canaries B, A and C, prints `added the v2 quiet canaries (B, A, C)`,
  and leaves the v1 canaries unchanged. Then redeploy the site and the nginx
  block as in Phase 3. `lurewall canaries list` shows each canary's family and
  signal. Never paste its output anywhere.
- **Who runs it.** The agent that helped design the quiet canaries is not a
  test agent. Someone else generates the tokens, and the test agents get only
  the task prompt.
- **Rotate between agents.** Rotate with `lurewall canaries rotate --state
  <STATE> --id <canary id>`, or `--all`, then rebuild and redeploy. A retired
  path is an ordinary 404 and counts for nothing.
- **Controls expect zero blocks:** browsing from test machine A, VoiceOver, lynx, a
  robots.txt-respecting crawler and a security.txt reader. A security.txt
  reader that follows C is logged `research_log_only`, and that is a pass. A
  scanner that follows A and then probes can be blocked, because A is a
  `recon` signal. Record that as recon, never as an AI catch.
- **Per run, record:** the canary family and ID taken, the signal, whether
  there was a probe burst, the decision, and whether the agent called the
  canary suspicious. `lab results` reports hits per family and signal.

## Teardown

As in the design doc, after the results are exported: on the lab host,
`pct stop <CTID> && pct destroy <CTID> --purge` and remove `/etc/pve/firewall/<CTID>.fw`.
On test machine A, `launchctl bootout gui/$(id -u)/org.lurewall.checkpoint-pull`.

## Case 21 · Possible IP switch

Use two distinct client source keys, a dedicated natural test vhost, an
eligible footer and the lab signals fixture. Use a fresh observe-only lab
with no previous counted hits for B. Both requests go to the same private
lab target. On A run `lurewall lab case 21 --from machine-a --part read`.
Transfer the footer reference privately. On B run
`lurewall lab case 21 --from machine-b --part probe` and enter A's source
and the reference at the prompts. Set `--target` on both invocations to the
lab's actual private origin. The harness requests two inert paths that are
configured as distinct signals only in the lab.

Collect the ledgers and verified event log as for the other cases. The probe
half passes only when the signed relay has A as issuer and B as requester,
both fixture probes appear for B, and B has no counted hit, would-block or
block. Inspect either endpoint with `explain-decision` and the time window
with `report`. Do not publish the reference, addresses or private ledgers.
