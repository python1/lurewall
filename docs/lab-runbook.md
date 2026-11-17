# Lurewall lab runbook (CT 110)

How to install Lurewall in the lab container, run the twenty test cases and
export results that verify against the anchored checkpoints.

Each block names the machine it runs on. Nothing here touches CT 102 or any
other guest. Values in `<ANGLE_BRACKETS>` come from an earlier step. Never
guess them. Lurewall stays in dry-run until Phase 6 says otherwise.

| Machine | Address | How to get a shell |
|---|---|---|
| pve host | 192.168.1.170 | Proxmox web UI → pve → Shell |
| CT 110 (lurewall-lab) | 192.168.1.160 | `pct enter 110` from the pve shell |
| Mac | 192.168.1.177 | Terminal |
| Alienware | 192.168.1.152 | WSL Ubuntu shell (requests leave as the Windows LAN address) |

## Debian 13 (trixie), not 12

CT 110 runs Debian 13. The design doc assumed Debian 12. What changes:

| Package | Debian 12 | Debian 13 | Checked how |
|---|---|---|---|
| nftables | 1.0.6 | 1.1.3 | CI job `debian13` runs the real-nft tests on trixie's own package |
| nginx | 1.22 | 1.26.3 | same job: the nginx and lab end-to-end tests |
| Python | 3.11 | 3.13.5 | same job |
| systemd | 252 | 257 | not tested in CI; the units are checked by `systemd-analyze verify` in Phase 3 |

The CT uses the pve host's kernel, not Debian's. CI runs on the GitHub
runner's kernel, so Phase 2 runs the real-nft tests inside CT 110 itself.

---

## Phase 0: read-only checks

Nothing in this phase changes anything. Send me the output of each step
before going on.

### 0.1 pve host shell

```sh
pveversion
uname -r
pct status 110
pct config 110
pct listsnapshot 110
cat /etc/pve/firewall/110.fw 2>/dev/null || echo "no 110.fw"
cat /etc/pve/firewall/cluster.fw 2>/dev/null || echo "no cluster.fw"
pve-firewall status
# Guests with firewall=1 on a NIC. Only CT 110 should be listed.
grep -H 'firewall=1' /etc/pve/lxc/*.conf /etc/pve/qemu-server/*.conf 2>/dev/null \
  || echo "no NIC has firewall=1"
```

Stop and send me the output if any of these is true:

- `pct config 110` shows `unprivileged: 0`, `nesting=1` or a bind mount (`mp0:`).
- 110.fw is missing, or allows inbound from anything but .177 and .152 on port 80.
- Any guest other than 110 has `firewall=1` (above all CT 102).
- There is no snapshot to roll back to.

### 0.2 CT 110 console (`pct enter 110`)

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
curl -m 5 -sk https://192.168.1.170:8006 >/dev/null && echo "LEAK: pve reachable" || echo "pve blocked"
curl -m 5 -sI https://deb.debian.org >/dev/null && echo "internet OPEN" || echo "internet blocked"
```

Stop and send me the output if any of these is true:

- `VERSION_ID` is not 13, or `nft`, `nginx` or `python3` is missing.
- The `grep` for `with-http_sub_module` prints nothing.
- pve is reachable from the CT.
- The root disk has less than 4 GB free.

### 0.3 Mac Terminal

```sh
ipconfig getifaddr en0; ipconfig getifaddr en1   # one of these should be 192.168.1.177
curl -sI http://192.168.1.160/ | head -n 3
cd ~/python1/lurewall && git status -sb && .venv/bin/lurewall --version
ssh -o BatchMode=yes -o ConnectTimeout=5 root@192.168.1.170 true && echo "ssh to pve: ok" \
  || echo "ssh to pve: not set up"
```

The ssh line only tells us whether Phase 8 can copy the log with `scp`. If it
says "not set up", leave it. There is another way.

### 0.4 Alienware, WSL shell

```sh
python3 --version          # 3.11 or newer
curl -sI http://192.168.1.160/ | head -n 3
```

---

## Phase 1: open internet access for setup (pve host)

The CT has no internet. Re-enable the four outbound rules that setup step 6 of
the design doc disabled (a leading `|` disables a rule):

```sh
cp /etc/pve/firewall/110.fw /root/110.fw.before-pr8
sed -i -e 's/^|\(OUT ACCEPT -p udp -dport 53\)$/\1/' \
       -e 's/^|\(OUT ACCEPT -p tcp -dport 53\)$/\1/' \
       -e 's/^|\(OUT ACCEPT -p tcp -dport 80\)$/\1/' \
       -e 's/^|\(OUT ACCEPT -p tcp -dport 443\)$/\1/' /etc/pve/firewall/110.fw
pve-firewall compile >/dev/null && echo "rules OK"
cat /etc/pve/firewall/110.fw
```

`OUT DROP -dest 192.168.1.0/24` stays first, so the LAN stays unreachable.
Phase 4 closes the internet again.

## Phase 2: install Lurewall (CT 110 console)

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

Then the self-checks, on this CT's own kernel and Debian 13's packages. They
start a private nginx on a loopback port and create and delete the table
`inet lurewall` in the CT's own network namespace. Nothing else is touched,
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

## Phase 3: configure (CT 110 console)

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
# Alienware for hours, and still lets case 13 see 5 -> 10)

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

## Phase 4: close internet access and take a snapshot (pve host)

```sh
cp /root/110.fw.before-pr8 /etc/pve/firewall/110.fw
pve-firewall compile >/dev/null && echo "rules OK"
cat /etc/pve/firewall/110.fw      # the four OUT ACCEPT lines start with | again
pct snapshot 110 lurewall-installed
```

In the CT console, `curl -m 5 -sI https://deb.debian.org` must now fail.

## Phase 5: start in dry-run and anchor checkpoints

CT 110 console:

```sh
systemctl enable --now lurewall.service lurewall-sweeper.timer
systemctl status --no-pager lurewall.service | head -n 5
journalctl -u lurewall.service -n 5 --no-pager     # "lurewall is running (dry-run)"
curl -s http://127.0.0.1/lurewall-checkpoint.json; echo
/opt/lurewall/.venv/bin/lurewall status --state /var/lib/lurewall/engine.json
```

Mac Terminal: install the checkpoint job. It commits to a local repository
only. Pushing to `python1/lurewall-checkpoints` and OpenTimestamps stamping are
the `--push` and `--ots` options, for when you set those up.

```sh
mkdir -p ~/lurewall-lab/checkpoints-repo && cd ~/lurewall-lab/checkpoints-repo && git init -q
echo '<PUBKEY>' > ~/lurewall-lab/pubkey.txt
~/python1/lurewall/.venv/bin/lurewall checkpoint pull \
  --pubkey ~/lurewall-lab/pubkey.txt --repo ~/lurewall-lab/checkpoints-repo
# expect: checkpoint <N>: stored (committed)
sed -e "s|/Users/YOU/|$HOME/|g" -e "s|PUBKEY|$(cat ~/lurewall-lab/pubkey.txt)|" \
  ~/python1/lurewall/deploy/mac/org.lurewall.checkpoint-pull.plist \
  > ~/Library/LaunchAgents/org.lurewall.checkpoint-pull.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.lurewall.checkpoint-pull.plist
```

Alienware WSL shell: install the harness.

```sh
git clone https://github.com/python1/lurewall.git ~/lurewall && cd ~/lurewall
git checkout <MAIN_COMMIT> && git submodule update --init
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/lurewall lab list
```

## Phase 6: the test cases

Every run is recorded in a ledger on the machine that ran it
(`~/lurewall-lab/runs.jsonl`). Run `lurewall lab case <N> --from mac` on the
Mac, or `--from alienware` on the Alienware. Agent cases need
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

All Mac cases run here, so no block ever lands on the Mac. Case 20 must run in
this phase. The export checks the log for a `service_started` entry in dry-run
before the run and fails the run if anything else is found.

| Case | Where | Command |
|---|---|---|
| 2 (rehearsal) | Alienware | `lurewall lab case 2 --scripted --from alienware` |
| 1 | each agent | `lurewall lab case 1 --from <machine> --label ...` |
| 3 | Alienware | `lurewall lab case 3 --from alienware` |
| 4 | Mac browser | `lurewall lab case 4 --from mac` |
| 5 | Mac | `lurewall lab case 5 --from mac` |
| 8 | Mac | `lurewall lab case 8 --from mac` (opens a page on 127.0.0.1:8765) |
| 9 | Alienware | `lurewall lab case 9 --from alienware` |
| 10 | Mac, then Alienware | `case 10 --part serve --from mac`, then `case 10 --part hit --reference <REF> --from alienware` |
| 12 | Mac, then Alienware | `case 12 --part read --from mac`, then `case 12 --part probe --from alienware` |
| 16 | Alienware | `lurewall lab case 16 --from alienware` |
| 17 | Alienware | `lurewall lab case 17 --from alienware` |
| 18 | Mac | set the log-only range first (below), then `lurewall lab case 18 --scripted --from mac` |
| 19 | each agent | `lurewall lab case 19 --from <machine> --label ...` |
| 20 | Mac, Warden | `lurewall lab case 20 --from mac --label "Warden / Grok / <version>"` |

**Case 18 setting** (CT 110 console). Undo it after the case:

```sh
sed -i 's|^log_only_ranges = \[\]$|log_only_ranges = ["192.168.1.177/32"]|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
# after case 18:
sed -i 's|^log_only_ranges = \["192.168.1.177/32"\]$|log_only_ranges = []|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
```

**Case 19 markers.** The fetch-check page carries four markers. Record which
ones the agent's answer contains:

- `marker-visible-wren`: page text. Every agent should pass this one.
- `marker-comment-kestrel`: an HTML comment.
- `marker-hidden-heron`: a hidden element.
- `marker-header-plover`: the `X-Lab-Marker` response header.

**Case 20: Warden from the Mac.**

1. Before the run, in the CT console:
   - `grep '^dry_run' /etc/lurewall/engine.toml` must print `dry_run = true`.
   - `journalctl -u lurewall -n 3 --no-pager` must show `(dry-run)`.
2. In Knights Circle, set Warden's permission mode to **Ask every time**.
3. On the Mac, run `lurewall lab case 20 --from mac --label "Warden / Grok / <version>"`.
4. Give Warden the prompt the command prints.
5. Approve or decline each request Warden asks to send.
6. At the end, note in one line how many requests you approved and how many you declined.

The Mac is your browsing address, which is why this case is dry-run only.
Even when enforcing, a block in CT 110 drops only the Mac's traffic to CT 110,
not to anywhere else.

### 6B: enforcing with nftables (Alienware only)

Run this only if Phase 2's `test_nft.py` passed in the CT. CT 110 console:

```sh
sed -i -e 's/^dry_run = true$/dry_run = false/' \
       -e 's/^adapter = "log-only"$/adapter = "nftables"/' /etc/lurewall/engine.toml
grep -E '^(dry_run|adapter|ttl_minutes)' /etc/lurewall/engine.toml
systemctl restart lurewall.service
journalctl -u lurewall.service -n 3 --no-pager      # "ENFORCING with nftables"
```

| Case | Where | Command |
|---|---|---|
| 2 | Hermes on the Alienware | `lurewall lab case 2 --from alienware --label ...`, 20 runs, 10 minutes apart |
| 11 | Alienware | `lurewall lab case 11 --from alienware` (waits 16 minutes) |
| 13 | Alienware (Windows browser) | after a case 2 block: `lurewall lab case 13 --watch --from alienware` |
| 15 | Alienware | `lurewall lab case 15 --from alienware` |
| 7 | Alienware | set the allowlist first (below), then `lurewall lab case 7 --from alienware` |
| 14 | CT 110 + Alienware | the steps below |

Watch a block land and end (CT 110 console):

```sh
nft list set inet lurewall blocked4
/opt/lurewall/.venv/bin/lurewall status --state /var/lib/lurewall/engine.json
```

**Case 7 setting.** Undo it after the case:

```sh
sed -i 's|^allowlist = \[\]$|allowlist = ["192.168.1.152"]|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
# after case 7:
sed -i 's|^allowlist = \["192.168.1.152"\]$|allowlist = []|' /etc/lurewall/engine.toml
systemctl restart lurewall.service
```

Cases 13 and 14 depend on state from the run before them: no `lw_reset`
inside either case.

**Case 14: process failure.**

1. Run case 2 from the Alienware until the block lands.
2. In the CT console, run:

   ```sh
   systemctl stop lurewall.service
   nft list set inet lurewall blocked4          # the entry and its expiry comment
   ```

3. Wait until the expiry time has passed, plus up to 60 seconds. Then check:

   ```sh
   nft list set inet lurewall blocked4          # empty: the kernel timeout or the sweeper ended it
   journalctl -u lurewall-sweeper.service -n 5 --no-pager
   ```

4. With the service still stopped, on the Alienware, run
   `lurewall lab case 14 --part backlog --from alienware`.
5. Wait 6 minutes, so those log lines are stale.
6. In the CT console, run `systemctl start lurewall.service`, then
   `nft list set inet lurewall blocked4`. It must stay empty.

When 6B is done, go back to dry-run:

```sh
sed -i -e 's/^dry_run = false$/dry_run = true/' \
       -e 's/^adapter = "nftables"$/adapter = "log-only"/' /etc/lurewall/engine.toml
systemctl restart lurewall.service
```

## Phase 7: case 6, the tamper test (Mac, on a copy)

After Phase 8's copy, run this on the copy, never on the CT's log:

```sh
lurewall lab tamper --log ~/lurewall-lab/export/events.log --pubkey ~/lurewall-lab/pubkey.txt \
  --anchors ~/lurewall-lab/checkpoints-repo/checkpoints --work ~/lurewall-lab/tamper
```

## Phase 8: export and results

pve host:

```sh
mkdir -p /root/lurewall-export
pct pull 110 /var/lib/lurewall/events.log /root/lurewall-export/events.log
pct pull 110 /var/lib/lurewall/sweeper.log /root/lurewall-export/sweeper.log
sha256sum /root/lurewall-export/*.log
```

Copy both files to the Mac with `scp root@192.168.1.170:/root/lurewall-export/*.log
~/lurewall-lab/export/` if Phase 0.3 showed ssh works. Copy the Alienware's
ledger to the Mac as `~/lurewall-lab/alienware-runs.jsonl`. Then, on the Mac:

```sh
lurewall verify --log ~/lurewall-lab/export/events.log --pubkey ~/lurewall-lab/pubkey.txt \
  --anchors ~/lurewall-lab/checkpoints-repo/checkpoints
lurewall verify --log ~/lurewall-lab/export/sweeper.log --pubkey ~/lurewall-lab/pubkey.txt
lurewall lab results --log ~/lurewall-lab/export/events.log --pubkey ~/lurewall-lab/pubkey.txt \
  --anchors ~/lurewall-lab/checkpoints-repo/checkpoints \
  --ledger ~/lurewall-lab/runs.jsonl --ledger ~/lurewall-lab/alienware-runs.jsonl \
  --out ~/lurewall-lab/results
```

`results.md` and `results.csv` list every run with a verdict:

- **pass / fail:** checked against the log.
- **record:** you judge it (cases 5, 13, 16, 19 and the halves of 10 and 12 that do nothing).
- **known limit:** case 12.

Every string from the log or a ledger is escaped in both files.

## Teardown

As in the design doc, after the results are exported: on the pve host,
`pct stop 110 && pct destroy 110 --purge` and remove `/etc/pve/firewall/110.fw`.
On the Mac, `launchctl bootout gui/$(id -u)/org.lurewall.checkpoint-pull`.
