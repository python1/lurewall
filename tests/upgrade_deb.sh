#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Released v0.3.0 package -> this build -> identity on -> broken identity config ->
# rollback to v0.3.0, on a disposable systemd runner. Runs as root.
set -euo pipefail

if [[ $# != 2 || $EUID != 0 ]]; then
    echo "usage: upgrade_deb.sh RELEASED_V030_DEB NEW_ARTIFACT_DIR" >&2
    exit 2
fi
if dpkg-query --show lurewall >/dev/null 2>&1 || [[ -e /etc/lurewall || -e /var/lib/lurewall ]]; then
    echo "The upgrade test requires a fresh runner." >&2
    exit 1
fi
old=$(realpath -- "$1")
shopt -s nullglob
packages=("$2"/lurewall_*_all.deb)
(( ${#packages[@]} == 1 )) || { echo "Expected exactly one new package." >&2; exit 1; }
new=$(realpath -- "${packages[0]}")
[[ $(dpkg-deb --field "$old" Version) == 0.3.0* ]]
[[ $(dpkg-deb --field "$new" Version) == 0.4.0* ]]

site=/etc/nginx/conf.d/lurewall-upgrade-ci.conf
format=/etc/lurewall/nginx/operator-format.conf
engine=/etc/lurewall/engine.toml
agents=/etc/lurewall/agents.toml
log=/var/lib/lurewall/events.log
key=/var/lib/lurewall/keys/lurewall.key
checkpoint=/srv/lurewall/checkpoint/checkpoint.json
metrics=/var/lib/lurewall/telemetry/lurewall.prom
scratch=$(mktemp -d)
cleanup() {
    local status=$?
    if [[ $status != 0 ]]; then
        journalctl -u lurewall.service -u lurewall-fetch.service -n 60 --no-pager || true
    fi
    rm -f -- "$site"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
    rm -rf -- "$scratch"
    exit "$status"
}
trap cleanup EXIT

install_package() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
        -o Dpkg::Options::=--force-confold "$1"
}
as_detector() { runuser -u lurewall -- /usr/bin/lurewall "$@"; }
visit() {
    curl --fail --silent --show-error --noproxy '*' --retry 5 --retry-connrefused \
        -A "$1" --resolve lurewall-upgrade.example:18619:127.0.0.1 \
        http://lurewall-upgrade.example:18619/ >/dev/null
}
metric() { awk -v m="$1" '$1 == m {print $2}' "$metrics" 2>/dev/null || true; }
wait_metric_above() { # name floor
    for _ in {1..30}; do
        local value
        value=$(metric "$1")
        if [[ -n $value ]] && (( value > $2 )); then return 0; fi
        sleep 1
    done
    echo "metric $1 did not rise above $2 (now: $(metric "$1"))" >&2
    return 1
}
verify_chain() {
    as_detector verify --log "$log" --pubkey "$public_key" --anchors "$checkpoint"
}

echo "== released v0.3.0"
install_package "$old"
systemctl is-active --quiet lurewall.service
cat > "$site" <<'NGINX'
include /etc/lurewall/nginx/operator-format.conf;
server {
    listen 127.0.0.1:18619;
    server_name lurewall-upgrade.example;
    access_log /var/log/lurewall/access.jsonl lurewall_operator;
    location / { return 204; }
}
NGINX
nginx -t
systemctl start nginx
systemctl reload nginx
visit "v030-visitor"
wait_metric_above lurewall_records_processed_total 0
public_key=$(as_detector pubkey --key "$key")
verify_chain
# Local operator edits that dpkg must keep across the upgrade.
printf '\n# local operator note\n' >> "$format"
printf '\n# local operator note\n' >> "$engine"
cp -- "$format" "$scratch/format.v030"
cp -- "$engine" "$scratch/engine"
cp -- "$log" "$scratch/event-prefix"
prefix=$(wc -c < "$scratch/event-prefix")

echo "== upgrade to this build"
install_package "$new"
[[ $(dpkg-query --show --showformat '${Version}' lurewall) == 0.4.0* ]]
systemctl is-active --quiet lurewall.service
cmp -- "$format" "$scratch/format.v030"
cmp -- "$engine" "$scratch/engine"
cmp -n "$prefix" -- "$scratch/event-prefix" "$log"
[[ $(as_detector pubkey --key "$key") == "$public_key" ]]
test -s /etc/lurewall/nginx/operator-format-v4.conf
test -s /etc/lurewall/agents.example.toml
test ! -e "$agents"
[[ $(getent passwd lurewall-fetch | cut -d: -f7) == /usr/sbin/nologin ]]
if systemctl is-enabled --quiet lurewall-fetch.timer; then
    echo "The fetch timer must be opt-in." >&2
    exit 1
fi
records=$(metric lurewall_records_processed_total)
visit "v04-before-switch"
wait_metric_above lurewall_records_processed_total "${records:-0}"
verify_chain

echo "== switch nginx to the v4 format (operator guide step 1)"
cp -- "$format" "$format.pre-v4"
cp -- /etc/lurewall/nginx/operator-format-v4.conf "$format"
nginx -t
systemctl reload nginx
records=$(metric lurewall_records_processed_total)
failures=$(metric lurewall_access_log_parse_failures_total)
visit "v4-visitor"
wait_metric_above lurewall_records_processed_total "$records"
[[ $(metric lurewall_access_log_parse_failures_total) == "$failures" ]]

echo "== identity on, without restarting the reader (steps 2-3)"
cat > "$agents" <<'TOML'
visible_authorities = ["lurewall-upgrade.example:18619"]
[feed.common-crawlers]
url = "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"
coverage = "authoritative"
[feed.gptbot]
url = "https://openai.com/gptbot.json"
coverage = "authoritative"
[claim.Googlebot]
ranges = "common-crawlers"
[claim.GPTBot]
ranges = "gptbot"
TOML
chmod 0644 "$agents"
lurewall agent-check --config "$agents" 2> "$scratch/check.err"
grep -q "feed gptbot: only Google's published crawler ranges can be authoritative" "$scratch/check.err"
lurewall agent-replay-init
[[ $(stat -c %U /var/lib/lurewall/agent-replay.sqlite) == lurewall ]]
systemctl enable --now lurewall-fetch.timer
systemctl start lurewall-fetch.service
[[ $(systemctl show -p Result --value lurewall-fetch.service) == success ]]
python3 - <<'PY'
import base64, json
from pathlib import Path
for name in ("common-crawlers", "gptbot"):
    snap = json.loads(Path(f"/var/cache/lurewall-fetch/{name}.json").read_text())
    body = json.loads(base64.b64decode(snap["body"]))
    assert len(body["prefixes"]) > 0, name
    assert 900 <= snap["refresh"] - snap["fetched"] <= 2700, snap
PY
[[ $(stat -c %U /var/cache/lurewall-fetch/common-crawlers.json) == lurewall-fetch ]]
# The unit that just succeeded ran with these effective sandbox settings.
systemctl show -p InaccessiblePaths --value lurewall-fetch.service | grep -c /var/lib/lurewall >/dev/null
[[ $(systemctl show -p MemoryDenyWriteExecute --value lurewall-fetch.service) == yes ]]
[[ $(systemctl show -p User --value lurewall-fetch.service) == lurewall-fetch ]]
systemd-analyze security --no-pager lurewall-fetch.service | tail -1
sleep 6 # the reader looks at agents.toml at most every five seconds
identity=$(metric lurewall_agent_indeterminate_total)
visit "Mozilla/5.0 (compatible; Googlebot/2.1)"
# Plain-HTTP fixture: the claim is judged and must stay indeterminate (unconfirmed ingress).
wait_metric_above lurewall_agent_indeterminate_total "${identity:-0}"
[[ $(metric lurewall_agent_impersonation_total) == 0 ]]
journalctl -u lurewall.service --no-pager | grep -c "treating it as partial" >/dev/null

echo "== a broken agents.toml never stops the detector (H1)"
printf 'this is [not toml\n' >> "$agents"
sleep 6
records=$(metric lurewall_records_processed_total)
visit "after-broken-config"
wait_metric_above lurewall_records_processed_total "$records"
systemctl is-active --quiet lurewall.service
journalctl -u lurewall.service --no-pager | grep -c "agent identity configuration not applied" >/dev/null
systemctl restart lurewall.service # a restart with the broken file must also come up
systemctl is-active --quiet lurewall.service
lurewall agent-check --config "$agents" && { echo "agent-check accepted a broken file" >&2; exit 1; }
verify_chain

echo "== roll back to v0.3.0 (operator guide)"
cp -- "$format.pre-v4" "$format"
nginx -t
systemctl reload nginx
visit "legacy-after-restore"
sleep 3
python3 - <<'PY'
import json
from pathlib import Path
log = Path("/var/log/lurewall/access.jsonl")
cursor = json.loads(Path("/var/lib/lurewall/reader.state").read_text())
assert cursor["inode"] == log.stat().st_ino and cursor["offset"] == log.stat().st_size, cursor
PY
systemctl disable --now lurewall-fetch.timer
systemctl stop lurewall-fetch.service
install_package "$old"
[[ $(dpkg-query --show --showformat '${Version}' lurewall) == 0.3.0* ]]
systemctl is-active --quiet lurewall.service
cmp -- "$format" "$scratch/format.v030"
offset=$(python3 -c 'import json; print(json.load(open("/var/lib/lurewall/reader.state"))["offset"])')
visit "v030-after-rollback"
for _ in {1..30}; do
    now=$(python3 -c 'import json; print(json.load(open("/var/lib/lurewall/reader.state"))["offset"])')
    (( now > offset )) && break
    sleep 1
done
(( now > offset ))
[[ $(as_detector pubkey --key "$key") == "$public_key" ]]
cmp -n "$prefix" -- "$scratch/event-prefix" "$log"
verify_chain
echo "upgrade and rollback: ok"
