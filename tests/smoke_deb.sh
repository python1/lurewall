#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Runs as root inside fresh, disposable Linux CI fixtures.
set -euo pipefail

if [[ $# != 3 || $EUID != 0 || ! $2 =~ ^[a-f0-9]{40}$ || ! $3 =~ ^(systemd|container)$ ]]; then
    echo "usage: smoke_deb.sh ARTIFACT_DIR SOURCE_COMMIT systemd|container" >&2
    exit 2
fi
if dpkg-query --show lurewall >/dev/null 2>&1 || [[ -e /etc/lurewall || -e /var/lib/lurewall ]]; then
    echo "The package smoke test requires a fresh runner." >&2
    exit 1
fi

artifact_dir=$1
source_commit=$2
mode=$3
shopt -s nullglob
packages=("$artifact_dir"/lurewall_*_all.deb)
if (( ${#packages[@]} != 1 )); then
    echo "Expected exactly one canonical Lurewall package." >&2
    exit 1
fi
package=$(realpath -- "${packages[0]}")
[[ $(dpkg-deb --field "$package" Package) == lurewall ]]
[[ $(dpkg-deb --field "$package" Architecture) == all ]]
sha256sum "$package"

nginx_fixture=/etc/nginx/conf.d/lurewall-package-ci.conf
if [[ -e $nginx_fixture || -L $nginx_fixture ]]; then
    echo "The smoke test's nginx fixture already exists." >&2
    exit 1
fi
scratch=$(mktemp -d)
detach_nginx() {
    if [[ -e $nginx_fixture ]]; then
        rm -- "$nginx_fixture"
        nginx -t && systemctl reload nginx
    fi
}
cleanup() {
    local status=$?
    detach_nginx || status=1
    rm -rf -- "$scratch"
    exit "$status"
}
trap cleanup EXIT

as_detector() {
    runuser -u lurewall -- /usr/bin/lurewall "$@"
}

log=/var/lib/lurewall/events.log
key=/var/lib/lurewall/keys/lurewall.key
checkpoint=/srv/lurewall/checkpoint/checkpoint.json
engine=/etc/lurewall/engine.toml

assert_observer() {
    /usr/bin/python3 - "$engine" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    config = tomllib.load(stream)
assert config.get("dry_run") is True
assert config["enforcement"]["adapter"] == "log-only"
PY
    nft -j list tables | /usr/bin/python3 -c '
import json, sys
assert all(entry.get("table", {}).get("name") != "lurewall"
           for entry in json.load(sys.stdin)["nftables"])
'
}

run_service_once() {
    # Exercise the installed ExecStart in Debian's container without PID 1.
    /usr/bin/python3 - <<'PY'
from pathlib import Path
from shlex import split
from subprocess import run

unit = Path("/usr/lib/systemd/system/lurewall.service").read_text()
line = next(line for line in unit.replace("\\\n", " ").splitlines()
            if line.startswith("ExecStart="))
argv = split(line.removeprefix("ExecStart="))
assert argv[:2] == ["/usr/bin/lurewall", "run"]
run(["/usr/sbin/runuser", "-u", "lurewall", "--", *argv, "--once"], check=True)
PY
}

verify_evidence() {
    as_detector verify --log "$log" --pubkey "$public_key" --anchors "$checkpoint"
}

apt-get install -y --no-install-recommends "$package"
[[ $(cat /usr/share/doc/lurewall/source-commit) == "$source_commit" ]]
[[ $(stat -c %a "$key") == 600 ]]
[[ $(stat -c %U "$key") == lurewall ]]
assert_observer

if [[ $mode == systemd ]]; then
    systemctl is-active --quiet lurewall.service
    for timer in lurewall-sweeper.timer lurewall-notify.timer; do
        if systemctl is-active --quiet "$timer"; then
            echo "An optional timer is unexpectedly active ($timer)." >&2
            exit 1
        fi
    done
    cat > "$nginx_fixture" <<'NGINX'
include /etc/lurewall/nginx/operator-format.conf;
server {
    listen 127.0.0.1:18519;
    server_name lurewall-package.example;
    access_log /var/log/lurewall/access.jsonl lurewall_operator;
    location / { return 204; }
}
NGINX
    nginx -t
    systemctl start nginx
    systemctl reload nginx
    curl --fail --silent --show-error --noproxy '*' --retry 5 --retry-connrefused \
        --resolve lurewall-package.example:18519:127.0.0.1 http://lurewall-package.example:18519/ >/dev/null
    metrics=/var/lib/lurewall/telemetry/lurewall.prom
    for _ in {1..25}; do
        if grep -Eq '^lurewall_records_processed_total [1-9][0-9]*$' "$metrics"; then
            break
        fi
        sleep 1
    done
    grep -Eq '^lurewall_records_processed_total [1-9][0-9]*$' "$metrics"
else
    run_service_once
fi

public_key=$(as_detector pubkey --key "$key")
verify_evidence
/usr/bin/lurewall doctor --json | /usr/bin/python3 -c '
import json, sys
checks = {entry["name"]: entry for entry in json.load(sys.stdin)}
assert checks["permissions"]["level"] == "pass", checks
# The installed launcher drops root. Its nft query cannot inspect the table
# whose absence assert_observer independently confirmed with CAP_NET_ADMIN.
nft = checks["nftables"]
assert nft["level"] == "info" and "non-root" in nft["detail"], nft
if sys.argv[1] == "systemd":
    assert checks["nginx log"]["level"] == "pass", checks
' "$mode"
cp -- "$log" "$scratch/event-prefix"
printf '\n# Local operator setting retained by dpkg\n' >> "$engine"
cp -- "$engine" "$scratch/engine.toml"
prefix_bytes=$(wc -c < "$scratch/event-prefix")

# Reinstall the exact artifact. dpkg runs the upgrade/configure hooks for
# replacement of an installed package, even when the version is unchanged.
dpkg --install "$package"
cmp -- "$engine" "$scratch/engine.toml"
[[ $(as_detector pubkey --key "$key") == "$public_key" ]]
assert_observer
if [[ $mode == systemd ]]; then
    systemctl is-active --quiet lurewall.service
else
    run_service_once
fi
verify_evidence
cmp -n "$prefix_bytes" -- "$scratch/event-prefix" "$log"

if [[ $mode == systemd ]]; then
    if dpkg --remove lurewall; then
        echo "Uninstall unexpectedly succeeded while nginx still had the Lurewall log." >&2
        exit 1
    fi
    systemctl is-active --quiet lurewall.service
    detach_nginx
fi
if [[ $mode == container ]]; then
    # Disposable image, no nginx daemon. Exercise the root launcher and prerm together.
    printf 'invalid_fixture_directive;\n' > "$nginx_fixture"
    /usr/bin/lurewall uninstall --force
    rm -- "$nginx_fixture"
else
    apt-get remove -y lurewall
fi
[[ ! -e /usr/bin/lurewall ]]
[[ -s $key && -s $checkpoint ]]
if [[ $mode == systemd ]] && systemctl is-active --quiet lurewall.service; then
    echo "The Lurewall service remained active after removing the package." >&2
    exit 1
fi
cmp -- "$engine" "$scratch/engine.toml"
cmp -n "$prefix_bytes" -- "$scratch/event-prefix" "$log"
