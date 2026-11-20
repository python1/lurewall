# SPDX-License-Identifier: AGPL-3.0-only
"""Maintainer lifecycle tests using temporary state and simulated host commands."""

import json
import os
import runpy
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LIFECYCLE = runpy.run_path(str(REPO / "deploy/debian/lifecycle"))
Lifecycle = LIFECYCLE["Lifecycle"]
LifecycleError = LIFECYCLE["LifecycleError"]
OBSERVER = 'version = 1\ndry_run = true\n[enforcement]\nadapter = "log-only"\n'
ENFORCING = 'version = 1\ndry_run = false\n[enforcement]\nadapter = "nftables"\n'


class Host:
    def __init__(self):
        self.calls = []
        self.units = set()
        self.table = False
        self.kernel = True
        self.allow_stop = True
        self.nginx = "# configuration file /etc/nginx/nginx.conf:\nhttp {}"

    def __call__(self, argv):
        self.calls.append(tuple(argv))
        binary = Path(argv[0]).name
        status = 0
        output = ""
        if binary == "nft":
            if argv[1] == "-j":
                tables = [{"table": {"family": "inet", "name": "other"}}]
                if self.table:
                    tables.append({"table": {"family": "inet", "name": "lurewall"}})
                output = json.dumps({"nftables": tables})
                status = 0 if self.kernel else 1
            elif argv[1:] == ["delete", "table", "inet", "lurewall"]:
                self.table = False
        elif binary == "runuser":
            if "keygen" in argv or "save_state" in str(argv):
                Path(argv[-1]).write_text("private fixture\n")
        elif binary == "systemctl" and "is-active" in argv:
            status = 0 if argv[-1] in self.units else 3
        elif binary == "deb-systemd-invoke":
            if argv[1] in ("start", "restart"):
                self.units.update(argv[2:])
            elif argv[1] == "stop" and self.allow_stop:
                self.units.difference_update(argv[2:])
        elif binary == "nginx":
            output = self.nginx
        return subprocess.CompletedProcess(argv, status, stdout=output, stderr="")


def target(tmp_path, live=True):
    for item in ("etc/lurewall", "var/lib", "var/log"):
        (tmp_path / item).mkdir(parents=True)
    if live:
        (tmp_path / "run/systemd/system").mkdir(parents=True)
    (tmp_path / "etc/lurewall/engine.toml").write_text(OBSERVER)
    host = Host()
    lifecycle = Lifecycle(
        tmp_path, runner=host, get_account=lambda _runner: (os.getuid(), os.getgid())
    )
    return lifecycle, host


def test_fresh_configuration_initializes_private_state_without_enforcement(tmp_path):
    lifecycle, host = target(tmp_path)
    lifecycle.configure()

    assert lifecycle.marker.read_text() == "live\n"
    assert host.units == {"lurewall.service"}
    assert not host.table
    assert [call[2:] for call in host.calls if call[1] == "enable"] == [("lurewall.service",)]
    assert (lifecycle.state / "keys/lurewall.key").is_file()
    assert (lifecycle.state / "canaries.json").is_file()
    assert lifecycle.access.stat().st_mode & 0o777 == 0o640
    assert lifecycle.access.parent.stat().st_mode & 0o777 == 0o751
    assert all(call[1:4] == ("-u", "lurewall", "--") for call in host.calls if "keygen" in call)


def test_offline_configuration_queues_only_observer_for_boot(tmp_path):
    lifecycle, host = target(tmp_path, live=False)
    host.kernel = False
    lifecycle.configure()

    assert lifecycle.marker.read_text() == "offline\n"
    assert [call[2:] for call in host.calls if call[1] == "enable"] == [("lurewall.service",)]
    assert all(
        "systemctl" not in call[0] and "deb-systemd-invoke" not in call[0] for call in host.calls
    )
    lifecycle.remove()
    assert not lifecycle.marker.exists()


def test_upgrade_preserves_active_configuration_and_evidence(tmp_path):
    lifecycle, host = target(tmp_path)
    lifecycle.configure()
    key = lifecycle.state / "keys/lurewall.key"
    key.write_text("existing fixture\n")
    log = lifecycle.state / "events.log"
    log.write_text("existing evidence\n")
    config = lifecycle.config / "engine.toml"
    config.write_text(ENFORCING)
    host.table = True
    host.calls.clear()
    lifecycle.configure()

    assert key.read_text() == "existing fixture\n"
    assert log.read_text() == "existing evidence\n"
    assert config.read_text() == ENFORCING
    assert host.table
    assert not any("keygen" in call or call[1] == "enable" for call in host.calls)
    assert ("/usr/bin/deb-systemd-invoke", "restart", "lurewall.service") in host.calls


def test_refuses_fresh_install_that_would_inherit_enforcement_or_own_another_table(tmp_path):
    lifecycle, host = target(tmp_path)
    config = lifecycle.config / "engine.toml"
    config.write_text(ENFORCING)
    with pytest.raises(LifecycleError, match="Set dry_run=true"):
        lifecycle.configure()
    assert not host.calls
    config.write_text(OBSERVER)
    host.table = True
    with pytest.raises(LifecycleError, match="already exists"):
        lifecycle.configure()
    assert not lifecycle.state.exists()


@pytest.mark.parametrize(
    "directive",
    [
        "log_format lurewall_operator escape=json 'fixture';",
        "access_log /var/log/lurewall/access.jsonl;",
    ],
)
@pytest.mark.parametrize("force", [False, True])
def test_removal_refuses_when_nginx_still_references_lurewall(tmp_path, directive, force):
    lifecycle, host = target(tmp_path)
    lifecycle.configure()
    host.nginx += f"\n{directive}"
    host.calls.clear()
    with pytest.raises(LifecycleError, match="reload nginx"):
        lifecycle.remove(force=force)
    assert host.calls == [("/usr/sbin/nginx", "-T")]
    assert lifecycle.marker.is_file()


def test_removal_stops_observer_lifts_owned_blocks_and_preserves_evidence(tmp_path):
    lifecycle, host = target(tmp_path)
    lifecycle.configure()
    key = lifecycle.state / "keys/lurewall.key"
    original_key = key.read_bytes()
    log = lifecycle.state / "events.log"
    log.write_text("retained evidence\n")
    host.table = True
    lifecycle.remove()

    assert not host.table and not host.units
    assert not lifecycle.marker.exists()
    assert key.read_bytes() == original_key
    assert log.read_text() == "retained evidence\n"


def test_removal_refuses_unverified_table_and_when_policy_denies_stopping(tmp_path):
    lifecycle, host = target(tmp_path, live=False)
    host.kernel = False
    lifecycle.configure()
    host.kernel = True
    host.table = True
    with pytest.raises(LifecycleError, match="not reserved"):
        lifecycle.remove()
    assert host.table
    host.table = False
    lifecycle.live = True
    lifecycle.configure()
    host.table = True
    host.allow_stop = False
    with pytest.raises(LifecycleError, match="remain active"):
        lifecycle.remove()
    assert host.table
    assert lifecycle.marker.read_text() == "live\n"


@pytest.mark.parametrize("missing", [False, True])
def test_forced_removal_with_broken_or_missing_nginx_preserves_evidence(tmp_path, missing):
    lifecycle, host = target(tmp_path)
    lifecycle.configure()
    host.nginx = "invalid"

    def invoke(argv):
        if missing and argv[0].endswith("/nginx"):
            raise FileNotFoundError
        return host(argv)

    lifecycle.runner = invoke
    with pytest.raises(LifecycleError, match="Could not verify"):
        lifecycle.remove()
    evidence = lifecycle.state / "events.log"
    evidence.write_bytes(b"evidence")
    lifecycle.remove(force=True)
    assert evidence.read_bytes() == b"evidence" and not lifecycle.marker.exists()
