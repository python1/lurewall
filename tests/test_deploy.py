# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise deployment lifecycle in a temporary tree without starting services."""

from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
from pathlib import Path

import pytest

from lurewall import engineconfig

REPO = Path(__file__).resolve().parents[1]
MANAGE = runpy.run_path(str(REPO / "deploy/manage"))
Deployment = MANAGE["Deployment"]
DeploymentError = MANAGE["DeploymentError"]


class Commands:
    def __init__(self):
        self.calls = []
        self.active = False
        self.failed_restart = None
        self.firewall = False

    def __call__(self, argv, *, check=True, capture=False):
        self.calls.append(tuple(argv))
        binary = Path(argv[0]).name
        code = 0
        output = ""
        if binary == "systemctl":
            verb = argv[1]
            if verb == "is-active":
                code = 0 if self.active else 3
            elif verb == "show":
                output = str(self.failed_restart or 0)
            elif verb == "restart" and self.failed_restart is not None:
                raise subprocess.CalledProcessError(1, argv)
            elif verb in ("start", "restart", "enable"):
                self.active = True
            elif verb in ("disable", "stop"):
                self.active = False
        elif binary == "nft":
            if argv[1] == "-j":
                tables = [{"table": {"family": "inet", "name": "other"}}]
                if self.firewall:
                    tables.append({"table": {"family": "inet", "name": "lurewall"}})
                output = json.dumps({"nftables": tables})
            else:
                assert argv[1:] == ["delete", "table", "inet", "lurewall"]
                self.firewall = False
        elif binary == "runuser":
            path = Path(argv[-1])
            path.write_bytes(b"preserved local fixture\n")
            path.chmod(0o600)
        return subprocess.CompletedProcess(argv, code, stdout=output if capture else None)


@pytest.fixture
def deployment(tmp_path):
    commands = Commands()
    target = Deployment(
        REPO, root=tmp_path, run=commands, get_account=lambda: (os.getuid(), os.getgid())
    )
    return target, commands


def test_install_starts_only_observation_and_leaves_nginx_configuration_alone(deployment):
    target, commands = deployment
    target.deploy("install")
    config = engineconfig.load(target.config / "engine.toml")
    assert config.dry_run and config.adapter == "log-only"
    assert config.ttl_ms == 5 * 60_000
    assert config.max_ttl_ms == 30 * 60_000
    assert target.launcher.readlink() == target.current / "bin/lurewall"
    assert target.launcher.is_file()
    assert stat.S_IMODE(target.access.stat().st_mode) == 0o640
    assert stat.S_IMODE(target.access.parent.stat().st_mode) == 0o751
    assert (target.state / "keys/lurewall.key").is_file()
    assert (target.state / "canaries.json").is_file()
    assert (target.config / "nginx/operator-format.conf").is_file()
    assert not (target.root / "etc/nginx").exists()
    assert not (target.systemd / "lurewall.service.d").exists()
    assert [call[2:] for call in commands.calls if call[1] == "enable"] == [
        ("--now", "lurewall.service"),
    ]
    assert not any(call[1] == "delete" for call in commands.calls)
    with pytest.raises(DeploymentError, match="already installed"):
        target.deploy("install")


def test_upgrade_keeps_state_and_uninstall_clears_only_its_firewall(deployment):
    target, commands = deployment
    target.deploy("install")
    original = target.current.readlink()
    log = target.state / "events.log"
    log.write_bytes(b"existing evidence\n")
    config = target.config / "engine.toml"
    config.write_bytes(config.read_bytes() + b"\n# operator change\n")
    prior_config = config.read_bytes()
    key = (target.state / "keys/lurewall.key").read_bytes()
    target.deploy("upgrade")
    assert target.current.readlink() != original
    assert ("/usr/bin/systemctl", "restart", "lurewall.service") in commands.calls
    assert config.read_bytes() == prior_config
    assert log.read_bytes() == b"existing evidence\n"
    assert (target.state / "keys/lurewall.key").read_bytes() == key
    commands.firewall = True
    target.uninstall()
    assert not commands.firewall
    assert not target.current.is_symlink() and not target.launcher.is_symlink()
    assert not (target.systemd / "lurewall.service").exists()
    assert not target.rotation.exists()
    assert log.read_bytes() == b"existing evidence\n"
    assert config.read_bytes() == prior_config
    assert (target.state / "keys/lurewall.key").read_bytes() == key


@pytest.mark.parametrize("status", [1, 3])
def test_failed_upgrade_restores_its_binary_and_does_not_rewind_evidence(deployment, status):
    target, commands = deployment
    target.deploy("install")
    previous_release = target.current.readlink()
    log = target.state / "events.log"
    log.write_text("retained\n")
    old_unit = target.systemd / "lurewall.service"
    prior_unit = old_unit.read_bytes()
    commands.failed_restart = status
    commands.calls.clear()
    with pytest.raises(DeploymentError, match="Previous release restored"):
        target.deploy("upgrade")
    assert target.current.readlink() == previous_release
    assert log.read_text() == "retained\n"
    assert old_unit.read_bytes() == prior_unit
    assert list(target.releases.iterdir()) == [previous_release]
    assert any(call[1] == "start" for call in commands.calls) == (status == 1)


def test_install_refuses_existing_managed_names_and_firewall(deployment):
    target, commands = deployment
    commands.firewall = True
    with pytest.raises(DeploymentError, match="table already exists"):
        target.deploy("install")
    assert not target.home.exists()
    target.launcher.parent.mkdir(parents=True)
    target.launcher.write_text("other local binary")
    with pytest.raises(DeploymentError, match="unmanaged installation"):
        target.deploy("install")
    assert target.launcher.read_text() == "other local binary"


def test_reinstall_requires_dry_run_when_retained_configuration_enforces(deployment):
    target, commands = deployment
    target.deploy("install")
    config = target.config / "engine.toml"
    config.write_text(
        config.read_text()
        .replace("dry_run = true", "dry_run = false")
        .replace('adapter = "log-only"', 'adapter = "nftables"')
    )
    target.uninstall()
    commands.calls.clear()
    with pytest.raises(DeploymentError, match="Set dry_run=true"):
        target.deploy("install")
    assert not any(call[1] == "enable" for call in commands.calls)
    assert "dry_run = false" in config.read_text()


def test_offline_build_uses_wheelhouse_without_index(deployment):
    target, commands = deployment
    wheelhouse = target.root / "wheels"
    wheelhouse.mkdir()
    target.deploy("install", wheelhouse)
    (invocation,) = (call for call in commands.calls if "pip" in call)
    assert "--no-index" in invocation
    path_index = invocation.index("--find-links") + 1
    assert invocation[path_index] == str(wheelhouse)
