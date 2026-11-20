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


@pytest.mark.parametrize(
    ("unit", "address_families", "capabilities"),
    [
        ("lurewall.service", "AF_UNIX AF_NETLINK", ""),
        ("lurewall-sweeper.service", "AF_UNIX AF_NETLINK", "CAP_NET_ADMIN"),
        ("lurewall-notify.service", "AF_UNIX AF_INET AF_INET6", ""),
        ("lurewall-notify-failure.service", "AF_UNIX AF_INET AF_INET6", ""),
    ],
)
def test_installed_services_restrict_processes_network_and_capabilities(
    deployment, unit, address_families, capabilities
):
    target, _commands = deployment
    target.deploy("install")
    directives = set((target.systemd / unit).read_text().splitlines())
    assert {
        "User=lurewall",
        "NoNewPrivileges=yes",
        "ProtectKernelLogs=yes",
        "ProtectClock=yes",
        "ProtectHostname=yes",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "RestrictNamespaces=yes",
        "RestrictRealtime=yes",
        "LockPersonality=yes",
        "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service",
        f"RestrictAddressFamilies={address_families}",
        f"CapabilityBoundingSet={capabilities}",
    } <= directives


class Commands:
    def __init__(self):
        self.calls = []
        self.active = False
        self.failed_restart = None
        self.firewall = False
        self.nginx_config = "# configuration file /etc/nginx/nginx.conf:\nevents {}\n"
        self.nginx_status = 0
        self.output_kind = None
        self.fail_validation = False
        self.wheels = []

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
        elif binary == "nginx":
            assert argv[1:] == ["-T"] and capture and not check
            code = self.nginx_status
            output = self.nginx_config
        elif binary == "nft":
            if argv[1] == "-j":
                tables = [{"table": {"family": "inet", "name": "other"}}]
                if self.firewall:
                    tables.append({"table": {"family": "inet", "name": "lurewall"}})
                output = json.dumps({"nftables": tables})
            else:
                assert argv[1:] == ["delete", "table", "inet", "lurewall"]
                self.firewall = False
        elif binary == "runuser" and argv[2] == "lurewall-build":
            if "pip" in argv:
                packages = Path(argv[argv.index("--target") + 1])
                module = packages / "lurewall"
                module.mkdir(parents=True)
                entry = module / "__init__.py"
                if self.output_kind == "symlink":
                    entry.symlink_to(Path(argv[-1]) / "not-found")
                elif self.output_kind == "fifo":
                    os.mkfifo(entry)
                elif self.output_kind == "hardlink":
                    original = packages.parent / "hardlink-target"
                    original.touch()
                    entry.hardlink_to(original)
                else:
                    entry.write_text("# disposable installed package\n")
                    entry.chmod(0o777)
                (packages / "bin").mkdir()
                (packages / "bin/pip").touch()
                if "--find-links" in argv:
                    index = argv.index("--find-links") + 1
                    self.wheels = list(Path(argv[index]).iterdir())
            if self.fail_validation and any("import lurewall.signing" in arg for arg in argv):
                raise subprocess.CalledProcessError(1, argv)
        elif binary == "runuser":
            path = Path(argv[-1])
            path.write_bytes(b"preserved local fixture\n")
            path.chmod(0o600)
        return subprocess.CompletedProcess(argv, code, stdout=output if capture else None)


@pytest.fixture
def deployment(tmp_path):
    commands = Commands()
    target = Deployment(
        REPO,
        root=tmp_path,
        run=commands,
        get_account=lambda: (os.getuid(), os.getgid()),
        get_build_account=lambda: (os.getuid(), os.getgid()),
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
    commands.nginx_config += "# access_log /var/log/lurewall/access.jsonl lurewall_operator;\n"
    target.uninstall()
    assert not commands.firewall
    assert not target.current.is_symlink() and not target.launcher.is_symlink()
    assert not (target.systemd / "lurewall.service").exists()
    assert not target.rotation.exists()
    assert log.read_bytes() == b"existing evidence\n"
    assert config.read_bytes() == prior_config
    assert (target.state / "keys/lurewall.key").read_bytes() == key


@pytest.mark.parametrize(
    "config",
    [
        'http { access_log /var/log/nginx/example.log "lurewall_operator"; }',
        'http { access_log "/var/log/lurewall/../lurewall/access.jsonl" combined; }',
        'http { log_format lurewall_operator escape=json "fixture"; }',
    ],
)
def test_uninstall_refuses_nginx_log_dependencies_before_mutating(deployment, config):
    target, commands = deployment
    target.deploy("install")
    commands.firewall = True
    commands.nginx_config += config
    commands.calls.clear()

    with pytest.raises(DeploymentError, match=r"nginx still references Lurewall.*reload nginx"):
        target.uninstall()

    assert commands.calls == [("/usr/sbin/nginx", "-T")]
    assert commands.active and commands.firewall
    assert target.current.is_symlink() and target.rotation.is_file()


def test_uninstall_refuses_a_link_to_the_managed_log(deployment):
    target, commands = deployment
    target.deploy("install")
    alternate = target.access.with_name("alternate.jsonl")
    alternate.symlink_to(target.access)
    commands.nginx_config += (
        f"http {{ access_log /{alternate.relative_to(target.root)} combined; }}"
    )
    with pytest.raises(DeploymentError, match="nginx still references Lurewall"):
        target.uninstall()


@pytest.mark.parametrize("status", [0, 1])
def test_uninstall_errors_without_printing_unusable_nginx_output(deployment, status):
    target, commands = deployment
    target.deploy("install")
    commands.nginx_config = "private fixture content"
    commands.nginx_status = status
    commands.calls.clear()

    with pytest.raises(DeploymentError, match=r"Could not verify.*reload nginx") as caught:
        target.uninstall()

    assert "private fixture content" not in str(caught.value)
    assert commands.calls == [("/usr/sbin/nginx", "-T")]
    assert target.current.is_symlink()


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


def test_failed_rollback_commands_do_not_skip_later_rollback_steps(deployment, monkeypatch):
    target, commands = deployment
    target.deploy("install")
    previous_release = target.current.readlink()
    old_unit = target.systemd / "lurewall.service"
    old_unit.write_bytes(old_unit.read_bytes() + b"\n# retained prior unit\n")
    unit_bytes = old_unit.read_bytes()
    evidence = target.state / "events.log"
    evidence.write_bytes(b"retained evidence\n")
    systemctl = target.systemctl
    failures = {"stop": 15, "daemon-reload": 16, "start": 17}
    rollback_calls = []
    activation_failed = False

    def fail(*args, check=True, capture=False):
        nonlocal activation_failed
        if args[0] == "restart":
            activation_failed = True
            commands.active = False
            raise subprocess.CalledProcessError(27, args)
        if activation_failed and args[0] in failures:
            rollback_calls.append(args[0])
            assert not check
            return subprocess.CompletedProcess(args, failures[args[0]])
        return systemctl(*args, check=check, capture=capture)

    monkeypatch.setattr(target, "systemctl", fail)
    with pytest.raises(DeploymentError) as caught:
        target.deploy("upgrade")

    assert rollback_calls == ["stop", "daemon-reload", "start"]
    assert target.current.readlink() == previous_release
    assert old_unit.read_bytes() == unit_bytes
    assert evidence.read_bytes() == b"retained evidence\n"
    assert list(target.releases.iterdir()) == [previous_release]
    message = str(caught.value)
    assert "27" in message
    for label, status in failures.items():
        assert label in message and str(status) in message


def test_rollback_keeps_failed_release_if_service_may_still_use_it(deployment, monkeypatch):
    target, commands = deployment
    target.deploy("install")
    previous_release = target.current.readlink()
    commands.failed_restart = 1
    systemctl = target.systemctl

    def fail_stop(*args, check=True, capture=False):
        if args[0] == "stop":
            assert not check
            return subprocess.CompletedProcess(args, 15)
        return systemctl(*args, check=check, capture=capture)

    monkeypatch.setattr(target, "systemctl", fail_stop)
    with pytest.raises(DeploymentError, match="failed release may still be in use"):
        target.deploy("upgrade")

    assert target.current.readlink() == previous_release
    assert len(list(target.releases.iterdir())) == 2


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


def test_source_install_refuses_an_existing_debian_package(deployment):
    target, commands = deployment
    marker = target.root / "usr/lib/lurewall/debian-lifecycle"
    marker.parent.mkdir(parents=True)
    marker.touch()

    with pytest.raises(DeploymentError, match="Debian package is installed"):
        target.deploy("install")

    assert commands.calls == []
    assert not target.home.exists()


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
    (wheelhouse / "fixture.whl").touch()
    target.deploy("install", wheelhouse)
    (invocation,) = (call for call in commands.calls if "pip" in call)
    assert "--no-index" in invocation
    path_index = invocation.index("--find-links") + 1
    assert Path(invocation[path_index]) != wheelhouse
    assert [wheel.name for wheel in commands.wheels] == ["fixture.whl"]


def test_installer_builds_and_checks_packages_only_as_the_builder(deployment):
    target, commands = deployment
    target.deploy("install")
    builds = [
        call for call in commands.calls if call[:3] == ("/usr/sbin/runuser", "-u", "lurewall-build")
    ]
    assert len(builds) == 4
    for invocation in builds:
        assert invocation[3:7] == ("--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin")
        assert invocation[7].startswith(f"HOME={target.home / '.build-'}")
        assert invocation[7].endswith("/work")
        assert "PIP_CONFIG_FILE=/dev/null" in invocation
    assert any("venv" in invocation for invocation in builds)
    assert any("pip" in invocation for invocation in builds)
    assert any("import lurewall.signing" in arg for arg in builds[-1])
    assert (
        target.current / "packages/lurewall/__init__.py"
    ).read_text() == "# disposable installed package\n"
    installed = target.current / "packages/lurewall/__init__.py"
    assert stat.S_IMODE(installed.stat().st_mode) == 0o444
    assert not (target.current / "packages/bin").exists()
    assert not (target.current / "venv").exists()
    assert (target.current / "trusted/lurewall/__init__.py").read_bytes() == (
        REPO / "src/lurewall/__init__.py"
    ).read_bytes()
    assert not list(target.home.glob(".build-*"))

    launcher = (target.current / "bin/lurewall").read_text().splitlines()
    root_line = next(line for line in launcher if "allowlist/list|" in line)
    dropped_line = next(line for line in launcher if "/usr/sbin/runuser" in line)
    assert "/trusted " in root_line and "/packages " not in root_line
    assert "-u lurewall -- /usr/bin/env -i" in dropped_line and "/packages " in dropped_line


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_installer_rejects_nonregular_package_handoff(deployment, kind):
    target, commands = deployment
    commands.output_kind = kind
    with pytest.raises(DeploymentError, match="only regular files"):
        target.deploy("install")
    assert not target.current.is_symlink()
    assert not list(target.home.glob(".build-*"))
    assert not list(target.releases.iterdir())
    assert not any(call[0] == "/usr/bin/systemctl" for call in commands.calls)


def test_installer_cleans_failed_validation_before_starting_anything(deployment):
    target, commands = deployment
    commands.fail_validation = True
    with pytest.raises(subprocess.CalledProcessError):
        target.deploy("install")
    assert not target.current.is_symlink()
    assert not list(target.home.glob(".build-*"))
    assert not list(target.releases.iterdir())
    assert not any(call[0] == "/usr/bin/systemctl" for call in commands.calls)


@pytest.mark.parametrize("missing", [False, True])
def test_forced_source_uninstall_preserves_evidence(deployment, missing):
    target, commands = deployment
    target.deploy("install")
    commands.nginx_status = 1

    def invoke(argv, **kwargs):
        if missing and argv[0].endswith("/nginx"):
            raise FileNotFoundError
        return commands(argv, **kwargs)

    target.run = invoke
    evidence = target.state / "events.log"
    evidence.write_bytes(b"evidence")
    target.uninstall(force=True)
    assert evidence.read_bytes() == b"evidence" and not target.launcher.exists()
