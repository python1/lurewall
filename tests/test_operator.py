# SPDX-License-Identifier: AGPL-3.0-only
"""Operator workflows with local state, synthetic addresses and in-memory nft."""

from __future__ import annotations

import ipaddress
import json
import stat
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

import nginx_emu
import sig
from conftest import FakeClock
from fake_nft import FakeNft
from lurewall import canaries, cli, engine, engineconfig, operator, service, signing
from lurewall.eventlog import EventLog

SOURCE = "192.0.2.37"


@pytest.fixture
def local(tmp_path):
    now = time.time_ns() // 1_000_000
    clock = FakeClock(now)
    paths = service.Paths(
        access_log=tmp_path / "access.jsonl",
        reader_state=tmp_path / "reader.json",
        event_log=tmp_path / "events.log",
        key=tmp_path / "signing.key",
        canaries=tmp_path / "canaries.json",
        signals=sig.LAB_CONFIG,
        engine_config=tmp_path / "engine.toml",
        engine_state=tmp_path / "engine.json",
        checkpoint=tmp_path / "checkpoint.json",
        allowlist_file=tmp_path / "allowlist",
        operator_dir=tmp_path / "operator",
    )
    paths.engine_config.write_text("version = 1\n")
    paths.access_log.write_bytes(nginx_emu.line(ts_ms=now, ip=SOURCE))
    paths.allowlist_file.write_text("# local comments survive CLI edits\n")
    paths.allowlist_file.chmod(0o644)
    paths.operator_dir.mkdir(mode=0o700)
    canaries.save_state(sig.canary_set(), paths.canaries)
    signer = signing.EurekaSigner.generate(paths.key)
    return paths, signer, clock


def test_allowlist_updates_preserve_comments_and_permissions(local, capsys):
    paths, _, _ = local
    arguments = ["--file", str(paths.allowlist_file)]
    assert cli.main(["allowlist", "add", SOURCE, *arguments]) == cli.EXIT_OK
    assert "Restart lurewall.service" in capsys.readouterr().out
    assert cli.main(["allowlist", "add", f"{SOURCE}/32", *arguments]) == cli.EXIT_OK
    assert "already matches" in capsys.readouterr().out
    assert cli.main(["allowlist", "list", *arguments]) == cli.EXIT_OK
    assert capsys.readouterr().out == f"{SOURCE}/32\n"
    assert stat.S_IMODE(paths.allowlist_file.stat().st_mode) == 0o644
    assert cli.main(["allowlist", "remove", SOURCE, *arguments]) == cli.EXIT_OK
    assert paths.allowlist_file.read_text() == "# local comments survive CLI edits\n"


def test_allowlist_path_cannot_be_a_symlink(local):
    paths, _, _ = local
    target = paths.allowlist_file
    link = target.with_name("other-list")
    link.symlink_to(target)
    with pytest.raises(OSError):
        operator.read_allowlist(link)
    with pytest.raises(ValueError, match="regular file"):
        operator.change_allowlist(link, "add", SOURCE)


def test_allowlist_can_run_from_trusted_source_without_third_party_packages(tmp_path):
    source_dir = Path(__file__).resolve().parents[1] / "src"
    allowlist = tmp_path / "allowlist"
    allowlist.touch()
    command = (
        "import sys; sys.path.insert(0, sys.argv.pop(1)); "
        "from lurewall.cli import main; result = main(sys.argv[1:]); "
        "assert not any(m in sys.modules for m in ['cryptography', 'lurewall._eureka']); "
        "sys.exit(result)"
    )
    subprocess.run(  # noqa: S603 - fixed interpreter and local test arguments
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            command,
            str(source_dir),
            "allowlist",
            "add",
            SOURCE,
            "--file",
            str(allowlist),
        ],
        check=True,
    )
    assert allowlist.read_text() == f"{SOURCE}/32\n"


def test_unblock_serializes_with_running_service_and_survives_backend_failure(local, capsys):
    paths, signer, clock = local
    expiry = clock.now + 60_000
    state = {
        "version": engine.STATE_VERSION,
        "hits": {},
        "blocks": {SOURCE: [clock.now, expiry, 60_000, True]},
        "history": {},
        "alert_raised": None,
    }
    engine.write_private(paths.engine_state, json.dumps(state).encode())
    paths.engine_config.write_text(
        'version = 1\ndry_run = false\n[enforcement]\nadapter = "nftables"\n'
    )
    fake = FakeNft(clock)
    running = service.Service(paths, runner=fake, clock=clock, fsync=False)
    try:
        assert SOURCE in fake.elements()
        arguments = ["unblock", SOURCE, "--operator-dir", str(paths.operator_dir)]
        assert cli.main(arguments) == cli.EXIT_OK
        assert "queued" in capsys.readouterr().out
        assert cli.main(arguments) == cli.EXIT_USAGE
        assert "already pending" in capsys.readouterr().err
        fake.fail = True
        running.step()
        assert SOURCE in fake.elements()
        assert engine.read_status(paths.engine_state, clock.now)["blocks"] == []
        assert (paths.operator_dir / "unblock").is_file()
        fake.fail = False
        clock.advance(5_000)
        running.step()
        assert SOURCE not in fake.elements()
        assert not (paths.operator_dir / "unblock").exists()
    finally:
        running.close()
    report, source, _, records = operator.explain(
        SOURCE, paths.event_log, signer.public_key_hex, [paths.checkpoint], 20
    )
    assert report.ok and source == SOURCE
    assert any(item["type"] == "manual_unblock" for item in records)


def test_service_reads_allowlist_before_reinstating_saved_blocks(local):
    paths, _, clock = local
    expiry = clock.now + 60_000
    state = {
        "version": engine.STATE_VERSION,
        "hits": {},
        "blocks": {SOURCE: [clock.now, expiry, 60_000, True]},
        "history": {},
        "alert_raised": None,
    }
    engine.write_private(paths.engine_state, json.dumps(state).encode())
    paths.engine_config.write_text(
        'version = 1\ndry_run = false\n[enforcement]\nadapter = "nftables"\n'
    )
    paths.allowlist_file.write_text(f"{SOURCE}\n")
    fake = FakeNft(clock)
    running = service.Service(paths, runner=fake, clock=clock, fsync=False)
    try:
        assert running.config.allowlist == (ipaddress.ip_network(SOURCE),)
        assert SOURCE not in fake.elements()
        assert running.engine.active_blocks() == {}
    finally:
        running.close()


def test_explain_aggregates_ipv6_and_does_not_print_unverified_or_unrelated_data(
    make_log, signer, capsys
):
    log = make_log()
    log.append("would_block", "2001:db8:37::/64", {"reason": "dry_run", "uri": "private-value"})
    log.append("block", SOURCE, {"reason": "unrelated-value"})
    log.close()
    arguments = [
        "explain-decision",
        "2001:db8:37::123",
        "--event-log",
        str(log.path),
        "--pubkey",
        signer.public_key_hex,
    ]
    assert cli.main(arguments) == cli.EXIT_OK
    output = capsys.readouterr().out
    assert "2001:db8:37::/64" in output and "dry_run" in output
    assert "private-value" not in output and "unrelated-value" not in output
    log.path.write_bytes(log.path.read_bytes().replace(b"dry_run", b"changed"))
    assert cli.main(arguments) == cli.EXIT_FAIL
    failed = capsys.readouterr()
    assert "RESULT: FAIL" in failed.err
    assert not failed.out


def test_doctor_reads_nginx_sample_and_signed_checkpoint(local, monkeypatch):
    paths, signer, clock = local
    with EventLog(paths.event_log, signer, checkpoint_path=paths.checkpoint, clock=clock) as trace:
        trace.append("service_started", detail={"dry_run": True})
    fake = FakeNft(clock)
    monkeypatch.setattr(operator, "system_runner", lambda _: fake)
    arguments = {
        "engine_path": paths.engine_config,
        "signals_path": paths.signals,
        "canaries_path": paths.canaries,
        "allowlist_path": paths.allowlist_file,
        "access_log": paths.access_log,
        "event_log": paths.event_log,
        "key": paths.key,
        "checkpoint": paths.checkpoint,
        "operator_dir": paths.operator_dir,
        "require_peer_log": False,
    }
    checks = {check.name: check.level for check in operator.doctor(**arguments)}
    assert checks["config"] == checks["nginx log"] == checks["checkpoint"] == "pass"
    assert fake.changes() == []
    paths.access_log.write_bytes(b"unexpected format\n")
    paths.checkpoint.write_bytes(b"invalid checkpoint")
    checks = {check.name: check.level for check in operator.doctor(**arguments)}
    assert checks["nginx log"] == checks["checkpoint"] == "fail"


def test_installed_status_reports_service_state_and_configured_mode(local, capsys, monkeypatch):
    paths, _, _ = local
    monkeypatch.setattr(cli, "STATE_DIR", paths.engine_state.parent)
    monkeypatch.setattr(cli, "ENGINE_CONFIG", paths.engine_config)
    monkeypatch.setattr(operator, "unit_state", lambda: "failed")
    assert cli.main(["status", "--json"]) == cli.EXIT_FAIL
    result = json.loads(capsys.readouterr().out)
    assert result == {"mode": "dry-run", "service": "failed", "saved_state": None}


def test_systemd_notify_after_startup_uses_only_local_datagram(monkeypatch):
    monkeypatch.setenv("NOTIFY_SOCKET", "@fixture-name")
    datagram = Mock()
    context = Mock()
    # A socket is a context manager, so expose the fake on its entered instance.
    context.__enter__ = Mock(return_value=datagram)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("socket.socket", lambda *_: context)
    cli._notify_ready()
    datagram.sendto.assert_called_once_with(b"READY=1", "\0fixture-name")


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("[enforcement]\ntcp_ports = [0]", "TCP ports"),
        ("[enforcement]\ntcp_ports = [443, 443]", "TCP ports"),
        ("[enforcement]\ntcp_ports = [true]", "TCP ports"),
        ('[sources]\ntrusted_proxies = ["::/0"]', "explicit proxy"),
        (
            'dry_run = false\n[enforcement]\nadapter = "nftables"\n'
            '[sources]\ntrusted_proxies = ["192.0.2.0/28"]',
            "require dry-run or the log-only adapter",
        ),
    ],
)
def test_config_refuses_unsafe_enforcement_settings(raw, reason):
    with pytest.raises(engineconfig.EngineConfigError, match=reason):
        engineconfig.parse("version = 1\n" + raw)


def test_impersonation_is_signed_and_never_added_to_source_attack_state(local, tmp_path):
    from dataclasses import replace

    from lurewall import identitylab

    paths, signer, clock = local
    now = clock.now // 1000
    obs, _, _ = identitylab.fixture(tmp_path, now)
    config = obs.config
    config.write_text(
        config.read_text()
        .replace('coverage = "partial"', 'coverage = "authoritative"')
        .replace(
            "https://ranges.example/ranges.json",
            "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
        )
    )
    fields = identitylab.log_fields(now)
    paths.access_log.write_text(json.dumps(fields) + "\n")
    running = service.Service(replace(paths, agents=config), clock=clock, fsync=False)
    try:
        assert running.step() == 1
        view = running.collector.tracker.view(fields["ip"])
        assert view.attack_keys == () and view.attack_requests == 0
        assert not running.engine.active_blocks()
    finally:
        running.close()
    from lurewall.verify import verify_log

    items = []
    assert verify_log(
        paths.event_log, signer.public_key_hex, [paths.checkpoint], visit=items.append
    ).ok
    (identity,) = [item for item in items if item.type == "agent_identity"]
    assert identity.detail["verdict"] == "impersonation" and identity.detail["counted"] is False
    assert identity.detail["duration_ms"] == 10
