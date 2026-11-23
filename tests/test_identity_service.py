# SPDX-License-Identifier: AGPL-3.0-only
"""Identity verification through the real Service wiring: optional, alert-only, never fatal."""

from __future__ import annotations

import json
import os
import secrets

import pytest

import sig
from conftest import FakeClock
from lurewall import canaries, cli, identitylab, service, signing
from lurewall.verify import verify_log

GOOGLE = "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"
SOURCE = "192.0.2.8"  # outside the lab ranges (198.51.100.0/24)


def make_paths(root, agents=None):
    paths = service.Paths(
        access_log=root / "access.jsonl",
        reader_state=root / "reader.json",
        event_log=root / "events.log",
        key=root / "signing.key",
        canaries=root / "canaries.json",
        signals=sig.LAB_CONFIG,
        engine_config=root / "engine.toml",
        engine_state=root / "engine.json",
        checkpoint=root / "checkpoint.json",
        telemetry_dir=root / "telemetry",
        agents=agents,
        agent_cache=root / "cache",
        agent_requests=root / "requests",
        agent_replay=root / "replay.sqlite",
    )
    paths.engine_config.write_text("version = 1\n")
    paths.access_log.write_bytes(b"")
    (root / "telemetry").mkdir(mode=0o700)
    canaries.save_state(sig.canary_set(), paths.canaries)
    signer = signing.EurekaSigner.generate(paths.key)
    return paths, signer


def google_lab(root, now):
    """The offline lab fixture with its range feed standing in for Google's crawler ranges."""
    obs, key, kid = identitylab.fixture(root, now)
    obs.close()
    config = obs.config
    config.write_text(
        config.read_text()
        .replace('coverage = "partial"', 'coverage = "authoritative"')
        .replace("https://ranges.example/ranges.json", GOOGLE)
        + '[claim.Googlebot]\nranges = "ranges"\n'
    )
    return config, key, kid


def line(now_s, offset_ms, **fields):
    base = identitylab.log_fields(now_s)
    base["ts"] = f"{now_s + offset_ms // 1000}.{offset_ms % 1000:03d}"
    base.update(fields)
    base["request"] = f"{base['method']} {base['uri']} {base['protocol']}"
    return base


def write(paths, rows):
    with paths.access_log.open("a") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def events(paths, signer):
    items = []
    assert verify_log(
        paths.event_log, signer.public_key_hex, [paths.checkpoint], visit=items.append
    ).ok
    return items


def run(paths, clock, steps=1):
    running = service.Service(paths, clock=clock, fsync=False)
    try:
        for _ in range(steps):
            running.step()
            clock.advance(10)
    finally:
        running.close()
    return running


def attack_rows(now_s):
    """A counted canary hit, an impersonating request, and one distinct probe.

    If impersonation counted as an attack signal, the impersonating request and the
    probe would be two distinct signals on two requests: the block row.
    """
    page = line(now_s, 1, ip=SOURCE, ua="Mozilla/5.0", request_id=secrets.token_hex(16))
    hit = line(
        now_s,
        2,
        ip=SOURCE,
        ua="Mozilla/5.0",
        uri=sig.canary_set().canaries[0].reference(page["request_id"]),
        request_id=secrets.token_hex(16),
    )
    spoof = line(now_s, 3, ip=SOURCE, ua="Googlebot/2.1", request_id=secrets.token_hex(16))
    probe = line(now_s, 4, ip=SOURCE, ua="Mozilla/5.0", uri="/.env", status="404")
    probe["request_id"] = secrets.token_hex(16)
    return [page, hit, spoof, probe]


def detector_events(items):
    """Every signed event except identity observations and their roll-ups."""
    return [
        (item.type, item.source, item.detail)
        for item in items
        if not item.type.startswith("agent_")
        and not (item.type == "rollup" and item.detail.get("of") == "agent_identity")
    ]


def test_impersonation_has_zero_votes_through_the_service(tmp_path):
    now_s = 1_800_000_000
    rows = attack_rows(now_s)
    seen = {}
    for mode in ("off", "on"):
        root = tmp_path / mode
        root.mkdir()
        agents = google_lab(root, now_s)[0] if mode == "on" else None
        paths, signer = make_paths(root, agents)
        write(paths, rows)
        running = run(paths, FakeClock(now_s * 1000 + 50))
        items = events(paths, signer)
        seen[mode] = detector_events(items)
        # One attack signal either way: the probe. Impersonation never reaches the tracker.
        assert len(running.collector.tracker.view(SOURCE).attack_keys) == 1
        identity = [item.detail for item in items if item.type == "agent_identity"]
        if mode == "on":
            assert [row["verdict"] for row in identity] == ["impersonation"]
            assert identity[0]["counted"] is False
            metrics = (root / "telemetry/lurewall.prom").read_text()
            assert "lurewall_agent_impersonation_total 1" in metrics
            assert (root / "telemetry/impersonation.pending").exists()
        else:
            assert identity == []
    kinds = [kind for kind, _, _ in seen["off"]]
    # The scenario sits one signal below the block row: the canary hit counted and
    # the probe raised a signal. Had impersonation counted, this would be would_block.
    assert "canary_hit" in kinds and "attack_signal" in kinds
    assert "would_block" not in kinds and "attack_threshold_met" not in kinds
    assert seen["on"] == seen["off"]


def test_the_scenario_above_blocks_with_one_more_real_signal(tmp_path):
    now_s = 1_800_000_000
    paths, signer = make_paths(tmp_path)
    second = line(now_s, 5, ip=SOURCE, uri="/.git/config", status="404")
    second["request_id"] = secrets.token_hex(16)
    write(paths, [*attack_rows(now_s), second])
    run(paths, FakeClock(now_s * 1000 + 50))
    assert "would_block" in [item.type for item in events(paths, signer)]


def test_a_broken_agents_file_never_stops_the_detector_and_edits_apply_live(tmp_path):
    now_s = 1_800_000_000
    config, _, _ = google_lab(tmp_path, now_s)
    good = config.read_text()
    config.write_text(good + "\nthis is [not toml\n")
    paths, signer = make_paths(tmp_path, config)
    clock = FakeClock(now_s * 1000 + 50)
    write(paths, [line(now_s, 1, ua="Googlebot/2.1")])
    running = service.Service(paths, clock=clock, fsync=False)
    try:
        assert running.step() == 1  # the detector runs with identity off
        assert not running.identity.active
        config.write_text(good)
        clock.advance(6_000)
        write(paths, [line(now_s, 6_100, ua="Googlebot/2.1")])
        assert running.step() == 1
        assert running.identity.active
        config.write_text(good + "\n[feed.bad]\nurl = 1\n")
        clock.advance(6_000)
        write(paths, [line(now_s, 12_200, ua="Googlebot/2.1")])
        assert running.step() == 1
        assert running.identity.active  # the last valid settings stay in force
        config.unlink()
        clock.advance(6_000)
        write(paths, [line(now_s, 18_300, ua="Googlebot/2.1")])
        assert running.step() == 1
        assert not running.identity.active
    finally:
        running.close()
    kinds = [
        (item.type, item.detail.get("identity"), item.detail.get("verdict"))
        for item in events(paths, signer)
        if item.type.startswith("agent_")
    ]
    assert kinds == [
        ("agent_config_invalid", "off", None),
        ("agent_config_loaded", None, None),
        ("agent_identity", None, "impersonation"),
        ("agent_config_invalid", "unchanged", None),
        ("agent_identity", None, "impersonation"),
        ("agent_config_removed", None, None),
    ]
    metrics = (tmp_path / "telemetry/lurewall.prom").read_text()
    assert "lurewall_agent_impersonation_total 2" in metrics
    assert (tmp_path / "telemetry/service_failure.pending").exists()


@pytest.mark.parametrize(
    "bad",
    [
        "this is [not toml",
        "claim = 5",
        'feed = "x"',
        "[claim]\nGPTBot = 3",
        "[claim.X]\nranges = [1]",
    ],
)
def test_no_malformed_agents_file_stops_the_service(tmp_path, bad):
    now_s = 1_800_000_000
    config = tmp_path / "agents.toml"
    config.write_text(bad + "\n")
    paths, signer = make_paths(tmp_path, config)
    write(paths, [line(now_s, 1, ua="Googlebot/2.1")])
    running = run(paths, FakeClock(now_s * 1000 + 50))
    assert not running.identity.active
    items = events(paths, signer)
    (invalid,) = [i.detail for i in items if i.type == "agent_config_invalid"]
    assert invalid["identity"] == "off"
    assert cli.main(["agent-check", "--config", str(config)]) == cli.EXIT_USAGE


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_an_unreadable_agents_file_never_stops_the_detector(tmp_path):
    now_s = 1_800_000_000
    config, _, _ = google_lab(tmp_path, now_s)
    config.chmod(0)
    paths, signer = make_paths(tmp_path, config)
    clock = FakeClock(now_s * 1000 + 50)
    write(paths, [line(now_s, 1, ua="Googlebot/2.1")])
    running = service.Service(paths, clock=clock, fsync=False)
    try:
        assert running.step() == 1 and not running.identity.active
        config.chmod(0o644)  # a chmod alone (ctime) is noticed
        clock.advance(6_000)
        write(paths, [line(now_s, 6_100, ua="Googlebot/2.1")])
        running.step()
        assert running.identity.active
    finally:
        running.close()
    types = [item.type for item in events(paths, signer) if item.type.startswith("agent_")]
    assert types[:2] == ["agent_config_invalid", "agent_config_loaded"]


def test_an_observer_failure_is_recorded_and_the_reader_carries_on(tmp_path, monkeypatch):
    from lurewall import agentidentity

    now_s = 1_800_000_000
    config, _, _ = google_lab(tmp_path, now_s)
    paths, signer = make_paths(tmp_path, config)

    def broken(self, record, now_ms):
        raise RuntimeError("fixture")

    monkeypatch.setattr(agentidentity.Observer, "observe", broken)
    write(paths, [line(now_s, 1, ua="Googlebot/2.1"), line(now_s, 2, uri="/.env")])
    run(paths, FakeClock(now_s * 1000 + 50))
    items = events(paths, signer)
    (row,) = [item.detail for item in items if item.type == "agent_identity"]
    assert (row["verdict"], row["reason"], row["alert"]) == (
        "indeterminate",
        "observer_error",
        False,
    )
    assert json.loads((tmp_path / "reader.json").read_text())["offset"] > 0


def test_impersonation_keeps_per_request_evidence_and_ordinary_repeats_roll_up(tmp_path):
    now_s = 1_800_000_000
    config, _, _ = google_lab(tmp_path, now_s)
    paths, signer = make_paths(tmp_path, config)
    rows = [line(now_s, i, ua="Googlebot/2.1") for i in range(1, 4)]
    rows += [line(now_s, i, ua="Googlebot/2.1", ip="198.51.100.7") for i in range(4, 7)]
    write(paths, rows)
    running = service.Service(paths, clock=FakeClock(now_s * 1000 + 50), fsync=False)
    try:
        running.step()
    finally:
        running.close()  # writes pending roll-up counts
    items = events(paths, signer)
    spoofs = [i.detail for i in items if i.type == "agent_identity" and i.source == SOURCE]
    assert [s["request_id"] for s in spoofs] == [r["request_id"] for r in rows[:3]]
    assert all(s["range_snapshot"] for s in spoofs)
    verified = [i for i in items if i.type == "agent_identity" and i.source == "198.51.100.7"]
    assert len(verified) == 1 and verified[0].detail["reason"] == "ip_range"
    (rollup,) = [i for i in items if i.type == "rollup" and i.detail["of"] == "agent_identity"]
    assert rollup.detail["count"] == 2
    assert rollup.detail["key"].startswith("verified|Googlebot|ip_range|")
    assert len(rollup.detail["key"].split("|")[3]) == 16  # the range snapshot digest prefix
