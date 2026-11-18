# SPDX-License-Identifier: AGPL-3.0-only
"""The engine with the nftables adapter, the service, and the sweeper.

nft is a stand-in here (see fake_nft). What the real nft does is checked by
test_nft's real-backend run.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess

import pytest

import nginx_emu
import sig
from conftest import FakeClock
from fake_nft import FakeNft
from lurewall import canaries, cli, engine, service, signing
from lurewall.collector import SignalCollector
from lurewall.engine import Engine
from lurewall.engineconfig import EngineConfig, EngineConfigError
from lurewall.eventlog import EventLog, LogLockedError
from lurewall.nft import SET4, NftAdapter, NftError
from lurewall.verify import verify_log

T0 = sig.NOW
SECOND = 1000
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE
AGENT = "192.0.2.10"
OTHER = "198.51.100.20"


class Rig:
    """Collector, engine and nftables adapter over a fake nft, on one fake clock."""

    def __init__(self, *, state_path=None, clock=None, fake=None, start=True, **config) -> None:
        config.setdefault("adapter", "nftables")
        self.config = EngineConfig(**config)
        self.sink = sig.ListSink()
        self.clock = clock or FakeClock(T0)
        self.fake = fake or FakeNft(self.clock)
        self.canaries = sig.canary_set()
        self.collector = SignalCollector(sig.classifier(), self.sink)
        self.adapter = service.make_adapter(self.config, runner=self.fake, clock=self.clock)
        self.engine = Engine(
            self.config,
            self.sink,
            self.collector.tracker,
            adapter=self.adapter,
            state_path=state_path,
            clock=self.clock,
            alert=lambda _message: None,
        )
        self.report = self.engine.start() if start else None

    def send(self, uri="/", *, ip=AGENT, stale_by=0, **kwargs):
        self.clock.advance(1)
        record = sig.rec(
            uri, ip=ip, ts_ms=self.clock.now - stale_by, now_ms=self.clock.now, **kwargs
        )
        self.last = self.collector.handle(record)
        return self.engine.handle(self.last)

    def attack(self, ip=AGENT, probes=("/.env", "/.git/config"), **kwargs):
        """A counted canary hit, then two distinct probes."""
        self.send("/", ip=ip, **kwargs)
        rid = self.last.record.request_id
        self.send(self.canaries.canaries[0].reference(rid), ip=ip, **kwargs)
        decision = None
        for uri in probes:
            decision = self.send(uri, ip=ip, **kwargs)
        return decision

    def live(self) -> dict[str, int | None]:
        return (
            {
                entry.element: entry.expiry_ms
                for entry in NftAdapter(self.fake, clock=self.clock, dry_run=False).list()
            }
            if self.fake.installed
            else {}
        )


# -- a block lands, with its expiry, and ends ------------------------------------------


def test_an_enforced_block_lands_in_nftables_with_the_expiry_from_the_decision():
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    decision = rig.attack()
    assert decision.outcome == engine.BLOCK
    assert rig.live() == {AGENT: decision.expiry_ms}
    (meta,) = rig.fake.elements().values()
    assert meta["timeout"] == 300 and meta["comment"] == f"lurewall:exp={decision.expiry_ms}"
    # The same absolute time is in Lurewall's own state.
    assert rig.engine.active_blocks() == {AGENT: decision.expiry_ms}
    assert rig.sink.of("block")[0][2]["applied"] is True


def test_an_ipv6_block_is_the_slash_64():
    rig = Rig(dry_run=False)
    decision = rig.attack(ip="2001:db8:4:4::77")
    assert rig.live() == {"2001:db8:4:4::/64": decision.expiry_ms}


def test_the_engine_removes_the_entry_when_the_block_expires():
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    rig.fake.freeze_timeouts = True  # so this is the engine's doing, not the kernel's
    decision = rig.attack()
    rig.clock.now = decision.expiry_ms
    rig.engine.tick()
    assert rig.live() == {}
    assert rig.sink.of("block_expired")[0][2]["enforced"] is True


# -- dry-run stays the default ------------------------------------------------------------------


def test_nothing_is_enforced_by_default():
    rig = Rig()  # EngineConfig() as it stands, but for the adapter name
    assert rig.config.dry_run is True
    assert rig.attack().outcome == engine.WOULD_BLOCK
    assert rig.fake.calls == [] and not rig.fake.installed
    assert rig.report is None and rig.sink.of("reconcile") == []


def test_the_default_adapter_is_log_only():
    assert EngineConfig().adapter == "log-only"
    rig = Rig(dry_run=False, adapter="log-only")
    assert rig.attack().outcome == engine.WOULD_BLOCK
    assert rig.sink.of("would_block")[0][2]["reason"] == "log_only_adapter"
    assert rig.sink.of("block") == []
    assert rig.fake.calls == []


def test_enforcing_takes_both_settings():
    # dry_run = false alone blocks nothing; adapter = "nftables" alone blocks nothing.
    for config in (
        {"dry_run": True, "adapter": "nftables"},
        {"dry_run": False, "adapter": "log-only"},
    ):
        rig = Rig(**config)
        rig.attack()
        assert rig.fake.changes() == []
    both = Rig(dry_run=False, adapter="nftables")
    both.attack()
    assert both.live() != {}


def test_the_shipped_engine_config_enforces_nothing():
    from lurewall import engineconfig

    config = engineconfig.load(sig.REPO / "deploy" / "engine" / "lab.toml")
    assert config.dry_run is True and config.adapter == "log-only"
    assert isinstance(service.make_adapter(config), engine.LogOnlyAdapter)


@pytest.mark.parametrize(
    "text",
    [
        'version = 1\n[enforcement]\nadapter = "iptables"\n',
        "version = 1\n[enforcement]\nadapter = true\n",
        'version = 1\n[enforcement]\nnft_path = "nft"\n',
        'version = 1\n[enforcement]\nnft_path = "/usr/sbin/nft; reboot"\n',
        'version = 1\n[enforcement]\nnft_path = "/usr/sbin/../bin/sh -c"\n',
        'version = 1\n[enforcement]\ncommand = "/bin/sh"\n',
    ],
)
def test_bad_enforcement_config_is_refused(text):
    from lurewall import engineconfig

    with pytest.raises(EngineConfigError):
        engineconfig.parse(text)


def test_enforcement_config_is_read():
    from lurewall import engineconfig

    config = engineconfig.parse(
        "version = 1\ndry_run = false\n"
        '[enforcement]\nadapter = "nftables"\nnft_path = "/sbin/nft"\n'
    )
    assert (config.dry_run, config.adapter, config.nft_path) == (False, "nftables", "/sbin/nft")


# -- nothing enforced on stale events --------------------------------------------------------


def test_a_backlog_of_old_events_enforces_nothing():
    rig = Rig(dry_run=False)
    assert rig.attack(stale_by=6 * MINUTE) is None
    for uri in ("/admin", "/wp-login.php", "/phpmyadmin"):
        assert rig.send(uri, stale_by=6 * MINUTE) is None
    assert rig.fake.changes() in ([], [rig.fake.changes()[0]] if rig.fake.changes() else [])
    assert rig.live() == {} and rig.engine.active_blocks() == {}
    assert rig.sink.of("block") == []


# -- allowlist, log-only, cross-site: never reach nftables -------------------------------------


def test_guarded_sources_never_reach_nftables():
    rig = Rig(
        dry_run=False,
        allowlist=(ipaddress.ip_network("192.0.2.0/24"),),
        log_only=(ipaddress.ip_network("198.51.100.0/24"),),
    )
    assert rig.attack(ip=AGENT).outcome == engine.ALLOWLISTED
    assert rig.attack(ip=OTHER).outcome == engine.LOG_ONLY_RANGE
    for uri in ("/.env", "/.git/config"):
        rig.send(uri, ip="203.0.113.5", referer="https://evil.example/")
    assert rig.live() == {}


# -- adapter failures ----------------------------------------------------------------------------


def test_a_failed_block_is_logged_and_retried():
    rig = Rig(dry_run=False)
    rig.fake.fail = True
    decision = rig.attack()
    assert decision.outcome == engine.BLOCK  # the decision stands
    assert rig.sink.of("block")[0][2]["applied"] is False
    (failure,) = rig.sink.of("enforcement_failed")
    assert failure[1] == AGENT and failure[2] == {"action": "block", "error": "NftError"}
    rig.engine.tick()
    rig.engine.tick()
    assert len(rig.sink.of("enforcement_failed")) == 1  # not one line per retry

    rig.fake.fail = False
    rig.engine.tick()
    assert rig.live() == {AGENT: decision.expiry_ms}  # the original expiry, not a fresh TTL
    assert rig.sink.of("block_applied")[0][1] == AGENT
    rig.engine.tick()
    assert len(rig.sink.of("block_applied")) == 1


def test_a_block_that_never_lands_is_dropped_when_it_expires():
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    rig.fake.fail = True
    decision = rig.attack()
    rig.clock.now = decision.expiry_ms
    rig.engine.tick()
    rig.fake.fail = False
    rig.engine.tick()
    assert rig.live() == {} and rig.engine.active_blocks() == {}


def test_a_failed_unblock_is_logged_and_the_engine_carries_on():
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    decision = rig.attack()
    rig.fake.freeze_timeouts = True
    rig.fake.fail = True
    rig.clock.now = decision.expiry_ms
    rig.engine.tick()
    assert rig.engine.active_blocks() == {}
    assert rig.sink.of("enforcement_failed")[0][2]["action"] == "unblock"
    assert rig.sink.of("block_expired")
    # The entry is still there; the sweeper is what removes it.
    rig.fake.fail = False
    assert rig.live() == {AGENT: decision.expiry_ms}
    assert dict(NftAdapter(rig.fake, clock=rig.clock, dry_run=False).sweep()) == {AGENT: "expired"}


def test_a_source_the_adapter_refuses_is_logged_not_fatal():
    rig = Rig(dry_run=False)
    decision = rig.attack(ip="127.0.0.1")
    assert decision.outcome == engine.BLOCK
    assert rig.sink.of("enforcement_failed")[0][2] == {"action": "block", "error": "ValueError"}
    assert rig.live() == {}


def test_no_failure_event_holds_nfts_words():
    rig = Rig(dry_run=False)

    def angry(_args, _stdin):
        raise NftError("zzmarker: syntax error near '}; flush ruleset'")

    rig.adapter._run = angry
    rig.attack()
    assert rig.sink.of("enforcement_failed")
    assert "zzmarker" not in json.dumps(rig.sink.events)


# -- reconcile on startup: state file against the live set ----------------------------------------


def restart(rig, state, **config):
    rig.engine.close()
    return Rig(state_path=state, clock=rig.clock, fake=rig.fake, **config)


def test_startup_reconcile_restores_blocks_lost_in_a_reboot(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, ttl_ms=HOUR, state_path=state)
    first = rig.attack(ip=AGENT)
    second = rig.attack(ip="2001:db8:4:4::77")
    rig.fake.reboot()
    rig.clock.advance(10 * MINUTE)

    again = restart(rig, state, dry_run=False, ttl_ms=HOUR)
    assert again.live() == {AGENT: first.expiry_ms, "2001:db8:4:4::/64": second.expiry_ms}
    left = again.fake.elements()[AGENT]["timeout"]
    assert 49 * 60 <= left <= 50 * 60  # the time left, not a fresh hour
    assert sorted(event[1] for event in again.sink.of("block_restored")) == sorted(
        [AGENT, "2001:db8:4:4::/64"]
    )
    assert again.sink.of("reconcile")[0][2] == {"kept": 0, "removed": 0, "restored": 2}


def test_startup_reconcile_removes_live_entries_the_state_does_not_know(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, ttl_ms=HOUR, state_path=state)
    kept = rig.attack(ip=AGENT)
    rig.fake.sets[SET4]["203.0.113.66"] = {
        "timeout": 3600,
        "comment": f"lurewall:exp={rig.clock.now + HOUR}",
        "added": rig.clock.now,
    }
    rig.fake.sets[SET4]["203.0.113.67"] = {"timeout": None, "comment": None, "added": rig.clock.now}

    again = restart(rig, state, dry_run=False, ttl_ms=HOUR)
    assert again.live() == {AGENT: kept.expiry_ms}
    removed = {
        event[2]["element"]: event[2]["reason"] for event in again.sink.of("enforcement_removed")
    }
    assert removed == {"203.0.113.66": "unknown", "203.0.113.67": "unknown"}
    assert again.sink.of("reconcile")[0][2] == {"kept": 1, "removed": 2, "restored": 0}


def test_blocks_that_expired_while_the_service_was_down_are_not_restored(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE, state_path=state)
    rig.attack()
    rig.fake.freeze_timeouts = True  # the entry outlived its timeout, somehow
    rig.clock.advance(HOUR)

    again = restart(rig, state, dry_run=False, ttl_ms=5 * MINUTE)
    assert again.live() == {} and again.engine.active_blocks() == {}
    assert again.sink.of("block_expired")[0][1] == AGENT
    assert again.sink.of("block_restored") == []


def test_when_state_is_lost_startup_reconcile_empties_the_set(tmp_path):
    rig = Rig(dry_run=False, ttl_ms=HOUR, state_path=tmp_path / "engine.json")
    rig.attack()
    assert rig.live() != {}
    again = Rig(dry_run=False, clock=rig.clock, fake=rig.fake, state_path=tmp_path / "new.json")
    assert again.live() == {}
    assert again.sink.of("enforcement_removed")[0][2] == {"element": AGENT, "reason": "unknown"}


def test_a_dry_run_restart_reconciles_nothing_and_touches_nothing(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, ttl_ms=HOUR, state_path=state)
    decision = rig.attack()
    calls = len(rig.fake.calls)
    again = restart(rig, state, dry_run=True, ttl_ms=HOUR)
    assert again.report is None and len(again.fake.calls) == calls
    assert again.sink.of("reconcile") == []
    # The live entry keeps its own expiry: the kernel and the sweeper end it.
    again.fake.freeze_timeouts = False
    again.clock.now = decision.expiry_ms
    assert again.fake.elements() == {}


def test_blocks_decided_in_dry_run_are_never_put_in_place_later(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=True, ttl_ms=HOUR, state_path=state)
    assert rig.attack().outcome == engine.WOULD_BLOCK
    again = restart(rig, state, dry_run=False, ttl_ms=HOUR)
    assert again.engine.active_blocks() != {}  # still tracked as a would-be block
    assert again.live() == {}
    assert again.sink.of("block_restored") == []


def test_log_only_decisions_are_never_installed_on_switch_to_nftables(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(state_path=state, dry_run=False, adapter="log-only")
    rig.attack()

    again = restart(rig, state, dry_run=False)
    assert again.live() == {}
    assert again.sink.of("block_restored") == []


@pytest.mark.parametrize(
    ("policy", "source", "protected"),
    [("allowlist", AGENT, "192.0.2.0/24"), ("log_only", "2001:db8::11", "2001:db8::22/128")],
)
@pytest.mark.parametrize("live", [True, False])
def test_startup_reconcile_honors_current_protected_ranges(
    tmp_path, policy, source, protected, live
):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, state_path=state)
    rig.attack(ip=source)
    if not live:
        rig.fake.reboot()

    again = restart(rig, state, dry_run=False, **{policy: (ipaddress.ip_network(protected),)})

    assert again.live() == {}
    assert again.engine.active_blocks() == {}
    assert engine.read_status(state, rig.clock.now)["active_blocks"] == 0
    assert again.sink.of("block_restored") == []


def test_reconcile_retries_protected_removal_after_backend_recovers(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, state_path=state)
    decision = rig.attack()
    rig.fake.fail = True

    again = restart(rig, state, dry_run=False, allowlist=(ipaddress.ip_network(AGENT),))
    assert again.report is None
    assert again.engine.active_blocks() == {AGENT: decision.expiry_ms}
    assert engine.read_status(state, rig.clock.now)["active_blocks"] == 1

    rig.fake.fail = False
    again.engine.tick()
    assert again.live() == {}
    assert again.engine.active_blocks() == {}
    assert engine.read_status(state, rig.clock.now)["active_blocks"] == 0
    assert again.sink.of("block_restored") == []


def test_a_failed_reconcile_is_logged_and_the_blocks_are_retried(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, ttl_ms=HOUR, state_path=state)
    decision = rig.attack()
    rig.fake.reboot()
    rig.fake.fail = True
    again = restart(rig, state, dry_run=False, ttl_ms=HOUR)
    assert again.report is None
    assert again.sink.of("enforcement_failed")[0][2]["action"] == "reconcile"
    again.fake.fail = False
    again.engine.tick()
    assert again.live() == {AGENT: decision.expiry_ms}


# -- the sweeper: apart from the service ----------------------------------------------------------


@pytest.fixture
def key(tmp_path):
    path = tmp_path / "keys" / "lurewall.key"
    path.parent.mkdir()
    signing.EurekaSigner.generate(path)
    return path


def entries(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def test_the_sweeper_ends_a_block_with_the_service_stopped_and_its_state_gone(tmp_path, key):
    # Design test case 14, first half.
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE, state_path=state)
    decision = rig.attack()
    rig.engine.close()  # the main service stops
    state.unlink()  # and its state is lost
    rig.fake.freeze_timeouts = True  # and the kernel timeout does not fire

    log = tmp_path / "sweeper.log"
    rig.clock.now = decision.expiry_ms - 1
    assert service.sweep(log, key, runner=rig.fake, clock=rig.clock, fsync=False) == (0, True)
    assert rig.live() == {AGENT: decision.expiry_ms}
    assert not log.exists()  # a run with nothing to do writes nothing

    rig.clock.now = decision.expiry_ms
    assert service.sweep(log, key, runner=rig.fake, clock=rig.clock, fsync=False) == (1, True)
    assert rig.live() == {}
    (entry,) = entries(log)
    assert entry["type"] == "sweep_removed"
    assert entry["detail"] == {"element": AGENT, "reason": "expired"}
    assert verify_log(log, signing.EurekaSigner.load(key).public_key_hex).ok


def test_the_kernel_timeout_alone_ends_a_block_with_everything_stopped():
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    decision = rig.attack()
    rig.engine.close()
    rig.clock.now = decision.expiry_ms + SECOND
    assert rig.fake.elements() == {}  # no service, no sweeper


def test_the_sweeper_leaves_live_blocks_alone(tmp_path, key):
    rig = Rig(dry_run=False, ttl_ms=HOUR)
    decision = rig.attack()
    log = tmp_path / "sweeper.log"
    for _ in range(5):
        rig.clock.advance(MINUTE)
        assert service.sweep(log, key, runner=rig.fake, clock=rig.clock, fsync=False) == (0, True)
    assert rig.live() == {AGENT: decision.expiry_ms} and not log.exists()


def test_the_sweeper_does_nothing_where_nftables_was_never_set_up(tmp_path, key):
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    log = tmp_path / "sweeper.log"
    assert service.sweep(log, key, runner=fake, clock=clock, fsync=False) == (0, True)
    assert not fake.installed and fake.changes() == [] and not log.exists()


def test_a_sweeper_failure_is_logged_and_the_next_run_tries_again(tmp_path, key):
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    decision = rig.attack()
    rig.fake.freeze_timeouts = True
    rig.clock.now = decision.expiry_ms
    log = tmp_path / "sweeper.log"
    rig.fake.fail = True
    assert service.sweep(log, key, runner=rig.fake, clock=rig.clock, fsync=False) == (0, False)
    assert entries(log)[-1]["type"] == "sweep_failed"
    assert entries(log)[-1]["detail"] == {"error": "NftError"}
    rig.fake.fail = False
    assert service.sweep(log, key, runner=rig.fake, clock=rig.clock, fsync=False) == (1, True)
    assert rig.live() == {}
    assert verify_log(log, signing.EurekaSigner.load(key).public_key_hex).ok


def test_the_sweeper_signs_a_failure_for_a_malformed_set_listing(tmp_path, key):
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    NftAdapter(fake, clock=clock, dry_run=False).ensure()
    log = tmp_path / "sweeper.log"

    def runner(args, stdin):
        if args[:3] == ["-j", "list", "set"]:
            return json.dumps({"nftables": [{"set": []}]})
        return fake(args, stdin)

    assert service.sweep(log, key, runner=runner, clock=clock, fsync=False) == (0, False)
    (entry,) = entries(log)
    assert entry["type"] == "sweep_failed"
    assert verify_log(log, signing.EurekaSigner.load(key).public_key_hex).ok


def test_the_sweeper_runs_while_the_service_holds_its_own_log(tmp_path, key):
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    decision = rig.attack()
    rig.fake.freeze_timeouts = True
    rig.clock.now = decision.expiry_ms
    main_log = EventLog(tmp_path / "events.log", signing.EurekaSigner.load(key), fsync=False)
    try:
        swept = service.sweep(
            tmp_path / "sweeper.log", key, runner=rig.fake, clock=rig.clock, fsync=False
        )
        assert swept == (1, True)
        # Pointed at the service's log by mistake, it refuses rather than write into it.
        rig.adapter.block(OTHER, rig.clock.now - 0 + HOUR)
        rig.fake.sets[SET4][OTHER]["comment"] = "lurewall:exp=1"
        with pytest.raises(LogLockedError):
            service.sweep(
                tmp_path / "events.log", key, runner=rig.fake, clock=rig.clock, fsync=False
            )
    finally:
        main_log.close()


def test_the_sweep_command_exit_codes(tmp_path, key, capsys):
    fake_nft = tmp_path / "nft"
    fake_nft.write_text('#!/bin/sh\necho \'{"nftables": [{"metainfo": {}}]}\'\n')
    fake_nft.chmod(0o700)
    args = ["sweep", "--event-log", str(tmp_path / "sweeper.log"), "--key", str(key)]
    assert cli.main([*args, "--nft", str(fake_nft)]) == cli.EXIT_OK
    assert capsys.readouterr().out == ""
    assert cli.main([*args, "--nft", str(tmp_path / "missing")]) == cli.EXIT_FAIL
    assert entries(tmp_path / "sweeper.log")[-1]["type"] == "sweep_failed"
    no_key = ["sweep", "--event-log", str(tmp_path / "s.log"), "--key", str(tmp_path / "no.key")]
    assert cli.main([*no_key, "--nft", str(tmp_path / "missing")]) == cli.EXIT_USAGE


# -- the service ----------------------------------------------------------------------


@pytest.fixture
def lab(tmp_path, key):
    """Everything the service needs, in a temp directory outside any repository."""
    canary_set = sig.canary_set()
    canaries.save_state(canary_set, tmp_path / "canaries.json")
    (tmp_path / "checkpoint").mkdir()  # the directory nginx serves; the operator makes it

    def make(engine_toml="version = 1\n"):
        (tmp_path / "engine.toml").write_text(engine_toml)
        return service.Paths(
            access_log=tmp_path / "access.log",
            reader_state=tmp_path / "reader.state",
            event_log=tmp_path / "events.log",
            key=key,
            canaries=tmp_path / "canaries.json",
            signals=sig.LAB_CONFIG,
            engine_config=tmp_path / "engine.toml",
            engine_state=tmp_path / "engine.json",
            checkpoint=tmp_path / "checkpoint" / "checkpoint.json",
        )

    make.canaries = canary_set
    make.dir = tmp_path
    return make


ENFORCING = (
    'version = 1\ndry_run = false\n[block]\nttl_minutes = 5\n[enforcement]\nadapter = "nftables"\n'
)


def attack_lines(canary_set, start, ip="192.0.2.10"):
    rid = nginx_emu.request_id(("page", start, ip))
    return [
        nginx_emu.line(ts_ms=start, ip=ip, uri=b"/developers/api.html", rid=rid),
        nginx_emu.line(ts_ms=start + 1, ip=ip, uri=canary_set.canaries[0].reference(rid).encode()),
        nginx_emu.line(ts_ms=start + 2, ip=ip, uri=b"/%2eenv", status=404),
        nginx_emu.line(ts_ms=start + 3, ip=ip, uri=b"//.git/config", status=404),
    ]


def run_argv(paths) -> list[str]:
    options = {
        "--access-log": paths.access_log,
        "--reader-state": paths.reader_state,
        "--event-log": paths.event_log,
        "--key": paths.key,
        "--canaries": paths.canaries,
        "--signals": paths.signals,
        "--engine": paths.engine_config,
        "--engine-state": paths.engine_state,
    }
    return ["run", "--once", *(str(item) for pair in options.items() for item in pair)]


def types(path):
    return [entry["type"] for entry in entries(path)]


def test_the_service_blocks_restarts_reconciles_and_the_log_verifies(lab):
    paths = lab(ENFORCING)
    clock = FakeClock(T0 + 10)
    fake = FakeNft(clock)
    paths.access_log.write_bytes(b"".join(attack_lines(lab.canaries, T0)))

    running = service.Service(paths, clock=clock, runner=fake, fsync=False)
    assert running.step() == 4
    assert running.step() == 0
    (element,) = fake.elements()
    assert element == "192.0.2.10"
    running.close()

    fake.reboot()  # the container restarts: the set is gone
    clock.advance(MINUTE)
    again = service.Service(paths, clock=clock, runner=fake, fsync=False)
    assert set(fake.elements()) == {"192.0.2.10"}
    assert fake.elements()["192.0.2.10"]["timeout"] <= 4 * 60
    assert again.step() == 0  # the reader resumed where it stopped: nothing is read twice
    clock.advance(5 * MINUTE)
    again.step()
    assert fake.elements() == {}
    again.close()

    seen = types(paths.event_log)
    for expected in ("service_started", "canary_hit", "block", "service_stopped", "block_restored",
                     "reconcile", "block_expired"):  # fmt: skip
        assert expected in seen, expected
    assert seen.count("block") == 1
    assert verify_log(paths.event_log, signing.EurekaSigner.load(paths.key).public_key_hex).ok
    assert paths.checkpoint.exists()


def test_the_service_is_dry_run_with_a_minimal_config(lab):
    paths = lab("version = 1\n")
    clock = FakeClock(T0 + 10)
    fake = FakeNft(clock)
    paths.access_log.write_bytes(b"".join(attack_lines(lab.canaries, T0)))
    running = service.Service(paths, clock=clock, runner=fake, fsync=False)
    running.step()
    running.close()
    assert fake.calls == []
    seen = entries(paths.event_log)
    assert seen[0]["detail"] == {"dry_run": True, "adapter": "log-only"}
    assert "would_block" in [entry["type"] for entry in seen]
    assert "block" not in [entry["type"] for entry in seen]


def test_the_service_restarted_on_a_backlog_enforces_none_of_it(lab):
    # Design test case 14, second half.
    paths = lab(ENFORCING)
    clock = FakeClock(T0 + HOUR)  # the lines below are an hour old
    fake = FakeNft(clock)
    lines = attack_lines(lab.canaries, T0) + attack_lines(lab.canaries, T0 + 50, ip="198.51.100.9")
    paths.access_log.write_bytes(b"".join(lines))
    running = service.Service(paths, clock=clock, runner=fake, fsync=False)
    assert running.step() == 8
    running.close()
    assert fake.elements() == {}
    seen = types(paths.event_log)
    assert "block" not in seen and "would_block" not in seen
    assert "stale_backlog" in seen or "attack_signal" in seen  # logged all the same


def test_records_are_not_lost_if_the_service_dies_before_committing(lab):
    paths = lab(ENFORCING)
    clock = FakeClock(T0 + 10)
    fake = FakeNft(clock)
    paths.access_log.write_bytes(b"".join(attack_lines(lab.canaries, T0)))
    crashed = service.Service(paths, clock=clock, runner=fake, fsync=False)
    for record in crashed.reader.poll():
        crashed.engine.handle(crashed.collector.handle(record))
    crashed.events.close()  # dies here: the reader's position was never saved
    crashed.reader.close()

    again = service.Service(paths, clock=clock, runner=fake, fsync=False)
    assert again.step() == 4  # read again, not skipped
    again.close()
    assert set(fake.elements()) == {"192.0.2.10"}
    assert types(paths.event_log).count("block") <= 2  # at-least-once, never zero


@pytest.mark.parametrize(
    "breakage",
    ["engine", "signals", "canaries", "key"],
)
def test_a_broken_input_stops_the_service_before_it_writes_anything(lab, breakage, capsys):
    paths = lab("version = 1\n")
    paths.access_log.write_bytes(b"")
    bad = lab.dir / "bad"
    bad.write_text("version = 99\n")
    swapped = {
        "engine": {"engine_config": bad},
        "signals": {"signals": bad},
        "canaries": {"canaries": sig.REPO / "examples" / "canaries.example.json"},
        "key": {"key": lab.dir / "missing.key"},
    }[breakage]
    paths = service.Paths(**{**paths.__dict__, **swapped})
    argv = run_argv(paths)
    assert cli.main(argv) == cli.EXIT_USAGE
    assert "lurewall run:" in capsys.readouterr().err
    assert not paths.event_log.exists()


def test_the_run_command_processes_the_log_once_in_dry_run(lab, capsys):
    paths = lab("version = 1\n")
    now = nginx_emu.NOW_MS
    paths.access_log.write_bytes(b"".join(attack_lines(lab.canaries, now)))
    argv = run_argv(paths)
    assert cli.main(argv) == cli.EXIT_OK
    assert "dry-run" in capsys.readouterr().out
    seen = types(paths.event_log)
    assert seen[0] == "service_started" and seen[-1] == "service_stopped"
    assert "attack_signal" in seen and "block" not in seen
    # Run by the real clock, these fixture lines are stale: nothing would be enforced.
    assert "would_block" not in seen


def test_the_run_command_reports_log_only_without_dry_run(lab, capsys):
    paths = lab("version = 1\ndry_run = false\n")
    paths.access_log.write_bytes(b"")

    assert cli.main(run_argv(paths)) == cli.EXIT_OK
    assert "lurewall is running (log-only)" in capsys.readouterr().out


def test_two_services_cannot_share_one_log(lab):
    paths = lab("version = 1\n")
    paths.access_log.write_bytes(b"")
    first = service.Service(paths, fsync=False)
    try:
        with pytest.raises(LogLockedError):
            service.Service(paths, fsync=False)
    finally:
        first.close()


# -- the systemd units -----------------------------------------------------------------


def unit(name: str) -> str:
    return (sig.REPO / "deploy" / "systemd" / name).read_text()


def test_the_sweeper_has_its_own_timer_and_does_not_depend_on_the_service():
    sweeper = unit("lurewall-sweeper.service")
    timer = unit("lurewall-sweeper.timer")
    directives = [line for line in sweeper.splitlines() if line and not line.startswith("#")]
    for word in ("Requires=", "PartOf=", "BindsTo=", "After=", "Wants="):
        assert not any(line.startswith(word) for line in directives), word
    assert "lurewall sweep" in sweeper and "Type=oneshot" in sweeper
    assert "sweeper.log" in sweeper and "events.log" not in sweeper  # its own log
    assert "OnUnitActiveSec=60s" in timer and "WantedBy=timers.target" in timer


def test_the_units_run_unprivileged_with_only_the_capability_nftables_needs():
    for name in ("lurewall.service", "lurewall-sweeper.service"):
        text = unit(name)
        assert "User=lurewall" in text and "NoNewPrivileges=yes" in text
        assert "CapabilityBoundingSet=CAP_NET_ADMIN\n" in text
        assert "ProtectSystem=strict" in text
    assert "lurewall run" in unit("lurewall.service")


def test_the_units_pass_every_option_the_commands_require():
    parser = cli._build_parser()
    for name, command in (("lurewall.service", "run"), ("lurewall-sweeper.service", "sweep")):
        text = unit(name).replace("\\\n", " ")
        line = next(line for line in text.splitlines() if line.startswith("ExecStart="))
        argv = line.split()[1:]
        assert argv[0] == command
        parser.parse_args(argv)  # exits on a missing or unknown option


def test_nothing_in_the_repository_could_be_mistaken_for_engine_state():
    tracked = subprocess.run(  # noqa: S603
        [shutil.which("git"), "ls-files"], cwd=sig.REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    assert not [name for name in tracked if name.endswith(("engine.json", ".key", "sweeper.log"))]


def test_a_quiet_canary_through_the_service_blocks_once_bound_and_probed(lab):
    paths = lab(ENFORCING)
    clock = FakeClock(T0 + 10)
    fake = FakeNft(clock)
    b = next(c for c in lab.canaries.canaries if c.id == "footer_comment.quiet")
    ip = "192.0.2.10"
    paths.access_log.write_bytes(
        b"".join(
            [
                nginx_emu.line(ts_ms=T0, ip=ip, uri=b"/"),
                nginx_emu.line(
                    ts_ms=T0 + 1, ip=ip, uri=b.path.rstrip("/").upper().encode(), status=404
                ),
                nginx_emu.line(ts_ms=T0 + 2, ip=ip, uri=b"/%2eenv", status=404),
                nginx_emu.line(ts_ms=T0 + 3, ip=ip, uri=b"//.git/config", status=404),
            ]
        )
    )
    running = service.Service(paths, clock=clock, runner=fake, fsync=False)
    running.step()
    running.close()
    assert set(fake.elements()) == {ip}
    hit = next(e for e in entries(paths.event_log) if e["type"] == "canary_hit")
    assert (hit["detail"]["family"], hit["detail"]["signal"]) == ("v2-quiet", "ai")


def test_a_canary_that_collides_with_a_real_route_is_disabled_at_startup(lab, monkeypatch):
    paths = lab()
    b = next(c for c in lab.canaries.canaries if c.id == "footer_comment.quiet")
    real = service.labsite.site_routes() | {b.path + "index.html"}
    monkeypatch.setattr(service.labsite, "site_routes", lambda extra=None: real)
    clock = FakeClock(T0 + 10)
    paths.access_log.write_bytes(
        nginx_emu.line(ts_ms=T0, ip="192.0.2.10", uri=b"/")
        + nginx_emu.line(ts_ms=T0 + 1, ip="192.0.2.10", uri=b.path.encode(), status=404)
    )
    running = service.Service(paths, clock=clock, runner=FakeNft(clock), fsync=False)
    running.step()
    running.close()
    seen = entries(paths.event_log)
    disabled = [e["detail"] for e in seen if e["type"] == "canary_disabled_collision"]
    assert disabled == [{"canary": "footer_comment.quiet"}]
    assert "canary_hit" not in [e["type"] for e in seen]
