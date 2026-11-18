# SPDX-License-Identifier: AGPL-3.0-only
"""The decision engine: all four rows of the decision table, and what guards a block."""

from __future__ import annotations

import ipaddress
import json
import stat
import subprocess

import pytest

import nginx_emu
import sig
from conftest import HOSTILE_STRINGS, FakeClock
from lurewall import cli, engine, engineconfig
from lurewall.collector import SignalCollector
from lurewall.engine import Engine
from lurewall.engineconfig import EngineConfig, EngineConfigError
from lurewall.eventlog import EventLog
from lurewall.logreader import LogReader
from lurewall.verify import verify_log

T0 = sig.NOW
SECOND = 1000
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE
DAY = 24 * HOUR
AGENT = "192.0.2.10"
OTHER = "198.51.100.20"
PROBES = ("/.env", "/.git/config")


class FakeAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def block(self, source, expiry_ms):
        self.calls.append(("block", source, expiry_ms))

    def unblock(self, source):
        self.calls.append(("unblock", source))


class Rig:
    """Collector plus engine on a fake clock. Every request gets its own millisecond."""

    def __init__(self, *, state_path=None, sink=None, clock=None, **config) -> None:
        self.sink = sink or sig.ListSink()
        self.clock = clock or FakeClock(T0)
        self.canaries = sig.canary_set()
        self.collector = SignalCollector(sig.classifier(), self.sink)
        self.adapter = FakeAdapter()
        self.alerts: list[str] = []
        self.engine = Engine(
            EngineConfig(**config),
            self.sink,
            self.collector.tracker,
            adapter=self.adapter,
            state_path=state_path,
            clock=self.clock,
            alert=self.alerts.append,
        )
        self.last = None

    def send(self, uri="/", *, ip=AGENT, at=None, stale_by=0, **kwargs):
        if at is not None:
            self.clock.now = T0 + at
        else:
            self.clock.advance(1)
        record = sig.rec(
            uri, ip=ip, ts_ms=self.clock.now - stale_by, now_ms=self.clock.now, **kwargs
        )
        self.last = self.collector.handle(record)
        return self.engine.handle(self.last)

    def page(self, uri="/", **kwargs) -> str:
        """Fetch a page; returns the request ID nginx stamped into it."""
        self.send(uri, **kwargs)
        return self.last.record.request_id

    def hit(self, rid=None, *, canary=0, **kwargs):
        """Request a decoy with the ID from a page (fetching one first if not given)."""
        if rid is None:
            page = {key: kwargs.pop(key) for key in ("at", "stale_by") if key in kwargs}
            rid = self.page(ip=kwargs.get("ip", AGENT), **page)
            kwargs.update({key: value for key, value in page.items() if key == "stale_by"})
        return self.send(self.canaries.canaries[canary].reference(rid), **kwargs)

    def probes(self, uris=PROBES, **kwargs):
        decision = None
        for uri in uris:
            decision = self.send(uri, **kwargs)
        return decision

    def types(self) -> list[str]:
        return [event[0] for event in self.sink.events]

    def outcomes(self) -> list[str]:
        return [event[2]["outcome"] for event in self.sink.of("decision")]


def outcome(decision):
    return None if decision is None else decision.outcome


# -- the decision table --------------------------------------------------------------


def test_row_1_no_hit_no_threshold_logs_nothing():
    # Design test case 4: a human browsing.
    rig = Rig()
    for uri in ("/", "/assets/site.css", "/docs/", "/favicon.ico", "/no-such-page.html"):
        assert rig.send(uri, sfs="same-origin") is None
    assert rig.send("/admin") is None  # one stray probe is still nothing
    assert rig.types() == ["attack_signal"]
    assert rig.engine.active_blocks() == {}


def test_row_2_hit_without_attack_is_a_content_reader_and_is_not_blocked():
    # Design test case 1: a benign agent summarizes the site.
    rig = Rig(dry_run=False)
    decision = rig.hit()
    assert outcome(decision) == engine.CONTENT_READER
    (event,) = rig.sink.of("canary_hit")
    assert event[1] == AGENT and event[2]["counted"] is True
    assert event[2]["lure"] in ("instruction", "bait")
    assert rig.outcomes() == [engine.CONTENT_READER]
    assert rig.engine.active_blocks() == {} and rig.adapter.calls == []
    assert rig.engine.has_counted_hit(AGENT)


def test_row_3_attack_without_a_hit_is_logged_and_is_not_blocked():
    # Design test case 3: a scripted wordlist scanner.
    rig = Rig(dry_run=False)
    for uri in ("/.env", "/.git/config", "/admin", "/wp-login.php", "/phpmyadmin", "/?q=<script>"):
        decision = rig.send(uri, ua="python-requests/2.32", lang="")
    assert outcome(decision) == engine.ATTACK_NO_CANARY
    assert set(rig.outcomes()) == {engine.ATTACK_NO_CANARY}
    assert rig.engine.active_blocks() == {} and rig.adapter.calls == []
    assert rig.sink.of("block") == [] and rig.sink.of("would_block") == []


def test_row_4_hit_and_threshold_blocks_and_the_block_expires():
    # Design test case 2: an agent told to audit the site for exposed files.
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    rig.hit()
    assert rig.send("/.env") is not None and rig.engine.active_blocks() == {}
    decision = rig.send("/.git/config")
    assert outcome(decision) == engine.BLOCK
    assert decision.ttl_ms == 5 * MINUTE
    assert decision.expiry_ms == rig.clock.now + 5 * MINUTE
    assert rig.adapter.calls == [("block", AGENT, decision.expiry_ms)]
    (event,) = rig.sink.of("block")
    assert event[1] == AGENT
    assert event[2]["signals"] == ["path:*/.env", "path:*/.git"]
    assert event[2]["ttl_ms"] == 5 * MINUTE and event[2]["expiry_ms"] == decision.expiry_ms
    assert event[3] is None  # a block is never rolled up
    assert rig.engine.active_blocks() == {AGENT: decision.expiry_ms}

    rig.clock.now = decision.expiry_ms - 1
    rig.engine.tick()
    assert AGENT in rig.engine.active_blocks()
    rig.clock.now = decision.expiry_ms
    rig.engine.tick()
    assert rig.engine.active_blocks() == {}
    assert rig.adapter.calls[-1] == ("unblock", AGENT)
    (expired,) = rig.sink.of("block_expired")
    assert expired[1] == AGENT and expired[2]["enforced"] is True


def test_the_order_of_evidence_does_not_matter():
    rig = Rig(dry_run=False)
    assert outcome(rig.probes()) == engine.ATTACK_NO_CANARY
    assert outcome(rig.hit()) == engine.BLOCK


def test_one_request_with_two_signals_is_not_enough_even_with_a_hit():
    rig = Rig(dry_run=False)
    rig.hit()
    assert outcome(rig.send("/a/../.env")) == engine.CONTENT_READER
    assert rig.engine.active_blocks() == {}
    assert outcome(rig.send("/b/../.env")) == engine.BLOCK


def test_repeats_of_one_probe_never_block():
    rig = Rig(dry_run=False)
    rig.hit()
    for uri in ("/.env", "/%2eenv", "//.env", "/.ENV", "/%252eenv") * 20:
        assert outcome(rig.send(uri)) == engine.CONTENT_READER
    assert rig.engine.active_blocks() == {}


def test_speed_and_behavior_signals_never_block():
    rig = Rig(dry_run=False)
    rig.hit()
    for n in range(300):
        rig.send(f"/docs/page-{n:04d}.html", ua="curl/8.5.0", lang="", status=404)
    assert rig.last.view.behavior
    assert rig.engine.active_blocks() == {} and rig.sink.of("block") == []


# -- dry-run is the default ----------------------------------------------------------


def test_dry_run_is_on_by_default_and_enforces_nothing():
    assert EngineConfig().dry_run is True
    rig = Rig(ttl_ms=5 * MINUTE)
    rig.hit()
    decision = rig.probes()
    assert outcome(decision) == engine.WOULD_BLOCK
    assert rig.adapter.calls == []
    assert rig.sink.of("block") == []
    (event,) = rig.sink.of("would_block")
    assert event[2]["reason"] == "dry_run" and event[2]["ttl_ms"] == 5 * MINUTE
    # The would-be block is tracked, so the log says once what would have happened.
    assert outcome(rig.probes(("/admin", "/wp-login.php"))) == engine.ALREADY_BLOCKED
    assert len(rig.sink.of("would_block")) == 1
    rig.clock.advance(5 * MINUTE)
    rig.engine.tick()
    (expired,) = rig.sink.of("block_expired")
    assert expired[2]["enforced"] is False
    assert rig.adapter.calls == []


def test_dry_run_traffic_during_the_would_be_block_does_not_carry_over():
    rig = Rig(ttl_ms=5 * MINUTE)
    rig.hit()
    rig.probes()
    for _ in range(30):
        rig.probes(("/admin", "/wp-login.php", "/phpmyadmin"))
    rig.clock.advance(5 * MINUTE)
    # Straight after expiry one probe is one probe, as it would be after a real block.
    assert outcome(rig.send("/.env")) == engine.CONTENT_READER
    assert len(rig.sink.of("would_block")) == 1


# -- request-ID binding ----------------------------------------------------------------


def test_a_relayed_hit_counts_for_neither_source():
    # Design test case 10: a reference served to one machine, requested from another.
    rig = Rig(dry_run=False)
    rid = rig.page(ip=AGENT)
    assert rig.hit(rid, ip=OTHER) is None
    (event,) = rig.sink.of("canary_relayed")
    assert event[1] == OTHER and event[2]["issued_to"] == AGENT
    assert rig.sink.of("canary_hit") == []
    assert not rig.engine.has_counted_hit(AGENT) and not rig.engine.has_counted_hit(OTHER)
    for ip in (AGENT, OTHER):
        assert outcome(rig.probes(ip=ip)) == engine.ATTACK_NO_CANARY
    assert rig.engine.active_blocks() == {}


def test_split_addresses_are_not_blocked():
    # Design test case 12: pages read from one address, probes from another.
    # A known limit, checked so it is stated and not assumed.
    rig = Rig(dry_run=False)
    assert outcome(rig.hit(ip=AGENT)) == engine.CONTENT_READER
    assert outcome(rig.probes(ip=OTHER)) == engine.ATTACK_NO_CANARY
    assert rig.engine.active_blocks() == {}


@pytest.mark.parametrize(
    ("query", "reason"),
    [
        ("", "no_id"),
        ("?{param}=", "no_id"),
        ("?{param}=nonsense", "no_id"),
        ("?{param}=" + "A" * 32, "no_id"),
        ("?{param}=" + "ab" * 15, "no_id"),
        ("?{param}=" + "ab" * 17, "no_id"),
        ("?other=" + "ab" * 16, "no_id"),
        ("?{param}=" + "ab" * 16, "unknown_id"),
        ("?{param}=" + "0" * 32, "unknown_id"),
    ],
)
def test_a_hit_without_an_id_issued_by_nginx_counts_for_nobody(query, reason):
    rig = Rig(dry_run=False)
    rig.page()
    canary = rig.canaries.canaries[0]
    assert rig.send(canary.path + query.format(param=canary.param)) is None
    (event,) = rig.sink.of("canary_unbound")
    assert event[2]["reason"] == reason
    assert not rig.engine.has_counted_hit(AGENT)
    assert outcome(rig.probes()) == engine.ATTACK_NO_CANARY
    assert rig.engine.active_blocks() == {}


def test_the_unstamped_placeholder_is_not_an_issued_id():
    rig = Rig()
    rig.page()
    assert rig.hit(rig.canaries.placeholder) is None
    assert rig.sink.of("canary_unbound")[0][2]["reason"] == "unknown_id"


def test_a_decoy_requests_own_id_is_never_issued():
    # A decoy body carries no reference, so its request ID binds nothing.
    rig = Rig()
    rig.hit()
    decoy_request_id = rig.last.record.request_id
    rig2_hits = len(rig.sink.of("canary_hit"))
    assert rig.hit(decoy_request_id, canary=1) is None
    assert len(rig.sink.of("canary_hit")) == rig2_hits
    assert rig.sink.of("canary_unbound")[-1][2]["reason"] == "unknown_id"


def test_an_id_is_good_for_a_day_and_no_longer():
    rig = Rig(dry_run=False)
    rid = rig.page(at=0)
    assert outcome(rig.hit(rid, at=24 * HOUR)) == engine.CONTENT_READER
    rig = Rig(dry_run=False)
    rid = rig.page(at=0)
    assert rig.hit(rid, at=24 * HOUR + 1) is None
    assert rig.sink.of("canary_unbound")[0][2]["reason"] == "expired_id"
    assert not rig.engine.has_counted_hit(AGENT)


def test_a_hit_logged_before_its_page_was_served_does_not_count():
    rig = Rig()
    rid = rig.page(at=10 * SECOND)
    assert rig.hit(rid, at=20 * SECOND, stale_by=15 * SECOND) is None
    assert rig.sink.of("canary_unbound")[0][2]["reason"] == "expired_id"


def test_ipv6_binding_is_by_slash_64():
    rig = Rig(dry_run=False)
    rid = rig.page(ip="2001:db8:7:7::1")
    assert outcome(rig.hit(rid, ip="2001:db8:7:7:aaaa:bbbb:cccc:dddd")) == engine.CONTENT_READER
    decision = rig.probes(ip="2001:db8:7:7::99")
    assert outcome(decision) == engine.BLOCK and decision.source == "2001:db8:7:7::/64"
    assert rig.adapter.calls[0][:2] == ("block", "2001:db8:7:7::/64")
    # The next /64 along is a different source: relayed.
    rid = rig.page(ip="2001:db8:7:8::1")
    assert rig.hit(rid, ip="2001:db8:7:9::1") is None
    assert rig.sink.of("canary_relayed")[0][2]["issued_to"] == "2001:db8:7:8::/64"


def test_every_placement_and_both_lure_types_are_counted_and_labelled():
    rig = Rig()
    for index, canary in enumerate(rig.canaries.canaries):
        if not canary.quiet:
            rig.hit(canary=index)
    events = rig.sink.of("canary_hit")
    v1 = [c.id for c in rig.canaries.canaries if not c.quiet]
    assert [event[2]["canary"] for event in events] == v1
    assert {event[2]["lure"] for event in events} == {"instruction", "bait"}
    assert all(event[2]["placement"] for event in events)
    assert {(e[2]["family"], e[2]["signal"]) for e in events} == {("v1-imperative", "ai")}


def test_the_first_issue_of_an_id_wins():
    # A line read twice, or an ID replayed from another address, rebinds nothing.
    rig = Rig()
    rid = rig.page(ip=AGENT)
    record = rig.last.record
    forged = sig.rec("/", ip=OTHER)
    forged = type(forged)(**{**forged.__dict__, "request_id": record.request_id})
    rig.engine.handle(rig.collector.handle(forged))
    assert outcome(rig.hit(rid, ip=AGENT)) == engine.CONTENT_READER
    assert rig.hit(rid, ip=OTHER) is None
    assert rig.sink.of("canary_relayed")[0][2]["issued_to"] == AGENT


# -- cross-site requests count for nothing ---------------------------------------------


def test_framing_through_a_browser_blocks_nobody():
    # Design test case 8: another site's page embeds a canary path and two
    # attack paths as images.
    rig = Rig(dry_run=False)
    cross = {"sfs": "cross-site", "referer": "https://evil.example/frame.html"}
    rig.send(rig.canaries.canaries[0].reference("ab" * 16), **cross)
    for uri in PROBES:
        assert rig.send(uri, **cross) is None
    assert rig.sink.of("canary_hit") == [] and rig.sink.of("decision") == []
    assert len(rig.sink.of("cross_site")) == 3
    assert rig.engine.active_blocks() == {}


def test_a_bound_hit_sent_cross_site_is_not_counted():
    rig = Rig(dry_run=False)
    rid = rig.page()
    assert rig.hit(rid, sfs="cross-site") is None
    assert rig.hit(rid, referer="https://evil.example/") is None
    assert rig.sink.of("canary_hit") == [] and not rig.engine.has_counted_hit(AGENT)


def test_a_real_content_reader_cannot_be_blocked_through_cross_site_probes():
    # The case the cross-site filter exists for: a source that really read the
    # site holds a counted hit for days. A hostile page then makes it request
    # attack paths. It must not be blocked, however many it is made to send.
    rig = Rig(dry_run=False)
    assert outcome(rig.hit()) == engine.CONTENT_READER
    decision = None
    for _ in range(100):
        for uri in ("/.env", "/.git/config", "/admin", "/wp-login.php"):
            decision = rig.send(uri, referer="https://evil.example/page.html")
    assert outcome(decision) == engine.CONTENT_READER_CROSS_SITE
    assert rig.engine.active_blocks() == {} and rig.adapter.calls == []
    assert rig.sink.of("block") == [] and rig.sink.of("would_block") == []
    named = [
        e for e in rig.sink.of("decision") if e[2]["outcome"] == engine.CONTENT_READER_CROSS_SITE
    ]
    assert named and named[-1][2]["cross_site_signals"][0] == "path:*/.env"


def test_cross_site_probes_do_not_top_up_a_real_one():
    rig = Rig(dry_run=False)
    rig.hit()
    rig.send("/.env")
    for uri in ("/.git/config", "/admin"):
        rig.send(uri, sfs="cross-site")
    assert rig.engine.active_blocks() == {}
    assert outcome(rig.send("/.git/config")) == engine.BLOCK


def test_cross_site_probes_without_a_hit_decide_nothing():
    rig = Rig()
    for uri in PROBES:
        assert rig.send(uri, sfs="cross-site") is None
    assert rig.sink.of("decision") == []


# -- the sticky hit ----------------------------------------------------------------------


def test_waiting_out_the_attack_window_does_not_help():
    # Design test case 11: probes sent 16 minutes after the hit.
    rig = Rig(dry_run=False)
    rig.hit(at=0)
    rig.send("/.env", at=16 * MINUTE)
    assert outcome(rig.send("/.git/config", at=16 * MINUTE + SECOND)) == engine.BLOCK


def test_a_hit_is_counted_for_seven_days_and_no_longer():
    rig = Rig(dry_run=False)
    rig.hit(at=0)
    hit_time = rig.clock.now - T0
    rig.send("/.env", at=hit_time + 7 * DAY - SECOND)
    assert outcome(rig.send("/.git/config", at=hit_time + 7 * DAY)) == engine.BLOCK

    rig = Rig(dry_run=False)
    rig.hit(at=0)
    hit_time = rig.clock.now - T0
    rig.send("/.env", at=hit_time + 7 * DAY)
    assert outcome(rig.send("/.git/config", at=hit_time + 7 * DAY + 1)) == engine.ATTACK_NO_CANARY
    assert rig.engine.active_blocks() == {}


def test_the_sticky_period_comes_from_config():
    rig = Rig(dry_run=False, sticky_ms=HOUR)
    rig.hit(at=0)
    rig.send("/.env", at=2 * HOUR)
    assert outcome(rig.send("/.git/config", at=2 * HOUR + 1)) == engine.ATTACK_NO_CANARY


# -- allowlist and log-only ranges ----------------------------------------------------------


def nets(*values):
    return tuple(ipaddress.ip_network(value) for value in values)


@pytest.mark.parametrize("dry_run", [True, False])
def test_an_allowlisted_source_is_logged_as_would_block_and_never_blocked(dry_run):
    # Design test case 7.
    rig = Rig(dry_run=dry_run, allowlist=nets("192.0.2.0/24"))
    rig.hit()
    assert outcome(rig.probes()) == engine.ALLOWLISTED
    (event,) = rig.sink.of("would_block")
    assert event[2]["reason"] == "allowlisted"
    assert rig.engine.active_blocks() == {} and rig.adapter.calls == []
    assert rig.sink.of("block") == []
    # Another source is still blocked as usual.
    rig.hit(ip=OTHER)
    assert outcome(rig.probes(ip=OTHER)) == (engine.WOULD_BLOCK if dry_run else engine.BLOCK)


def test_an_ipv6_source_holding_one_allowlisted_address_is_never_blocked():
    # Blocking the /64 would block the allowlisted address inside it.
    rig = Rig(dry_run=False, allowlist=nets("2001:db8:1:1::25/128"))
    rig.hit(ip="2001:db8:1:1::9")
    assert outcome(rig.probes(ip="2001:db8:1:1::9")) == engine.ALLOWLISTED
    assert rig.engine.active_blocks() == {}


@pytest.mark.parametrize("dry_run", [True, False])
def test_a_source_in_a_published_provider_range_is_log_only(dry_run):
    # Design test case 18, with a fixture range.
    rig = Rig(dry_run=dry_run, log_only=nets("192.0.2.0/28", "2001:db8:f00::/48"))
    for ip in (AGENT, "2001:db8:f00:1::5"):
        assert outcome(rig.hit(ip=ip)) == engine.CONTENT_READER
        assert outcome(rig.probes(ip=ip)) == engine.LOG_ONLY_RANGE
    assert rig.engine.active_blocks() == {} and rig.adapter.calls == []
    assert rig.sink.of("block") == [] and rig.sink.of("would_block") == []
    assert len(rig.sink.of("canary_hit")) == 2  # logged all the same


def test_the_user_agent_never_makes_a_source_log_only():
    rig = Rig(dry_run=False, log_only=nets("203.0.113.0/24"))
    rig.hit(ua="ChatGPT-User/1.0")
    assert outcome(rig.probes(ua="ChatGPT-User/1.0; PerplexityBot; ClaudeBot")) == engine.BLOCK


# -- TTL rules ---------------------------------------------------------------------------


def block_again(rig, *, browsing=False):
    """Fresh evidence after the last block ended. Returns the new decision."""
    if browsing:
        rig.send("/assets/site.css", sfs="same-origin")
    return rig.probes()


def test_the_ttl_is_24_hours_then_doubles_on_repeat_up_to_seven_days():
    rig = Rig(dry_run=False)
    rig.hit()
    seen = []
    for _ in range(6):
        decision = block_again(rig)
        assert outcome(decision) == engine.BLOCK
        seen.append(decision.ttl_ms)
        rig.clock.now = decision.expiry_ms
        rig.engine.tick()
        if not rig.engine.has_counted_hit(AGENT):
            rig.hit()
    assert seen == [24 * HOUR, 48 * HOUR, 96 * HOUR, 7 * DAY, 7 * DAY, 7 * DAY]


def test_the_ttl_does_not_double_when_the_source_also_shows_ordinary_browsing():
    # Design test case 13, second run: a shared address.
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    rig.hit()
    first = block_again(rig)
    rig.clock.now = first.expiry_ms
    second = block_again(rig, browsing=True)
    assert outcome(second) == engine.BLOCK
    assert second.ttl_ms == first.ttl_ms == 5 * MINUTE
    assert rig.sink.of("block")[-1][2]["normal_browsing"] is True
    # Without the browsing, the next repeat doubles from where it stood.
    rig.clock.now = second.expiry_ms + 16 * MINUTE
    third = block_again(rig)
    assert third.ttl_ms == 10 * MINUTE


def test_a_long_quiet_spell_resets_the_ttl():
    rig = Rig(dry_run=False, ttl_ms=HOUR, max_ttl_ms=8 * HOUR, sticky_ms=90 * DAY)
    rig.hit()
    first = block_again(rig)
    rig.clock.now = first.expiry_ms
    assert block_again(rig).ttl_ms == 2 * HOUR
    rig.clock.now += 2 * HOUR + 8 * HOUR + 1  # past the block, then past the memory
    assert block_again(rig).ttl_ms == HOUR


def test_a_new_block_needs_fresh_evidence():
    rig = Rig(dry_run=False, ttl_ms=5 * MINUTE)
    rig.hit()
    decision = rig.probes()
    rig.clock.now = decision.expiry_ms
    # The signals that caused the first block are spent, though still in the window.
    assert outcome(rig.send("/admin")) == engine.CONTENT_READER
    assert rig.engine.active_blocks() == {}
    assert outcome(rig.send("/wp-login.php")) == engine.BLOCK


def test_no_second_block_while_one_is_active():
    rig = Rig(dry_run=False)
    rig.hit()
    rig.probes()
    for _ in range(10):
        assert outcome(rig.probes(("/admin", "/wp-login.php"))) == engine.ALREADY_BLOCKED
    assert len(rig.sink.of("block")) == 1
    assert len([call for call in rig.adapter.calls if call[0] == "block"]) == 1


# -- the block cap -----------------------------------------------------------------------


def blocked_source(rig, n):
    ip = f"203.0.113.{n}"
    rig.hit(ip=ip)
    return ip, rig.probes(ip=ip)


def test_at_the_cap_new_blocks_are_refused_and_an_alert_is_raised(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(dry_run=False, cap=3, ttl_ms=HOUR, state_path=state)
    expiries = {}
    for n in range(1, 4):
        ip, decision = blocked_source(rig, n)
        assert outcome(decision) == engine.BLOCK
        expiries[ip] = decision.expiry_ms
    assert rig.alerts == [] and not rig.engine.alert_standing()

    _ip, refused = blocked_source(rig, 4)
    assert outcome(refused) == engine.CAP_REACHED
    assert rig.engine.active_blocks() == expiries  # nothing evicted early
    (event,) = rig.sink.of("cap_reached")
    assert event[1] == "203.0.113.4" and event[2]["cap"] == 3
    assert len(rig.alerts) == 1 and "cap" in rig.alerts[0]
    assert rig.engine.alert_standing()

    # More refusals: counted in the log's roll-up, but one alert, not a stream.
    for n in range(5, 15):
        assert outcome(blocked_source(rig, n)[1]) == engine.CAP_REACHED
    assert len(rig.alerts) == 1
    assert all(event[3] == "cap" for event in rig.sink.of("cap_reached"))
    assert len([call for call in rig.adapter.calls if call[0] == "block"]) == 3

    # The warning stands in status until the operator clears it.
    assert cli.main(["status", "--state", str(state)]) == cli.EXIT_FAIL
    assert cli.main(["alerts", "clear", "--state", str(state)]) == cli.EXIT_OK
    assert engine.read_ack(state) > 0
    # The command stamps the real time; this test's clock is elsewhere.
    engine.clear_alert(state, now_ms=rig.clock.now)
    assert not rig.engine.alert_standing()
    assert cli.main(["status", "--state", str(state)]) == cli.EXIT_OK

    # Room again once a block expires. A later cap episode raises a new alert.
    rig.clock.advance(HOUR)
    rig.engine.tick()
    assert rig.engine.active_blocks() == {}
    for n in range(20, 23):
        assert outcome(blocked_source(rig, n)[1]) == engine.BLOCK
    assert outcome(blocked_source(rig, 23)[1]) == engine.CAP_REACHED
    assert len(rig.alerts) == 2 and rig.engine.alert_standing()


def test_the_default_cap_is_1000():
    assert EngineConfig().cap == 1000


def test_dry_run_blocks_count_toward_the_cap_too():
    rig = Rig(cap=1)
    assert outcome(blocked_source(rig, 1)[1]) == engine.WOULD_BLOCK
    assert outcome(blocked_source(rig, 2)[1]) == engine.CAP_REACHED


def test_status_output_names_the_standing_alert(tmp_path, capsys):
    state = tmp_path / "engine.json"
    rig = Rig(cap=1, state_path=state)
    blocked_source(rig, 1)
    blocked_source(rig, 2)
    capsys.readouterr()
    assert cli.main(["status", "--state", str(state)]) == cli.EXIT_FAIL
    out = capsys.readouterr().out
    assert "WARNING" in out and "active blocks: 1 (0 enforced, 1 dry-run)" in out
    assert "203.0.113.1" in out


def test_status_without_state_and_with_damaged_state(tmp_path, capsys):
    assert cli.main(["status", "--state", str(tmp_path / "none.json")]) == cli.EXIT_OK
    bad = tmp_path / "bad.json"
    bad.write_text('{"version": 1, "hits": "\x1b[31mred"}')
    assert cli.main(["status", "--state", str(bad)]) == cli.EXIT_USAGE
    assert "\x1b" not in capsys.readouterr().err


def test_the_journal_alert_is_an_error_level_line(capsys):
    engine.journal_alert("block cap reached")
    assert capsys.readouterr().err == "<3>lurewall: block cap reached\n"


# -- stale events --------------------------------------------------------------------------


def test_a_backlog_of_old_events_is_logged_and_never_enforced():
    # Design test case 14, second half: restart with a backlog.
    rig = Rig(dry_run=False)
    old = {"stale_by": 6 * MINUTE}
    rid = rig.page(**old)
    assert rig.hit(rid, **old) is None
    for uri in ("/.env", "/.git/config", "/admin"):
        assert rig.send(uri, **old) is None
    assert rig.last.record.stale
    assert rig.sink.of("canary_hit")[0][2] == {
        **rig.sink.of("canary_hit")[0][2],
        "counted": False,
        "stale": True,
    }
    assert not rig.engine.has_counted_hit(AGENT)
    assert rig.engine.active_blocks() == {} and rig.adapter.calls == []
    assert rig.sink.of("block") == [] and rig.sink.of("decision") == []
    # Fresh requests after the backlog start from nothing.
    assert outcome(rig.send("/.env")) is None


def test_a_page_from_the_backlog_can_still_bind_a_fresh_hit():
    rig = Rig()
    rid = rig.page(stale_by=6 * MINUTE)
    assert outcome(rig.hit(rid)) == engine.CONTENT_READER


# -- bounded state --------------------------------------------------------------------------


def test_the_issued_id_table_is_bounded_and_drops_are_logged():
    rig = Rig(max_issued_ids=50, max_ids_per_source=1000)
    first = rig.page(ip="203.0.113.1")
    for n in range(100):
        rig.page(f"/docs/p{n}.html", ip="203.0.113.2")
    assert len(rig.engine._issued) == 50
    assert sum(len(ids) for ids in rig.engine._issued_by.values()) == 50
    drops = rig.sink.of("engine_state_evicted")
    assert len(drops) == 51 and all(event[2] == {"table": "issued_id"} for event in drops)
    assert rig.hit(first, ip="203.0.113.1") is None  # rotated out: fails safe


def test_one_source_cannot_push_out_another_sources_ids():
    rig = Rig(dry_run=False, max_ids_per_source=16)
    mine = rig.page(ip=AGENT)
    for n in range(5000):
        rig.page(f"/docs/p{n}.html", ip=OTHER)
    assert len(rig.engine._issued_by[source := "198.51.100.20"]) == 16, source
    assert len(rig.engine._issued) == 17
    assert rig.sink.of("engine_state_evicted") == []
    assert outcome(rig.hit(mine, ip=AGENT)) == engine.CONTENT_READER


def test_the_hit_table_is_bounded_and_drops_are_logged():
    rig = Rig(max_hit_sources=5)
    for n in range(1, 13):
        rig.hit(ip=f"203.0.113.{n}")
    assert len(rig.engine._hits) == 5
    assert not rig.engine.has_counted_hit("203.0.113.1")
    assert rig.engine.has_counted_hit("203.0.113.12")
    drops = rig.sink.of("engine_state_evicted")
    assert len(drops) == 7 and all(event[2] == {"table": "canary_hit"} for event in drops)


# -- saved state ------------------------------------------------------------------------------


def test_state_survives_a_restart(tmp_path):
    state = tmp_path / "state" / "engine.json"
    rig = Rig(dry_run=False, cap=1, ttl_ms=HOUR, state_path=state)
    _ip, decision = blocked_source(rig, 1)
    blocked_source(rig, 2)  # refused at the cap: raises the alert
    rig.hit(ip=OTHER)
    rig.engine.close()
    assert stat.S_IMODE(state.stat().st_mode) == 0o600

    again = Rig(dry_run=False, cap=1, ttl_ms=HOUR, state_path=state, clock=rig.clock)
    assert again.engine.active_blocks() == {"203.0.113.1": decision.expiry_ms}
    assert again.engine.has_counted_hit(OTHER) and again.engine.has_counted_hit("203.0.113.2")
    assert again.engine.alert_standing()
    # The restored block still expires on time, and the repeat still doubles.
    again.clock.now = decision.expiry_ms
    again.engine.tick()
    assert again.engine.active_blocks() == {}
    assert again.adapter.calls == [("unblock", "203.0.113.1")]
    assert again.probes(ip="203.0.113.1").ttl_ms == 2 * HOUR


def test_issued_ids_do_not_survive_a_restart_so_old_references_fail_safe(tmp_path):
    state = tmp_path / "engine.json"
    rig = Rig(state_path=state)
    rid = rig.page()
    rig.engine.close()
    again = Rig(state_path=state, clock=rig.clock)
    assert again.hit(rid) is None
    assert again.sink.of("canary_unbound")[0][2]["reason"] == "unknown_id"


GOOD_STATE = {
    "version": 1,
    "hits": {"192.0.2.10": [T0, "api_doc.bait"]},
    "blocks": {"2001:db8:1:2::/64": [T0, T0 + HOUR, HOUR, True]},
    "history": {"2001:db8:1:2::/64": [HOUR, T0 + HOUR]},
    "alert_raised": None,
}


def test_well_formed_state_parses():
    state = engine.parse_state(json.dumps(GOOD_STATE).encode())
    assert state["hits"] == {"192.0.2.10": (T0, "api_doc.bait")}
    assert state["blocks"]["2001:db8:1:2::/64"].enforced is True


@pytest.mark.parametrize(
    "change",
    [
        {"version": 2},
        {"version": True},
        {"extra": 1},
        {"hits": []},
        {"hits": {"192.0.2.10": [T0]}},
        {"hits": {"192.0.2.10": [-1, "x"]}},
        {"hits": {"192.0.2.10": [1.5, "x"]}},
        {"hits": {"192.0.2.10": [T0, 7]}},
        {"hits": {"not-an-address": [T0, "x"]}},
        {"hits": {"192.0.2.0/24": [T0, "x"]}},
        {"hits": {"192.0.2.10/32": [T0, "x"]}},
        {"hits": {"2001:db8:1:2::1": [T0, "x"]}},
        {"hits": {"2001:db8:1:2::/48": [T0, "x"]}},
        {"hits": {"2001:0db8:1:2::/64": [T0, "x"]}},
        {"blocks": {"192.0.2.10": [T0, T0, HOUR]}},
        {"blocks": {"192.0.2.10": [T0, T0, HOUR, 1]}},
        {"blocks": {"192.0.2.10": [T0, "soon", HOUR, True]}},
        {"blocks": {"192.0.2.10": [T0, 2**60, HOUR, True]}},
        {"history": {"192.0.2.10": [HOUR]}},
        {"history": {"192.0.2.10": [True, T0]}},
        {"alert_raised": "yes"},
        {"alert_raised": -5},
    ],
)
def test_damaged_state_is_refused_whole(change, tmp_path):
    doc = {**GOOD_STATE, **change}
    with pytest.raises(ValueError):  # any ValueError means "refused"
        engine.parse_state(json.dumps(doc).encode())
    state = tmp_path / "engine.json"
    state.write_text(json.dumps(doc))
    rig = Rig(state_path=state)
    assert rig.sink.of("engine_state_invalid") == [
        ("engine_state_invalid", None, {"reason": "malformed"}, None)
    ]
    assert rig.engine.active_blocks() == {} and not rig.engine.has_counted_hit(AGENT)


@pytest.mark.parametrize(
    "raw", [b"", b"{", b"[]", b"null", b"\xff\xfe", b"[" * 100_000, b'{"version":NaN}']
)
def test_state_that_is_not_the_expected_json_is_refused(raw, tmp_path):
    with pytest.raises(ValueError):
        engine.parse_state(raw)
    state = tmp_path / "engine.json"
    state.write_bytes(raw)
    assert len(Rig(state_path=state).sink.of("engine_state_invalid")) == 1


def test_engine_state_is_refused_inside_a_git_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # noqa: S603, S607
    with pytest.raises(ValueError, match="git repository"):
        Rig(state_path=repo / "engine.json")


def test_the_ack_file_must_hold_a_time(tmp_path):
    state = tmp_path / "engine.json"
    assert engine.read_ack(state) == -1
    for text in ("", "soon", "-4", "9" * 30, "\x00\x00"):
        engine.ack_path(state).write_text(text)
        assert engine.read_ack(state) == -1
    engine.clear_alert(state, now_ms=T0)
    assert engine.read_ack(state) == T0
    assert stat.S_IMODE(engine.ack_path(state).stat().st_mode) == 0o600


# -- what the log holds ----------------------------------------------------------------------


def test_no_engine_event_holds_text_from_a_request():
    rig = Rig(dry_run=False)
    marker = "zzmarkerzz"
    rid = rig.page(f"/{marker}", ua=marker)
    canary = rig.canaries.canaries[0]
    rig.send(f"{canary.reference(rid)}&{marker}=1", ua=marker)
    rig.send(f"/.env/{marker}", ua=marker)
    rig.send(f"/.git/{marker}?{marker}", ua=marker, lang=marker)
    assert rig.sink.of("block")
    assert marker not in json.dumps(rig.sink.events)


@pytest.mark.parametrize("text", HOSTILE_STRINGS)
def test_hostile_text_on_a_decoy_request_never_raises(text):
    rig = Rig()
    rid = rig.page()
    canary = rig.canaries.canaries[0]
    for uri in (
        canary.path + "?" + canary.param + "=" + text,
        canary.reference(rid) + "&x=" + text,
        canary.path + "?" + text,
    ):
        rig.send(uri, ua=text, referer=text, sfs=text, lang=text)
    assert rig.sink.of("block") == []


def test_the_whole_path_from_access_log_to_signed_decisions(tmp_path, signer):
    # nginx's log file -> reader -> collector -> engine -> signed log -> verify.
    canaries = sig.canary_set()
    access = tmp_path / "access.log"
    page_rid = nginx_emu.request_id("page")
    lines = [
        nginx_emu.line(ts_ms=T0, uri=b"/developers/api.html", rid=page_rid),
        nginx_emu.line(ts_ms=T0 + 1, uri=canaries.canaries[0].reference(page_rid).encode()),
        nginx_emu.line(ts_ms=T0 + 2, uri=b"/%2eenv", ua=b'curl/8 "\xff\xfe'),
        b"this line is not JSON\n",
        nginx_emu.line(ts_ms=T0 + 3, uri=b"//.git/config", status=404),
        nginx_emu.line(ts_ms=T0 + 4, uri=b"/", ip="198.51.100.77"),
    ]
    access.write_bytes(b"".join(lines))
    clock = FakeClock(T0 + 10)
    events = EventLog(tmp_path / "events.log", signer, fsync=False, clock=clock)
    reader = LogReader(access, tmp_path / "reader.state", events, clock=clock)
    collector = SignalCollector(sig.classifier(), events)
    decisions = Engine(
        EngineConfig(dry_run=False, ttl_ms=5 * MINUTE),
        events,
        collector.tracker,
        adapter=(adapter := FakeAdapter()),
        state_path=tmp_path / "engine.json",
        clock=clock,
    )
    found = []
    while batch := reader.poll():
        found += [decisions.handle(collector.handle(record)) for record in batch]
    clock.advance(5 * MINUTE)
    decisions.tick()
    decisions.close()
    reader.close()
    events.close()

    assert [outcome(d) for d in found] == [None, "content_reader", "content_reader", "block", None]
    assert [call[0] for call in adapter.calls] == ["block", "unblock"]
    entries = [json.loads(line) for line in (tmp_path / "events.log").read_bytes().splitlines()]
    types = [entry["type"] for entry in entries]
    for expected in ("canary_hit", "attack_signal", "parse_failure", "block", "block_expired"):
        assert expected in types, expected
    assert verify_log(tmp_path / "events.log", signer.public_key_hex).ok


# -- config -------------------------------------------------------------------------------


def test_the_shipped_engine_config_is_dry_run_with_the_documented_defaults():
    config = engineconfig.load(sig.REPO / "deploy" / "engine" / "lab.toml")
    assert config == EngineConfig()
    assert config.dry_run is True
    assert (config.sticky_ms, config.ttl_ms, config.max_ttl_ms) == (7 * DAY, 24 * HOUR, 7 * DAY)
    assert config.cap == 1000


def test_dry_run_stays_on_unless_the_file_turns_it_off():
    assert engineconfig.parse("version = 1\n").dry_run is True
    assert engineconfig.parse("version = 1\ndry_run = false\n").dry_run is False


def test_config_values_are_read():
    config = engineconfig.parse(
        "version = 1\ndry_run = false\n[canary]\nsticky_days = 3\nid_ttl_hours = 2\n"
        "[block]\nttl_minutes = 5\nmax_ttl_minutes = 40\ncap = 7\n"
        '[sources]\nallowlist = ["192.0.2.0/24", "2001:db8::1"]\n'
        'log_only_ranges = ["203.0.113.0/24"]\n'
        "[limits]\nmax_hit_sources = 9\nmax_issued_ids = 8\nmax_ids_per_source = 2\n"
    )
    assert (config.sticky_ms, config.id_ttl_ms) == (3 * DAY, 2 * HOUR)
    assert (config.ttl_ms, config.max_ttl_ms, config.cap) == (5 * MINUTE, 40 * MINUTE, 7)
    assert config.allowlist == nets("192.0.2.0/24", "2001:db8::1/128")
    assert config.log_only == nets("203.0.113.0/24")
    assert (config.max_hit_sources, config.max_issued_ids, config.max_ids_per_source) == (9, 8, 2)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "version = 2\n",
        "version = 1\nsurprise = 1\n",
        'version = 1\ndry_run = "no"\n',
        "version = 1\ndry_run = 0\n",
        "version = 1\n[block]\nttl_minutes = 0\n",
        "version = 1\n[block]\nttl_minutes = 1.5\n",
        "version = 1\n[block]\ncap = 0\n",
        "version = 1\n[block]\ncap = 100000\n",
        "version = 1\n[block]\nttl_minutes = 60\nmax_ttl_minutes = 30\n",
        "version = 1\n[block]\nforever = true\n",
        "version = 1\n[canary]\nsticky_days = 0\n",
        'version = 1\n[sources]\nallowlist = "192.0.2.1"\n',
        'version = 1\n[sources]\nallowlist = ["192.0.2.1/24"]\n',
        'version = 1\n[sources]\nallowlist = ["example.org"]\n',
        "version = 1\n[sources]\nlog_only_ranges = [1]\n",
        'version = 1\n[sources]\nuser_agents = ["GPTBot"]\n',
        "version = 1\n[limits]\nmax_issued_ids = 0\n",
        "not toml [",
    ],
)
def test_malformed_engine_config_is_refused(text):
    with pytest.raises(EngineConfigError):
        engineconfig.parse(text)


def test_a_config_built_in_code_is_held_to_the_same_rules():
    for bad in (
        {"dry_run": 0},
        {"cap": 0},
        {"ttl_ms": 2 * HOUR, "max_ttl_ms": HOUR},
        {"sticky_ms": 1.5},
    ):
        with pytest.raises(EngineConfigError):
            EngineConfig(**bad)
    with pytest.raises(EngineConfigError, match="cannot read"):
        engineconfig.load("/nonexistent/engine.toml")
    with pytest.raises(EngineConfigError, match="UTF-8"):
        engineconfig.parse(b"\xff")


# -- v2 quiet canaries: bound by the page that carried them ----------------------------


def quiet_index(rig, canary_id):
    return next(i for i, c in enumerate(rig.canaries.canaries) if c.id == canary_id)


def quiet_hit(rig, canary_id, carrier, *, served=True, ip=AGENT, method="GET", **kwargs):
    if served:
        rig.send(carrier, ip=ip)
    canary = rig.canaries.canaries[quiet_index(rig, canary_id)]
    return rig.send(canary.path, ip=ip, method=method, status=404, **kwargs)


def test_canary_b_counts_after_its_page_was_served_and_blocks_with_probes():
    rig = Rig()
    assert outcome(quiet_hit(rig, "footer_comment.quiet", "/")) == engine.CONTENT_READER
    hit = rig.sink.of("canary_hit")[-1][2]
    assert (hit["family"], hit["signal"], hit["counted"]) == ("v2-quiet", "ai", True)
    assert outcome(rig.probes()) == engine.WOULD_BLOCK
    detail = rig.sink.of("would_block")[-1][2]
    assert (detail["canary_family"], detail["canary_signal"]) == ("v2-quiet", "ai")


def test_canary_a_counts_but_is_labelled_recon():
    rig = Rig()
    assert outcome(quiet_hit(rig, "robots_disallow.quiet", "/robots.txt")) == engine.CONTENT_READER
    assert rig.sink.of("canary_hit")[-1][2]["signal"] == "recon"
    assert outcome(rig.probes()) == engine.WOULD_BLOCK
    assert rig.sink.of("would_block")[-1][2]["canary_signal"] == "recon"


def test_canary_c_is_logged_and_never_counted():
    rig = Rig()
    assert quiet_hit(rig, "security_txt.quiet", "/.well-known/security.txt") is None
    hit = rig.sink.of("canary_hit")[-1][2]
    assert (hit["signal"], hit["counted"]) == ("research", False)
    assert rig.outcomes()[-1] == engine.RESEARCH_LOG_ONLY
    assert outcome(rig.probes()) != engine.WOULD_BLOCK  # probes alone never block


def test_a_quiet_hit_without_its_page_counts_for_nobody():
    rig = Rig()
    assert quiet_hit(rig, "footer_comment.quiet", "/", served=False) is None
    assert rig.sink.of("canary_unbound")[-1][2]["reason"] == "not_served"
    # Served to one address, followed from another: still nothing.
    rig.send("/", ip=AGENT)
    assert quiet_hit(rig, "footer_comment.quiet", "/", served=False, ip=OTHER) is None
    # The carrier of A does not bind B.
    assert quiet_hit(rig, "footer_comment.quiet", "/robots.txt", ip=OTHER) is None
    assert rig.sink.of("canary_hit") == []


def test_a_quiet_binding_expires_after_the_id_ttl():
    rig = Rig()
    rig.send("/", ip=AGENT, at=0)
    day = engineconfig.EngineConfig().id_ttl_ms
    canary = rig.canaries.canaries[quiet_index(rig, "footer_comment.quiet")]
    assert rig.send(canary.path, ip=AGENT, at=day + 1, status=404) is None
    assert rig.sink.of("canary_unbound")[-1][2]["reason"] == "expired_served"


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS"])
def test_a_quiet_decoy_counts_for_get_and_head_only(method):
    rig = Rig()
    assert quiet_hit(rig, "footer_comment.quiet", "/", method=method) is None
    assert rig.sink.of("canary_hit") == []
    rig2 = Rig()
    assert outcome(quiet_hit(rig2, "footer_comment.quiet", "/", method="HEAD")) == (
        engine.CONTENT_READER
    )


def test_a_cross_site_carrier_binds_nothing():
    rig = Rig()
    rig.send("/", ip=AGENT, sfs="cross-site", referer="https://evil.example/x.html")
    canary = rig.canaries.canaries[quiet_index(rig, "footer_comment.quiet")]
    assert rig.send(canary.path, ip=AGENT, status=404) is None
    assert rig.sink.of("canary_hit") == []


def test_the_served_table_is_bounded():
    rig = Rig(max_issued_ids=3)
    for n in range(5):
        rig.send("/", ip=f"198.51.100.{n}")
    assert any(e[2] == {"table": "served"} for e in rig.sink.of("engine_state_evicted"))
