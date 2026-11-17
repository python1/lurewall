# SPDX-License-Identifier: AGPL-3.0-only
"""The collector: records in, signed-log events out, design test cases end to end."""

from __future__ import annotations

import json

import nginx_emu
import sig
from lurewall import accesslog
from lurewall.collector import SignalCollector
from lurewall.sources import SignalTracker
from lurewall.verify import verify_log

T0 = sig.NOW
MINUTE = 60_000


def collector(sink=None, **tracker_kwargs):
    sink = sink or sig.ListSink()
    tracker = SignalTracker(**tracker_kwargs) if tracker_kwargs else None
    return SignalCollector(sig.classifier(), sink, tracker), sink


def send(target, uri="/", *, at=0, **kwargs):
    return target.handle(sig.rec(uri, ts_ms=T0 + at, now_ms=T0 + at, **kwargs))


def test_tracker_settings_come_from_the_config():
    target, _sink = collector()
    send(target, "/.env")
    assert not send(target, "/.git/config", at=15 * MINUTE).view.threshold_met


def test_an_attack_signal_is_logged_with_no_request_text():
    target, sink = collector()
    marker = "zzmarkerzz"
    record = sig.rec(
        f"/.env/{marker}?{marker}=1", ua=marker, referer=f"https://{sig.HOST}/{marker}"
    )
    target.handle(record)
    (event,) = sink.of("attack_signal")
    assert event == (
        "attack_signal",
        "192.0.2.10",
        {
            "request_id": record.request_id,
            "line": record.line_sha256,
            "signal": "path:*/.env",
            "form": "raw",
        },
        "path:*/.env",
    )
    assert marker not in json.dumps(sink.events)


def test_ipv6_events_are_keyed_by_the_slash_64():
    target, sink = collector()
    send(target, "/.env", ip="2001:db8:9:9::1234")
    assert sink.of("attack_signal")[0][1] == "2001:db8:9:9::/64"


def test_the_threshold_event_is_written_once_when_two_distinct_signals_arrive():
    target, sink = collector()
    send(target, "/.env")
    send(target, "/%2eenv", at=1)
    send(target, "//.env", at=2)
    assert sink.of("attack_threshold_met") == []
    send(target, "/.git/config", at=3)
    send(target, "/admin", at=4)
    send(target, "/.env", at=5)
    (event,) = sink.of("attack_threshold_met")
    assert event[1] == "192.0.2.10"
    assert event[2]["signals"] == ["path:*/.env", "path:*/.git"]
    assert event[2]["normal_browsing"] is False
    assert event[3] is None  # never rolled up


def test_the_threshold_event_records_ordinary_browsing_beside_the_attack():
    target, sink = collector()
    send(target, "/assets/site.css", sfs="same-origin")
    send(target, "/.env", at=1)
    observation = send(target, "/.git/config", at=2)
    assert not observation.view.ttl_may_double
    assert sink.of("attack_threshold_met")[0][2]["normal_browsing"] is True


def test_a_scripted_scanner_logs_attack_signals_and_nothing_decides_anything():
    # Design test case 3: a wordlist scanner with no canary hit.
    target, sink = collector()
    for n, uri in enumerate(["/.env", "/.git/config", "/admin", "/wp-login.php", "/phpmyadmin"]):
        observation = send(target, uri, at=n * 100, ua="python-requests/2.32", lang="", status=404)
        assert observation.classification.canary is None
    assert len(sink.of("attack_signal")) == 5
    assert len(sink.of("attack_threshold_met")) == 1
    assert {event[0] for event in sink.events} == {
        "attack_signal",
        "attack_threshold_met",
        "behavior_signal",
    }


def test_a_human_browsing_logs_nothing():
    # Design test case 4.
    target, sink = collector()
    for n, uri in enumerate(
        ["/", "/assets/site.css", "/assets/logo.svg", "/docs/", "/favicon.ico"]
    ):
        send(target, uri, at=n * 40, sfs="same-origin" if n else "none")
    assert sink.events == []


def test_framing_through_a_browser_counts_for_nothing():
    # Design test case 8: a page elsewhere embeds a canary path and two attack
    # paths as images, and a normal browser loads them.
    target, sink = collector()
    decoy = sig.canary_set().canaries[0]
    last = None
    for n, uri in enumerate([decoy.reference("ab" * 16), "/.env", "/.git/config"]):
        last = send(target, uri, at=n, sfs="cross-site", referer="https://evil.example/frame.html")
        assert last.classification.cross_site == "sec_fetch_site"
        assert last.classification.counted_canary is None
    assert last.view.attack_keys == () and not last.view.threshold_met
    assert sink.of("attack_signal") == [] and sink.of("attack_threshold_met") == []
    events = sink.of("cross_site")
    assert [event[2]["canary"] for event in events] == [decoy.id, None, None]
    assert [event[2]["would_raise"] for event in events] == [[], ["path:*/.env"], ["path:*/.git"]]


def test_path_variants_are_logged_as_attack_signals():
    # Design test case 17.
    target, sink = collector()
    for n, uri in enumerate(["/%2eenv", "//.env", "/.ENV", "/.eNv"]):
        observation = send(target, uri, at=n)
        assert sig.keys(observation.classification.attack) == ["path:*/.env"]
    assert [event[2]["signal"] for event in sink.of("attack_signal")] == ["path:*/.env"] * 4
    assert sink.of("attack_threshold_met") == []


def test_behavior_signals_are_logged_as_context():
    target, sink = collector()
    send(target, "/docs/", ua="curl/8.5.0", lang="")
    assert sorted(event[2]["signal"] for event in sink.of("behavior_signal")) == [
        "library_user_agent",
        "no_accept_language",
    ]
    assert sink.of("attack_signal") == []


def test_stale_records_are_logged_but_change_no_state():
    target, sink = collector()
    for uri in ("/.env", "/.git/config"):
        record = sig.rec(uri, ts_ms=T0 - 10 * MINUTE, now_ms=T0)
        assert not target.handle(record).view.threshold_met
    assert [event[2]["stale"] for event in sink.of("attack_signal")] == [True, True]
    assert sink.of("attack_threshold_met") == []
    assert len(target.tracker) == 0


def test_every_drop_at_the_size_limit_is_logged():
    target, sink = collector(max_sources=5)
    for n in range(25):
        send(target, "/", ip=f"198.51.100.{n + 1}", at=n)
    assert len(target.tracker) == 5
    drops = sink.of("signal_state_evicted")
    assert len(drops) == 20
    assert all(event[1] is None and event[3] == "" for event in drops)


def test_a_flood_from_one_source_rolls_up_in_the_signed_log(make_log, clock, signer, tmp_path):
    # Design test case 15, for signals: a burst cannot grow the log one line
    # per request, and a different probe sent during the burst is still recorded.
    log = make_log(rollup_window_ms=60_000)
    target, _sink = collector(sink=log)
    for n in range(3000):
        send(target, "/.env", at=n, ua="curl/8.5.0", lang="")
        if n == 1500:
            send(target, "/.git/config", at=n, ua="curl/8.5.0", lang="")
    clock.advance(61_000)
    log.tick()
    log.close()
    path = tmp_path / "events.log"
    entries = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert len(entries) < 20
    assert verify_log(path, signer.public_key_hex).ok
    signals = [
        entry["detail"].get("signal") for entry in entries if entry["type"] == "attack_signal"
    ]
    assert sorted(signals) == ["path:*/.env", "path:*/.git"]
    assert [entry["type"] for entry in entries].count("attack_threshold_met") == 1
    rolled = sum(entry["detail"]["count"] for entry in entries if entry["type"] == "rollup")
    assert rolled >= 2999  # every repeat is counted, none written out


def test_hostile_requests_end_to_end_through_the_parser_and_the_signed_log(
    make_log, signer, tmp_path
):
    log = make_log()
    target, _sink = collector(sink=log)
    handled = 0
    for _name, raw, _decoded in nginx_emu.HOSTILE_VALUES:
        for uri in (b"/.env/" + raw, b"/?q=" + raw, b"/" + raw):
            line = nginx_emu.line(uri=uri, ua=raw, referer=raw, sec_fetch_site=raw, method=b"GET")
            parsed = accesslog.parse_line(line.rstrip(b"\n"), 0, now_ms=T0, max_age_ms=300_000)
            if isinstance(parsed, accesslog.Record):
                target.handle(parsed)
                handled += 1
    assert handled > 40
    log.close()
    assert verify_log(tmp_path / "events.log", signer.public_key_hex).ok
