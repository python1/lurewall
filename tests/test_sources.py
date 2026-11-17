# SPDX-License-Identifier: AGPL-3.0-only
"""Per-source state: /64 keying, the two-signal threshold, bounds, shared addresses."""

from __future__ import annotations

import pytest

import sig
from lurewall import sources
from lurewall.signals import ATTACK, BEHAVIOR, RAW, Classification, Signal
from lurewall.sources import SignalTracker, source_key

CLASSIFIER = sig.classifier()
MINUTE = 60_000
T0 = sig.NOW


def tracker(**kwargs) -> SignalTracker:
    return SignalTracker(**kwargs)


def feed(table, uri="/", *, at=0, **kwargs):
    """Classify one request and hand it to the tracker. ``at`` is ms after T0."""
    record = sig.rec(uri, ts_ms=T0 + at, now_ms=T0 + at, **kwargs)
    return table.observe(record, CLASSIFIER.classify(record))


# -- source keys -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ip", "key"),
    [
        ("192.0.2.10", "192.0.2.10"),
        ("203.0.113.255", "203.0.113.255"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
        ("2001:db8:1:2::", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        ("2001:0db8:0001:0002:0000:0000:0000:0001", "2001:db8:1:2::/64"),
        ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
        ("::1", "::/64"),
        ("fe80::1", "fe80::/64"),
        ("::ffff:192.0.2.10", "192.0.2.10"),
    ],
)
def test_source_key_is_the_ipv4_address_or_the_ipv6_slash_64(ip, key):
    assert source_key(ip) == key


def test_one_slash_64_is_one_source_however_addresses_rotate():
    table = tracker()
    feed(table, "/.env", ip="2001:db8:aa:bb::1")
    view = feed(table, "/.git/config", ip="2001:db8:aa:bb:dead:beef:0:99")
    assert view.source == "2001:db8:aa:bb::/64"
    assert view.threshold_met
    assert len(table) == 1
    # 5,000 addresses of one /64 are still one row.
    for n in range(5000):
        feed(table, "/", ip=f"2001:db8:aa:bb::{n + 1:x}")
    assert len(table) == 1


def test_a_neighbouring_slash_64_is_a_different_source():
    table = tracker()
    feed(table, "/.env", ip="2001:db8:aa:bb::1")
    view = feed(table, "/.git/config", ip="2001:db8:aa:bc::1")
    assert not view.threshold_met
    assert len(table) == 2


def test_ipv4_addresses_are_never_grouped():
    table = tracker()
    feed(table, "/.env", ip="192.0.2.10")
    assert not feed(table, "/.git/config", ip="192.0.2.11").threshold_met


# -- the threshold: two distinct attack signals, never speed -------------------------


def test_two_distinct_attack_signals_meet_the_threshold():
    table = tracker()
    first = feed(table, "/.env")
    assert first.attack_keys == ("path:*/.env",) and not first.threshold_met
    second = feed(table, "/.git/config", at=1000)
    assert second.attack_keys == ("path:*/.env", "path:*/.git")
    assert second.threshold_met


# -- at least two separate requests ---------------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "/a/../.env",  # a path probe and a traversal
        "/.env/../.git/config",  # two path rules and a traversal
        "/admin?q=<script>alert(1)</script>",
        "/.env?id=1'+or+'1'='1&x=${jndi:ldap://x}",
    ],
)
def test_one_request_with_several_signals_does_not_meet_the_threshold(uri):
    table = tracker()
    view = feed(table, uri)
    assert len(view.attack_keys) >= 2
    assert view.attack_requests == 1
    assert not view.threshold_met


def test_the_same_request_read_twice_is_still_one_request():
    # Delivery is at-least-once: after a crash a line can be read again.
    table = tracker()
    record = sig.rec("/a/../.env")
    for _ in range(3):
        view = table.observe(record, CLASSIFIER.classify(record))
    assert view.attack_requests == 1 and not view.threshold_met


def test_a_second_request_completes_the_threshold():
    table = tracker()
    feed(table, "/a/../.env")
    view = feed(table, "/.env", at=10)  # nothing new, but a second request
    assert view.attack_requests == 2 and view.threshold_met


def test_the_two_requests_must_be_inside_the_window():
    table = tracker()
    feed(table, "/a/../.env")
    view = feed(table, "/", at=5)
    assert not view.threshold_met
    late = feed(table, "/b/../.git/x", at=16 * MINUTE)
    assert late.attack_requests == 1 and not late.threshold_met


def test_two_requests_with_one_signal_between_them_do_not_qualify():
    table = tracker()
    feed(table, "/.env")
    view = feed(table, "/%2eenv", at=5)
    assert view.attack_requests == 2 and view.attack_keys == ("path:*/.env",)
    assert not view.threshold_met


def test_the_request_count_per_source_is_bounded():
    table = tracker()
    view = None
    for n in range(500):
        view = feed(table, f"/.env?n={n}", at=n)
    assert view.attack_requests == sources.MAX_KEYS_PER_SOURCE


def test_cross_site_probes_are_kept_apart_and_never_counted():
    table = tracker()
    view = None
    for n, uri in enumerate(["/.env", "/.git/config", "/admin"]):
        view = feed(table, uri, at=n, referer="https://evil.example/")
    assert view.cross_site_keys == ("path:*/.env", "path:*/.git", "path:/admin")
    assert view.attack_keys == () and view.attack_requests == 0 and not view.threshold_met
    assert feed(table, "/", at=16 * MINUTE).cross_site_keys == ()


def test_forget_attack_drops_signals_but_not_the_rest():
    table = tracker()
    feed(table, "/assets/site.css")
    feed(table, "/.env")
    assert feed(table, "/.git/config").threshold_met
    table.forget_attack("192.0.2.10")
    view = table.view("192.0.2.10")
    assert view.attack_keys == () and view.attack_requests == 0 and not view.threshold_met
    assert view.normal_browsing
    table.forget_attack("198.51.100.200")  # unknown source: nothing to do
    assert not feed(table, "/admin", at=5).threshold_met


def test_one_stray_admin_request_does_not_qualify():
    assert not feed(tracker(), "/admin").threshold_met


@pytest.mark.parametrize("count", [2, 50, 2000])
def test_one_signal_repeated_never_meets_the_threshold(count):
    table = tracker()
    view = None
    for n in range(count):
        view = feed(table, "/.env", at=n)
    assert view.attack_keys == ("path:*/.env",)
    assert not view.threshold_met


def test_spelling_variants_of_one_probe_are_one_signal():
    table = tracker()
    view = None
    for n, uri in enumerate(["/.env", "/%2eenv", "//.env", "/.ENV", "/app/.env", "/.env?a=1"]):
        view = feed(table, uri, at=n)
    assert view.attack_keys == ("path:*/.env",)
    assert not view.threshold_met


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (("/.env", {}), ("/.git/config", {})),
        (("/%2eenv", {}), ("//admin", {})),
        (("/.env", {}), ("/?q=<script>alert(1)</script>", {})),
        (("/.env", {}), ("/index.html", {"method": "TRACE"})),
        (("/?id=1'+or+'1'='1", {}), ("/?x=${jndi:ldap://x}", {})),
        (("/index.html", {"method": "DELETE"}), ("/?f=../../x", {})),
    ],
)
def test_any_two_distinct_attack_signals_qualify(first, second):
    table = tracker()
    assert not feed(table, first[0], **first[1]).threshold_met
    assert feed(table, second[0], at=5, **second[1]).threshold_met


def test_speed_alone_never_meets_the_threshold():
    table = tracker()
    view = None
    # Steady, machine-like, asset-free, alphabetical, library client: every
    # behavior signal there is, hundreds of requests, and not one attack signal.
    for n in range(400):
        view = feed(
            table, f"/docs/page-{n:04d}.html", at=n * 250, ua="curl/8.5.0", lang="", status=404
        )
    kinds = {signal.kind for signal in view.behavior}
    assert {"steady_timing", "no_asset_loads", "methodical_order"} <= kinds
    assert view.attack_keys == ()
    assert not view.threshold_met


def test_speed_plus_one_attack_signal_still_does_not_qualify():
    table = tracker()
    for n in range(100):
        feed(table, f"/docs/page-{n:04d}.html", at=n * 250, ua="curl/8.5.0", lang="")
    view = feed(table, "/.env", at=100 * 250, ua="curl/8.5.0", lang="")
    assert view.behavior
    assert view.attack_keys == ("path:*/.env",)
    assert not view.threshold_met


def test_behavior_signals_handed_in_as_attack_signals_are_not_counted():
    # Even a caller that mislabels them cannot make timing or headers count.
    table = tracker()
    record = sig.rec("/")
    forged = Classification(
        cross_site=None,
        canary=None,
        attack=(
            Signal(BEHAVIOR, "steady_timing", "", RAW),
            Signal(ATTACK, "steady_timing", "", RAW),
            Signal(ATTACK, "library_user_agent", "", RAW),
            Signal(BEHAVIOR, "path", "/admin", RAW),
        ),
        behavior=(),
        suppressed=(),
        asset=False,
        browser_metadata=False,
        path="/",
    )
    view = table.observe(record, forged)
    assert view.attack_keys == () and not view.threshold_met


@pytest.mark.parametrize("threshold", [1, 0, -1, True, 2.0, None, 17])
def test_a_tracker_cannot_be_built_with_a_threshold_below_two(threshold):
    with pytest.raises(ValueError, match="threshold"):
        SignalTracker(threshold=threshold)


def test_a_raised_threshold_is_honoured():
    table = tracker(threshold=3)
    feed(table, "/.env")
    assert not feed(table, "/.git/config").threshold_met
    assert feed(table, "/admin").threshold_met


def test_cross_site_requests_count_for_nothing():
    table = tracker()
    for uri in ("/.env", "/.git/config", "/admin", "/?q=<script>"):
        view = feed(table, uri, sfs="cross-site")
        assert view.attack_keys == ()
    for uri in ("/.env", "/.git/config"):
        view = feed(table, uri, referer="https://evil.example/frame.html")
    assert view.attack_keys == () and not view.threshold_met


# -- the window ---------------------------------------------------------------------


def test_signals_must_fall_inside_one_window():
    table = tracker()
    feed(table, "/.env")
    assert feed(table, "/.git/config", at=15 * MINUTE - 1).threshold_met

    table = tracker()
    feed(table, "/.env")
    late = feed(table, "/.git/config", at=15 * MINUTE)
    assert late.attack_keys == ("path:*/.git",)
    assert not late.threshold_met


def test_a_repeat_keeps_a_signal_alive_in_the_window():
    table = tracker()
    feed(table, "/.env")
    feed(table, "/.env", at=10 * MINUTE)
    assert feed(table, "/.git/config", at=20 * MINUTE).threshold_met


def test_the_threshold_lapses_when_the_window_passes():
    table = tracker()
    feed(table, "/.env")
    feed(table, "/.git/config")
    assert feed(table, "/", at=14 * MINUTE).threshold_met
    assert not feed(table, "/", at=16 * MINUTE).threshold_met


def test_the_window_comes_from_config():
    table = tracker(window_ms=MINUTE)
    feed(table, "/.env")
    assert not feed(table, "/.git/config", at=MINUTE).threshold_met


def test_a_late_line_cannot_rewind_time_or_revive_an_old_signal():
    table = tracker()
    feed(table, "/.env")
    feed(table, "/", at=20 * MINUTE)
    # A line from the past (within the staleness limit) arrives out of order.
    late = sig.rec("/.git/config", ts_ms=T0 + 16 * MINUTE, now_ms=T0 + 20 * MINUTE)
    view = table.observe(late, CLASSIFIER.classify(late))
    assert view.attack_keys == ("path:*/.git",)
    assert not view.threshold_met


def test_stale_records_change_nothing():
    table = tracker()
    feed(table, "/.env")
    for uri in ("/.git/config", "/admin"):
        old = sig.rec(uri, ts_ms=T0 - 6 * MINUTE, now_ms=T0)
        future = sig.rec(uri, ts_ms=T0 + 60 * MINUTE, now_ms=T0)
        assert old.stale and future.stale
        for record in (old, future):
            view = table.observe(record, CLASSIFIER.classify(record))
            assert view.attack_keys == ("path:*/.env",) and not view.threshold_met
    # A backlog from a source never seen takes no row at all.
    unseen = sig.rec("/.env", ip="198.51.100.1", ts_ms=T0 - 60 * MINUTE, now_ms=T0)
    table.observe(unseen, CLASSIFIER.classify(unseen))
    assert len(table) == 1
    # And a far-future time did not move the clock: the first signal is still live.
    assert feed(table, "/.git/config", at=1000).threshold_met


# -- shared addresses: no TTL doubling beside ordinary browsing ---------------------


def test_ttl_may_double_for_a_source_showing_only_attack_traffic():
    table = tracker()
    feed(table, "/.env", ua="curl/8.5.0")
    view = feed(table, "/.git/config", ua="curl/8.5.0")
    assert view.threshold_met and not view.normal_browsing
    assert view.ttl_may_double


@pytest.mark.parametrize(
    "normal",
    [
        ("/assets/site.css", {}),
        ("/assets/logo.svg", {"status": 304}),
        ("/favicon.ico", {}),
        ("/docs/", {"sfs": "same-origin"}),
        ("/index.html", {"sfs": "none"}),
        ("/docs/setup.html", {"sfs": "same-site"}),
    ],
)
def test_no_ttl_doubling_when_the_source_also_shows_ordinary_browsing(normal):
    for order in ("before", "between", "after"):
        table = tracker()
        steps = [("/.env", {}), ("/.git/config", {})]
        steps.insert({"before": 0, "between": 1, "after": 2}[order], normal)
        view = None
        for n, (uri, kwargs) in enumerate(steps):
            view = feed(table, uri, at=n * 1000, **kwargs)
        assert view.threshold_met
        assert view.normal_browsing
        assert not view.ttl_may_double, order


def test_ordinary_browsing_must_be_inside_the_window_to_stop_doubling():
    table = tracker()
    feed(table, "/assets/site.css")
    feed(table, "/.env", at=16 * MINUTE)
    view = feed(table, "/.git/config", at=16 * MINUTE + 5)
    assert view.threshold_met and view.ttl_may_double


def test_attack_requests_dressed_as_browsing_do_not_stop_doubling():
    table = tracker()
    feed(table, "/.env", sfs="same-origin")
    feed(table, "/assets/../.git/config", sfs="same-origin")
    feed(table, "/admin/theme.css", sfs="none")
    view = feed(table, "/assets/x.css?q=<script>", status=200)
    assert view.threshold_met and view.ttl_may_double


def test_failed_asset_requests_and_plain_page_fetches_are_not_ordinary_browsing():
    table = tracker()
    feed(table, "/assets/missing.css", status=404)
    feed(table, "/index.html")
    feed(table, "/.env")
    view = feed(table, "/.git/config")
    assert view.ttl_may_double


def test_browsing_from_another_address_does_not_change_this_source():
    table = tracker()
    feed(table, "/assets/site.css", ip="192.0.2.99")
    feed(table, "/.env")
    assert feed(table, "/.git/config").ttl_may_double


def test_browsing_anywhere_in_the_slash_64_counts_for_the_slash_64():
    table = tracker()
    feed(table, "/assets/site.css", ip="2001:db8:5:5::aaaa", sfs="same-origin")
    feed(table, "/.env", ip="2001:db8:5:5::bbbb")
    view = feed(table, "/.git/config", ip="2001:db8:5:5::cccc")
    assert view.threshold_met and not view.ttl_may_double


def test_ordinary_browsing_alone_is_nothing():
    table = tracker()
    view = feed(table, "/assets/site.css", sfs="same-origin")
    assert view.normal_browsing and view.attack_keys == () and not view.threshold_met


# -- bounded state ----------------------------------------------------------------------


def test_the_table_never_grows_past_its_size_and_counts_every_drop():
    table = tracker(max_sources=100)
    for n in range(1000):
        feed(table, "/.env", ip=f"198.51.{n // 250}.{n % 250 + 1}", at=n)
        assert len(table) <= 100
    assert len(table) == 100
    assert table.take_evictions() == 900
    assert table.take_evictions() == 0


def test_the_source_idle_longest_is_dropped_first():
    table = tracker(max_sources=3)
    for n, ip in enumerate(["192.0.2.1", "192.0.2.2", "192.0.2.3"]):
        feed(table, "/.env", ip=ip, at=n)
    feed(table, "/", ip="192.0.2.1", at=10)  # .1 is active again; .2 is now idlest
    feed(table, "/.env", ip="192.0.2.4", at=11)
    assert table.take_evictions() == 1
    assert table.view("192.0.2.2").attack_keys == ()
    for ip in ("192.0.2.1", "192.0.2.3", "192.0.2.4"):
        assert table.view(ip).attack_keys == ("path:*/.env",)


def test_a_dropped_source_starts_again_from_nothing():
    table = tracker(max_sources=1)
    feed(table, "/.env", ip="192.0.2.1")
    feed(table, "/", ip="192.0.2.2", at=1)
    view = feed(table, "/.git/config", ip="192.0.2.1", at=2)
    assert view.attack_keys == ("path:*/.git",) and not view.threshold_met
    assert table.take_evictions() == 2


def test_sources_idle_for_a_whole_window_are_freed_without_counting_as_drops():
    table = tracker(max_sources=10)
    for n in range(10):
        feed(table, "/.env", ip=f"192.0.2.{n + 1}", at=n)
    feed(table, "/", ip="198.51.100.1", at=16 * MINUTE)
    assert len(table) == 1
    assert table.take_evictions() == 0


def test_each_sources_own_state_is_bounded():
    table = tracker()
    # Far more distinct rules than the per-source limit, and a long request run.
    probes = ["/.env", "/.git/x", "/.svn/x", "/.hg/x", "/admin", "/administrator", "/wp-admin",
              "/wp-content", "/wp-includes", "/phpmyadmin", "/pma", "/cgi-bin", "/actuator",
              "/.aws", "/.ssh", "/.vscode", "/solr", "/jenkins", "/wp-login.php", "/xmlrpc.php",
              "/phpinfo.php", "/server-status", "/.htpasswd", "/backup.sql"]  # fmt: skip
    view = None
    for n, uri in enumerate(probes * 20):
        view = feed(table, uri + "/" + "a" * 4000, at=n)
    state = table._sources[view.source]
    assert len(view.attack_keys) == sources.MAX_KEYS_PER_SOURCE
    assert len(state.attack) == sources.MAX_KEYS_PER_SOURCE
    assert len(state.recent) == sources.RECENT_REQUESTS
    assert all(len(path) <= 128 for _when, path, _asset in state.recent)
    assert view.threshold_met


def test_a_flood_of_sources_cannot_exhaust_memory_but_can_push_out_state():
    # Known limit, checked so it is not a surprise: at the size limit, a flood
    # of new sources drops the oldest idle ones, attack state included.
    table = tracker(max_sources=50)
    feed(table, "/.env", ip="203.0.113.5")
    for n in range(50):
        feed(table, "/", ip=f"198.51.100.{n + 1}", at=n + 1)
    assert table.view("203.0.113.5").attack_keys == ()
    assert table.take_evictions() == 1


@pytest.mark.parametrize("kwargs", [{"window_ms": 0}, {"max_sources": 0}, {"window_ms": 1.5}])
def test_bad_tracker_settings_are_refused(kwargs):
    with pytest.raises(ValueError, match="whole number"):
        SignalTracker(**kwargs)


# -- timing context ---------------------------------------------------------------------


def test_a_browsers_page_load_is_not_machine_like():
    table = tracker()
    view = None
    for n, uri in enumerate(
        [
            "/",
            "/assets/site.css",
            "/assets/logo.svg",
            "/favicon.ico",
            "/docs/",
            "/assets/site.css",
            "/docs/setup.html",
            "/assets/site.css",
            "/about.html",
            "/assets/logo.svg",
        ]
    ):
        view = feed(table, uri, at=n * 37 + (n // 3) * 9000, sfs="same-origin")
    assert view.behavior == ()


def test_irregular_spacing_is_not_steady_timing():
    table = tracker()
    view = None
    at = 0
    for n in range(12):
        at += 300 + (n * 7919) % 5000
        view = feed(table, f"/z{12 - n}.html", at=at)
    assert "steady_timing" not in {signal.kind for signal in view.behavior}
    assert "methodical_order" not in {signal.kind for signal in view.behavior}
