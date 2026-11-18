# SPDX-License-Identifier: AGPL-3.0-only
"""The nftables adapter.

Most tests here run twice: against a stand-in for ``nft``, and against the
real one. The real run needs root and happens in CI inside a private network
namespace (``sudo unshare --net``), so no host firewall is ever touched. It is
skipped elsewhere, unless LUREWALL_REQUIRE_NFT=1 says a skip would hide a
missing dependency.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
import time

import pytest

from conftest import FakeClock
from fake_nft import FakeNft
from lurewall import nft
from lurewall.nft import SET4, SET6, NftAdapter, NftError

REAL_NFT = shutil.which("nft") or next(
    (path for path in ("/usr/sbin/nft", "/sbin/nft") if os.path.exists(path)), None
)
REQUIRED = os.environ.get("LUREWALL_REQUIRE_NFT") == "1"
T0 = 1_800_000_000_000
SECOND = 1000
HOUR = 3_600_000
V4 = "192.0.2.10"
V6 = "2001:db8:1:2::/64"


class Env:
    """One backend: the runner, a clock the adapter shares, and a way to pass time."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        if kind == "fake":
            self.clock = FakeClock(T0)
            self.runner = self.fake = FakeNft(self.clock)
        else:
            self.clock = lambda: time.time_ns() // 1_000_000
            self.runner = nft.system_runner(REAL_NFT)
            self.fake = None

    def adapter(self, **kwargs) -> NftAdapter:
        kwargs.setdefault("dry_run", False)
        return NftAdapter(self.runner, clock=self.clock, **kwargs)

    def now(self) -> int:
        return self.clock()

    def wait(self, ms: int) -> None:
        if self.fake is not None:
            self.clock.advance(ms)
        else:
            time.sleep(ms / 1000)

    def raw(self, *lines: str) -> None:
        self.runner(["-f", "-"], "\n".join(lines) + "\n")

    def add(self, set_name: str, element: str, *, timeout_s=None, comment=None) -> None:
        """Put an element in place by hand, as something other than Lurewall might."""
        parts = [element]
        if timeout_s is not None:
            parts.append(f"timeout {timeout_s}s")
        if comment is not None:
            parts.append(f'comment "{comment}"')
        self.raw(f"add element inet lurewall {set_name} {{ {' '.join(parts)} }}")

    def reboot(self) -> None:
        if self.fake is not None:
            self.fake.reboot()
        else:
            self.raw("delete table inet lurewall")

    def drop_rules(self) -> list[str]:
        if self.fake is not None:
            return self.fake.rules
        text = self.runner(["list", "chain", "inet", "lurewall", "input"], None)
        return [line.strip() for line in text.splitlines() if "drop" in line]

    def live(self, adapter) -> dict[str, int | None]:
        return {entry.element: entry.expiry_ms for entry in adapter.list()}


@pytest.fixture(params=["fake", "real"])
def env(request):
    if request.param == "real":
        usable = REAL_NFT is not None and hasattr(os, "geteuid") and os.geteuid() == 0
        if not usable:
            if REQUIRED:
                pytest.fail("LUREWALL_REQUIRE_NFT=1 but nft is missing or this is not root")
            pytest.skip("needs root and nft, in a private network namespace")
    made = Env(request.param)
    yield made
    if request.param == "real":
        # The test may never have created it, or already removed it.
        with contextlib.suppress(NftError):
            made.raw("delete table inet lurewall")


# -- setting up the ruleset -------------------------------------------------------------


def test_ensure_creates_the_table_once_and_is_safe_to_repeat(env):
    adapter = env.adapter()
    assert adapter.installed() is False
    adapter.ensure()
    assert adapter.installed() is True
    adapter.block(V4, env.now() + HOUR)
    # A second process (a restart) sets up again: one pair of rules, entries kept.
    env.adapter().ensure()
    env.adapter().ensure()
    rules = env.drop_rules()
    assert len(rules) == 2
    assert any("@blocked4" in rule for rule in rules) and any("@blocked6" in rule for rule in rules)
    assert set(env.live(adapter)) == {V4}


# -- block, unblock, list --------------------------------------------------------------------


def test_a_block_is_stored_with_its_expiry_twice(env):
    adapter = env.adapter()
    expiry4, expiry6 = env.now() + HOUR, env.now() + 2 * HOUR
    adapter.block(V4, expiry4)
    adapter.block(V6, expiry6)
    entries = {entry.source: entry for entry in adapter.list()}
    assert set(entries) == {V4, V6}
    assert (entries[V4].set_name, entries[V6].set_name) == (SET4, SET6)
    # The absolute time, in the entry's comment ...
    assert entries[V4].expiry_ms == expiry4 and entries[V6].expiry_ms == expiry6
    # ... and the kernel's own countdown, never shorter than asked.
    assert 3590 <= entries[V4].kernel_expires_s <= 3600
    assert 7190 <= entries[V6].kernel_expires_s <= 7200


def test_blocking_again_replaces_the_entry_and_its_expiry(env):
    adapter = env.adapter()
    adapter.block(V4, env.now() + HOUR)
    later = env.now() + 3 * HOUR
    adapter.block(V4, later)
    (entry,) = adapter.list()
    assert entry.expiry_ms == later
    assert entry.kernel_expires_s > 2 * 3600


def test_unblock_removes_the_entry_and_is_safe_when_there_is_none(env):
    adapter = env.adapter()
    adapter.unblock(V4)  # nothing there, and no table yet
    adapter.block(V4, env.now() + HOUR)
    adapter.block(V6, env.now() + HOUR)
    adapter.unblock(V4)
    assert set(env.live(adapter)) == {V6}
    adapter.unblock(V4)
    adapter.unblock(V6)
    assert adapter.list() == []


def test_the_kernel_expires_an_entry_with_nothing_running(env):
    adapter = env.adapter()
    adapter.block(V4, env.now() + 1200)
    adapter.block(V6, env.now() + HOUR)
    assert set(env.live(adapter)) == {V4, V6}
    env.wait(3200)  # no adapter call, no sweeper: the timeout alone
    assert set(env.live(adapter)) == {V6}


def test_a_block_already_past_due_is_not_added(env):
    adapter = env.adapter()
    adapter.ensure()
    adapter.block(V4, env.now() - 1)
    adapter.block(V6, env.now())
    assert adapter.list() == []


def test_many_blocks_of_both_families(env):
    adapter = env.adapter()
    wanted = {f"198.51.100.{n}": env.now() + HOUR + n for n in range(1, 41)}
    wanted |= {f"2001:db8:0:{n:x}::/64": env.now() + HOUR + n for n in range(1, 41)}
    for source, expiry in wanted.items():
        adapter.block(source, expiry)
    assert {entry.source: entry.expiry_ms for entry in adapter.list()} == wanted


# -- reconcile on startup ------------------------------------------------------------------


def test_reconcile_removes_what_is_expired_or_unknown_and_keeps_the_rest(env):
    adapter = env.adapter()
    now = env.now()
    keep, mismatch, gone = now + HOUR, now + 2 * HOUR, now - 5 * SECOND
    adapter.block(V4, keep)
    adapter.block(V6, now + 3 * HOUR)  # the state file says something else
    env.add(SET4, "192.0.2.77", timeout_s=3600, comment=f"lurewall:exp={now + HOUR}")  # unknown
    env.add(SET4, "192.0.2.78", timeout_s=3600)  # no expiry at all
    env.add(SET4, "192.0.2.79")  # no timeout, no comment
    env.add(SET4, "192.0.2.80", timeout_s=3600, comment=f"lurewall:exp={gone}")  # past due
    env.add(SET6, "2001:db8:9::/48", timeout_s=3600, comment=f"lurewall:exp={now + HOUR}")
    env.add(SET4, "192.0.2.81", timeout_s=3600, comment="someone else's note")

    wanted = {V4: keep, V6: mismatch, "192.0.2.80": gone, "192.0.2.81": now + HOUR}
    report = adapter.reconcile(wanted)

    assert report.kept == 1
    assert dict(report.removed) == {
        V6: "expiry_mismatch",
        "192.0.2.77": "unknown",
        "192.0.2.78": "unknown",
        "192.0.2.79": "unknown",
        "192.0.2.80": "expired",
        "2001:db8:9::/48": "unknown_shape",
        "192.0.2.81": "no_expiry",
    }
    assert sorted(report.restored) == sorted(["192.0.2.81", V6])
    assert env.live(adapter) == {V4: keep, V6: mismatch, "192.0.2.81": now + HOUR}
    # A second reconcile finds nothing to do.
    again = adapter.reconcile(wanted)
    assert (again.kept, again.removed, again.restored) == (3, [], [])


def test_reconcile_restores_blocks_after_a_reboot_with_the_time_they_have_left(env):
    adapter = env.adapter()
    wanted = {V4: env.now() + HOUR, V6: env.now() + 2 * HOUR, "192.0.2.99": env.now() - 1}
    adapter.block(V4, wanted[V4])
    adapter.block(V6, wanted[V6])
    env.reboot()  # nftables sets live in memory only
    env.wait(2000)

    fresh = env.adapter()
    assert fresh.installed() is False
    report = fresh.reconcile(wanted)
    assert sorted(report.restored) == sorted([V4, V6]) and report.removed == []
    entries = {entry.source: entry for entry in fresh.list()}
    assert {source: entry.expiry_ms for source, entry in entries.items()} == {
        V4: wanted[V4],
        V6: wanted[V6],
    }
    # Time left, not a fresh TTL.
    assert 3590 <= entries[V4].kernel_expires_s <= 3598
    assert len(env.drop_rules()) == 2


def test_reconcile_with_nothing_wanted_empties_the_sets(env):
    adapter = env.adapter()
    adapter.block(V4, env.now() + HOUR)
    adapter.block(V6, env.now() + HOUR)
    report = adapter.reconcile({})
    assert dict(report.removed) == {V4: "unknown", V6: "unknown"}
    assert adapter.list() == []


# -- the sweeper -------------------------------------------------------------------------------


def test_sweep_removes_what_is_past_due_or_cannot_show_when_it_is_due(env):
    adapter = env.adapter()
    now = env.now()
    adapter.block(V4, now + HOUR)
    adapter.block(V6, now + HOUR)
    # Entries whose kernel timeout has not fired, for whatever reason.
    env.add(SET4, "192.0.2.80", timeout_s=3600, comment=f"lurewall:exp={now - 1}")
    env.add(SET6, "2001:db8:5:5::/64", timeout_s=3600, comment=f"lurewall:exp={now - HOUR}")
    env.add(SET4, "192.0.2.78", timeout_s=3600)
    env.add(SET4, "192.0.2.79")
    env.add(SET4, "192.0.2.82", comment=f"lurewall:exp={now + 400 * 24 * HOUR}")
    env.add(SET4, "192.0.2.83", comment="lurewall:exp=soon")
    env.add(SET6, "2001:db8:9::/48", timeout_s=3600, comment=f"lurewall:exp={now + HOUR}")

    # A brand-new adapter with no state: the sweeper knows only the live entries.
    removed = env.adapter().sweep()
    assert dict(removed) == {
        "192.0.2.80": "expired",
        "2001:db8:5:5::/64": "expired",
        "192.0.2.78": "no_expiry",
        "192.0.2.79": "no_expiry",
        "192.0.2.82": "bad_expiry",
        "192.0.2.83": "no_expiry",
        "2001:db8:9::/48": "unknown_shape",
    }
    assert env.live(adapter) == {V4: now + HOUR, V6: now + HOUR}
    assert env.adapter().sweep() == []


def test_sweep_does_nothing_where_lurewall_was_never_set_up(env):
    adapter = env.adapter()
    assert adapter.sweep() == []
    assert adapter.installed() is False  # and it did not create anything


# -- dry-run -----------------------------------------------------------------------------------


def test_the_adapter_is_dry_run_unless_told_otherwise():
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    adapter = NftAdapter(fake, clock=clock)
    assert adapter.dry_run is True


def test_a_dry_run_adapter_touches_nothing(env):
    adapter = env.adapter(dry_run=True)
    adapter.ensure()
    adapter.block(V4, env.now() + HOUR)
    adapter.unblock(V4)
    assert adapter.list() == []
    report = adapter.reconcile({V4: env.now() + HOUR})
    assert (report.kept, report.removed, report.restored) == (0, [], [])
    assert adapter.sweep() == []
    assert env.adapter().installed() is False
    if env.fake is not None:
        assert env.fake.calls == [(["-j", "list", "tables"], None)]  # only this test's own check


# -- only addresses reach nft -----------------------------------------------------------------

BAD_SOURCES = [
    "192.0.2.0/24",
    "192.0.2.10/32",
    "192.0.2.010",
    "2001:db8::1",
    "2001:db8::/48",
    "2001:db8:1:2::/65",
    "2001:0db8:1:2::/64",
    "2001:db8:1:2::1/64",
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104 - a value the adapter must refuse, not a bind address
    "224.0.0.1",
    "::/64",
    "ff02::/64",
    "",
    "example.org",
    "192.0.2.1 }; flush ruleset; add table inet x {",
    '192.0.2.1 comment "x"',
    "192.0.2.1\nflush ruleset",
    "192.0.2.1;flush ruleset",
    "@blocked4",
    "{ 192.0.2.1, 192.0.2.2 }",
    None,
    5,
    b"192.0.2.1",
]


@pytest.mark.parametrize("source", BAD_SOURCES)
def test_anything_but_a_source_key_is_refused_before_nft_is_run(source):
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    adapter = NftAdapter(fake, clock=clock, dry_run=False)
    for call in (
        lambda: adapter.block(source, T0 + HOUR),
        lambda: adapter.unblock(source),
        lambda: adapter.reconcile({source: T0 + HOUR}),
    ):
        with pytest.raises((ValueError, TypeError)):
            call()
    assert fake.calls == []


@pytest.mark.parametrize("expiry", [T0 + 30 * 24 * HOUR, 2**62, "soon", None, 1.5e12, True])
def test_a_block_must_carry_a_sane_expiry(expiry):
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    adapter = NftAdapter(fake, clock=clock, dry_run=False)
    with pytest.raises((ValueError, TypeError)):
        adapter.block(V4, expiry)
    with pytest.raises((ValueError, TypeError)):
        adapter.reconcile({V4: expiry})
    assert fake.changes() == []


def test_every_script_line_is_built_from_fixed_words_and_addresses():
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    adapter = NftAdapter(fake, clock=clock, dry_run=False)
    adapter.block(V4, T0 + HOUR)
    adapter.block(V6, T0 + 1)
    adapter.unblock(V4)
    scripts = fake.changes()
    assert scripts[0] == nft.RULESET
    add = "add element inet lurewall"
    assert scripts[1:] == [
        f'{add} blocked4 {{ {V4} timeout 3600s comment "lurewall:exp={T0 + HOUR}" }}\n',
        f'{add} blocked6 {{ {V6} timeout 1s comment "lurewall:exp={T0 + 1}" }}\n',
        f"delete element inet lurewall blocked4 {{ {V4} }}\n",
    ]


def test_a_hostile_comment_on_a_live_entry_is_never_sent_back_to_nft():
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    adapter = NftAdapter(fake, clock=clock, dry_run=False)
    adapter.ensure()
    marker = "zzmarker; flush ruleset"
    fake.sets[SET4]["192.0.2.50"] = {"timeout": None, "comment": marker, "added": T0}
    fake.sets[SET4]["192.0.2.51"] = {
        "timeout": 60,
        "comment": f"lurewall:exp={T0 + HOUR} {marker}",
        "added": T0,
    }
    fake.calls.clear()
    assert dict(adapter.sweep()) == {"192.0.2.50": "no_expiry", "192.0.2.51": "no_expiry"}
    assert all("zzmarker" not in script for script in fake.changes())


# -- what nft prints is not trusted ---------------------------------------------------------------


def listing(elements, *, name=SET4, table="lurewall") -> str:
    body = {"family": "inet", "name": name, "table": table, "elem": elements}
    return json.dumps({"nftables": [{"metainfo": {}}, {"set": body}]})


def test_parse_set_reads_every_form_nft_prints():
    entries = nft.parse_set(
        listing(
            [
                "192.0.2.1",
                {
                    "elem": {
                        "val": "192.0.2.2",
                        "timeout": 60,
                        "expires": 59,
                        "comment": "lurewall:exp=17",
                    }
                },
                {"elem": {"val": {"prefix": {"addr": "192.0.2.0", "len": 24}}, "timeout": 60}},
                {"range": ["192.0.2.5", "192.0.2.9"]},
            ]
        ),
        SET4,
    )
    assert [(e.element, e.source, e.expiry_ms, e.kernel_expires_s) for e in entries] == [
        ("192.0.2.1", "192.0.2.1", None, None),
        ("192.0.2.2", "192.0.2.2", 17, 59),
        ("192.0.2.0/24", None, None, None),
        ("192.0.2.5-192.0.2.9", None, None, None),
    ]
    six = nft.parse_set(
        listing(
            [
                {
                    "elem": {
                        "val": {"prefix": {"addr": "2001:db8:1:2::", "len": 64}},
                        "comment": "lurewall:exp=9",
                    }
                },
                "2001:db8::1",
                {"prefix": {"addr": "2001:DB8:0:0::", "len": 48}},
            ],
            name=SET6,
        ),
        SET6,
    )
    assert [(e.element, e.source, e.expiry_ms) for e in six] == [
        ("2001:db8:1:2::/64", "2001:db8:1:2::/64", 9),
        ("2001:db8::1", None, None),
        ("2001:db8::/48", None, None),
    ]
    empty = {"family": "inet", "name": SET4, "table": "lurewall"}
    assert nft.parse_set(json.dumps({"nftables": [{"set": empty}]}), SET4) == []


@pytest.mark.parametrize(
    "comment",
    [
        "",
        "lurewall:exp=",
        "lurewall:exp=-5",
        "lurewall:exp=1e9",
        " lurewall:exp=5",
        "lurewall:exp=5 ",
        "lurewall:exp=" + "9" * 17,
        "LUREWALL:EXP=5",
        "lurewall:exp=５",
        5,
        None,
        ["lurewall:exp=5"],
    ],
)
def test_a_comment_that_is_not_exactly_an_expiry_gives_none(comment):
    (entry,) = nft.parse_set(listing([{"elem": {"val": "192.0.2.2", "comment": comment}}]), SET4)
    assert entry.expiry_ms is None


@pytest.mark.parametrize(
    "output",
    [
        "",
        "not json",
        "[]",
        "{}",
        '{"nftables": {}}',
        '{"nftables": []}',
        '{"nftables": [{"set": []}]}',
        '{"nftables": [{"set": {"family": "ip", "name": "blocked4", "table": "lurewall"}}]}',
        '{"nftables": [{"set": {"name": "blocked4", "table": "other", "elem": []}}]}',
        '{"nftables": [{"set": {"name": "blocked6", "table": "lurewall", "elem": []}}]}',
        '{"nftables": [{"set": {"name": "blocked4", "table": "lurewall", "elem": {}}}]}',
        listing(["not-an-address"]),
        listing(["2001:db8::1"]),  # an IPv6 address in the IPv4 set
        listing([5]),
        listing([None]),
        listing([{"elem": {"val": {"prefix": {"addr": "192.0.2.0", "len": "24"}}}}]),
        listing([{"elem": {"val": {"prefix": {"addr": "192.0.2.0", "len": 99}}}}]),
        listing([{"prefix": {"addr": "192.0.2.1", "len": 24}}]),
        listing([{"range": ["192.0.2.1"]}]),
        listing([{"range": ["192.0.2.1", "2001:db8::1"]}]),
        listing([{"range": {"192.0.2.1": 0, "192.0.2.2": 0}}]),
        listing([{"range": ["192.0.2.2", "192.0.2.1"]}]),
        listing([{"elem": {"val": {"concat": ["192.0.2.1", 80]}}}]),
        listing([{"elem": {}}]),
        listing(["192.0.2.1 }; flush ruleset"]),
        "[" * 100_000,
    ],
)
def test_an_unexpected_listing_is_an_error_and_never_a_guess(output):
    with pytest.raises(NftError):
        nft.parse_set(output, SET4)


def test_a_scoped_address_is_rejected_in_a_set_listing():
    with pytest.raises(NftError):
        nft.parse_set(listing(["2001:db8::1%scope"], name=SET6), SET6)


@pytest.mark.parametrize("items", [{}, [{"table": []}], [{"unexpected": {}}], [1]])
def test_a_malformed_tables_listing_is_not_reported_as_absence(items):
    adapter = NftAdapter(lambda _args, _stdin: json.dumps({"nftables": items}), dry_run=False)

    with pytest.raises(NftError):
        adapter.installed()


def test_an_unexpected_listing_stops_reconcile_and_sweep_before_any_change():
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    adapter = NftAdapter(fake, clock=clock, dry_run=False)
    adapter.block(V4, T0 + HOUR)
    fake.sets[SET4]["bogus element"] = {"timeout": None, "comment": None, "added": T0}
    before = len(fake.changes())
    for call in (adapter.sweep, lambda: adapter.reconcile({}), lambda: adapter.unblock(V4)):
        with pytest.raises(NftError):
            call()
    assert len(fake.changes()) == before


def test_a_failing_nft_raises_and_changes_nothing():
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    adapter = NftAdapter(fake, clock=clock, dry_run=False)
    adapter.block(V4, T0 + HOUR)
    fake.fail = True
    for call in (
        lambda: adapter.block(V6, T0 + HOUR),
        lambda: adapter.unblock(V4),
        lambda: adapter.reconcile({}),
        adapter.sweep,
        adapter.list,
    ):
        with pytest.raises(NftError):
            call()
    fake.fail = False
    assert set(fake.elements()) == {V4}


def test_a_transaction_is_all_or_nothing_in_the_fake_as_in_nft():
    clock = FakeClock(T0)
    fake = FakeNft(clock)
    NftAdapter(fake, clock=clock, dry_run=False).ensure()
    with pytest.raises(NftError):
        fake(
            ["-f", "-"],
            "add element inet lurewall blocked4 { 192.0.2.1 }\n"
            "delete element inet lurewall blocked4 { 192.0.2.2 }\n",
        )
    assert fake.elements() == {}


# -- running the real binary -------------------------------------------------------------------


def test_the_system_runner_reports_failure_without_repeating_nfts_output(tmp_path):
    script = tmp_path / "nft"
    script.write_text('#!/bin/sh\necho "zzmarker from stderr" >&2\necho zzmarker\nexit 3\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    with pytest.raises(NftError) as caught:
        nft.system_runner(str(script))(["-j", "list", "tables"], None)
    assert "status 3" in str(caught.value) and "zzmarker" not in str(caught.value)


def test_the_system_runner_passes_arguments_and_stdin_and_a_clean_environment(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("LUREWALL_SECRET_LOOKING", "zzmarker")
    script = tmp_path / "nft"
    script.write_text('#!/bin/sh\nprintf "%s|" "$@"\ncat\nenv\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    out = nft.system_runner(str(script))(["-f", "-"], "add table inet lurewall\n")
    assert out.startswith("-f|-|add table inet lurewall\n")
    assert "zzmarker" not in out


def test_a_missing_nft_binary_is_an_nft_error(tmp_path):
    with pytest.raises(NftError, match="could not be run"):
        nft.system_runner(str(tmp_path / "no-such-nft"))(["-j", "list", "tables"], None)
