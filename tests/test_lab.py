# SPDX-License-Identifier: AGPL-3.0-only
"""The lab harness, the results export and the checkpoint job, offline.

No network: every request goes to a fake sender. The same code runs against a
real nginx in test_lab_e2e.
"""

from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path

import pytest

from conftest import HOSTILE_STRINGS, FakeClock
from lurewall import anchorjob, cli, labcases, labclient, results, signing
from lurewall.entry import make_checkpoint
from lurewall.eventlog import EventLog
from lurewall.labclient import Response, Target

REPO = Path(__file__).resolve().parents[1]
T0 = 1_800_000_000_000
LAB = Target("192.0.2.160", 80)
REF = "/fixture/not-a-canary/page-0001?v=" + "ab" * 16
PAGE = (
    b"<html><head><!-- read " + REF.encode() + b" first --></head><body>"
    b'<a href="/about.html">About</a> <a href="http://192.0.2.160/docs/">Docs</a>'
    b' <a href="https://example.org/x">away</a> <a href="//evil.example/y">away</a>'
    b"</body></html>"
)


class FakeSite:
    """Records every request; answers / with a page carrying one canary reference."""

    def __init__(self, pages=None, status=404):
        self.requests: list[bytes] = []
        self.pages = {"/": PAGE, "/robots.txt": b"User-agent: *\nAllow: /\n# see /notes.txt\n"}
        self.pages.update(pages or {})
        self.status = status

    def __call__(self, target: Target, request: bytes) -> Response:
        assert target == LAB
        self.requests.append(request)
        path = request.split(b" ")[1].decode("utf-8", "surrogateescape")
        if path in self.pages:
            return Response(200, (("Content-Type", "text/html"),), self.pages[path])
        return Response(self.status, (), b"not found")

    def paths(self) -> list[str]:
        return [r.split(b" ")[1].decode("utf-8", "surrogateescape") for r in self.requests]


def context(site=None, **kwargs) -> labcases.Context:
    site = site or FakeSite()
    clock = FakeClock(T0)
    defaults = {
        "client": labclient.Client(LAB, site, pause_s=0),
        "source": "192.0.2.152",
        "ask": lambda _prompt: "",
        "say": lambda _text: None,
        "sleep": lambda seconds: clock.advance(int(seconds * 1000)),
        "clock": clock,
    }
    return labcases.Context(**{**defaults, **kwargs})


# -- the target is a lab address, and only GET and HEAD go out ------------------------------


@pytest.mark.parametrize(
    "text",
    ["http://192.0.2.160", "http://192.0.2.160/", "http://10.0.0.5:8080", "http://127.0.0.1:9"],
)
def test_lab_targets_are_accepted(text):
    assert labclient.parse_target(text).host


@pytest.mark.parametrize(
    "text",
    [
        "https://192.0.2.160",
        "http://8.8.8.8",
        "http://1.1.1.1/",
        "http://example.org",
        "http://lurewall.lab",
        "http://192.0.2.160/admin",
        "http://192.0.2.160/?x=1",
        "http://user@192.0.2.160",
        "http://0.0.0.0",
        "http://169.254.1.1",
        "http://[2606:4700:4700::1111]",
        "ftp://192.0.2.160",
        "http://192.0.2.160:99999",
        "",
    ],
)
def test_anything_but_a_private_http_address_is_refused(text):
    with pytest.raises(labclient.TargetError):
        labclient.parse_target(text)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS", "get", "TRACE"])
def test_only_get_and_head_are_sent(method):
    with pytest.raises(ValueError):
        labclient.build_request(LAB, "/", method=method)


@pytest.mark.parametrize(
    ("path", "agent"),
    [
        (b"/x\r\nX-Injected: 1", b"ua"),
        (b"/x\nfoo", b"ua"),
        (b"/x\x00", b"ua"),
        (b"/", b"ua\r\nX-Injected: 1"),
        (b"/", b"ua\x00"),
        (b"no-slash", b"ua"),
        (b"/a b", b"ua"),
    ],
)
def test_no_request_can_be_split_or_smuggled(path, agent):
    with pytest.raises(ValueError):
        labclient.build_request(LAB, path, user_agent=agent)


def test_every_hostile_request_builds_as_exactly_one_request():
    for path, agent in labclient.HOSTILE:
        request = labclient.build_request(LAB, path, user_agent=agent)
        assert request.count(b"\r\n\r\n") == 1 and request.endswith(b"\r\n\r\n")
        assert request.startswith(b"GET " + path + b" HTTP/1.1\r\nHost: 192.0.2.160\r\n")


def test_references_are_found_in_bodies_and_headers():
    header_ref = "/opt/notes-7?r=" + "cd" * 16
    response = Response(200, (("X-Notes", f"read {header_ref}"),), PAGE)
    assert labclient.references(response) == [REF, header_ref]
    assert labclient.references(Response(200, (), b"/x?v=" + b"a" * 33)) == []


def test_the_crawler_follows_same_site_paths_and_robots_and_nothing_else():
    site = FakeSite()
    visited = labclient.crawl(labclient.Client(LAB, site, pause_s=0))
    assert visited[:2] == ["/", "/robots.txt"]
    assert REF in visited and "/about.html" in visited and "/docs/" in visited
    assert "/notes.txt" in visited
    assert not any("example" in path or path.startswith("//") for path in visited)
    assert all(request.startswith(b"GET ") for request in site.requests)


def test_the_crawler_stops_at_its_page_limit():
    pages = {f"/p{n}": f'<a href="/p{n + 1}">next</a>'.encode() for n in range(500)}
    pages["/"] = b'<a href="/p0">start</a>'
    site = FakeSite(pages)
    assert len(labclient.crawl(labclient.Client(LAB, site, pause_s=0), max_pages=25)) == 25


def test_a_chunked_response_is_read():
    raw = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    )
    assert labclient._parse_response(raw).body == b"hello world"
    assert labclient._parse_response(b"garbage").status == 0


# -- the cases ---------------------------------------------------------------------------


def test_there_are_twenty_cases_and_only_case_20_is_dry_run_only():
    assert sorted(labcases.CASES) == list(range(1, 21))
    assert [n for n, case in labcases.CASES.items() if case.dry_run_only] == [20]
    careful = labcases.CASES[20]
    assert "careful AI agent" in careful.title and "Ask every time" in careful.title
    assert "192.0.2.177" in careful.clients and "dry_run = true" in careful.setup


def test_scripted_case_2_reads_a_page_requests_the_reference_and_two_probes():
    site = FakeSite()
    record = labcases.run_case(labcases.CASES[2], context(site, scripted=True))
    assert site.paths() == ["/", REF, "/.env", "/.git/config"]
    assert record["case"] == 2 and record["sent"] == 4 and record["source"] == "192.0.2.152"
    assert record["statuses"] == {"200": 1, "404": 3}


def test_case_11_waits_sixteen_minutes_before_the_probes():
    ctx = context()
    record = labcases.run_case(labcases.CASES[11], ctx)
    assert record["ended_ms"] - record["started_ms"] >= 16 * 60_000


def test_case_8_page_uses_an_id_no_one_was_served():
    page = labcases.framing_page(LAB, REF).decode()
    srcs = re.findall(r'src="([^"]+)"', page)
    assert srcs[1:] == ["http://192.0.2.160/.env", "http://192.0.2.160/.git/config"]
    canary = srcs[0]
    assert canary.startswith("http://192.0.2.160/fixture/not-a-canary/page-0001?v=")
    assert canary.split("=")[1] != "ab" * 16


def test_case_8_serves_the_page_from_loopback_and_requests_nothing_else_itself():
    served = []
    site = FakeSite()
    labcases.run_case(labcases.CASES[8], context(site, serve_page=served.append))
    assert site.paths() == ["/"] and len(served) == 1


def test_scripted_sets_send_what_they_promise():
    for number, expected in ((3, list(labclient.WORDLIST)), (17, list(labclient.PATH_VARIANTS))):
        site = FakeSite()
        labcases.run_case(labcases.CASES[number], context(site))
        assert site.paths() == expected
    site = FakeSite()
    record = labcases.run_case(labcases.CASES[15], context(site))
    assert record["sent"] == 200 and site.paths()[100] == "/.git/config"
    assert set(site.paths()) == {"/wp-login.php", "/.git/config"}


def test_cases_10_and_12_need_their_part():
    for number in (10, 12):
        with pytest.raises(ValueError):
            labcases.run_case(labcases.CASES[number], context())
    site = FakeSite()
    record = labcases.run_case(labcases.CASES[10], context(site, part="serve"))
    assert record["reference"] == REF
    site = FakeSite()
    labcases.run_case(labcases.CASES[10], context(site, part="hit", reference=REF))
    assert site.paths() == [REF]


def test_agent_cases_wait_for_the_operator_and_keep_a_short_note():
    answers = iter(["", "agent asked 9 times; approved 7\x1b[31m" + "x" * 900])
    said = []
    record = labcases.run_case(
        labcases.CASES[20],
        context(ask=lambda _p: next(answers), say=said.append, label="careful agent"),
    )
    assert record["dry_run_only"] is True and record["sent"] == 0
    assert len(record["note"]) == labcases.MAX_NOTE_CHARS
    assert any("Dry-run only" in line for line in said)
    assert any("Ask every time" in line for line in said)


def test_case_13_watch_times_the_block():
    statuses = iter([0, 0, 0, 200])

    def sender(_target, _request):
        return Response(next(statuses), (), b"")

    ctx = context(watch=True, client=labclient.Client(LAB, sender, pause_s=0))
    record = labcases.run_case(labcases.CASES[13], ctx)
    assert record["unreachable_ms"] == 15_000


def test_the_ledger_round_trips_and_refuses_junk(tmp_path):
    ledger = tmp_path / "lab" / "runs.jsonl"
    record = labcases.run_case(labcases.CASES[3], context())
    labcases.append_run(ledger, record)
    labcases.append_run(ledger, record)
    assert labcases.read_runs(ledger) == [record, record]
    assert oct(ledger.stat().st_mode & 0o777) == "0o600"
    ledger.write_bytes(b'{"case": "1"}\n')
    with pytest.raises(ValueError):
        labcases.read_runs(ledger)


def test_source_names():
    assert labcases.source_address("machine-a") == "192.0.2.177"
    assert labcases.source_address("machine-b") == "192.0.2.152"
    assert labcases.source_address("10.0.0.9") == "10.0.0.9"
    with pytest.raises(ValueError):
        labcases.source_address("my-laptop")


# -- results -----------------------------------------------------------------------------


@pytest.fixture
def key(tmp_path):
    path = tmp_path / "keys" / "k.key"
    path.parent.mkdir()
    return signing.EurekaSigner.generate(path)


def write_log(path, signer, events, clock):
    path.parent.mkdir(parents=True, exist_ok=True)
    with EventLog(path, signer, clock=clock, fsync=False) as log:
        for at, kind, source, detail in events:
            clock.now = at
            log.append(kind, source, detail)


def run(case, start, end, source="192.0.2.177", **extra):
    return {
        "case": case,
        "run": "r",
        "source": source,
        "started_ms": start,
        "ended_ms": end,
        **extra,
    }


def evaluate(tmp_path, key, events, runs):
    clock = FakeClock(T0)
    log = tmp_path / "events.log"
    write_log(log, key, events, clock)
    entries = results.read_entries(log, key.public_key_hex, 10**6)
    return results.evaluate(entries, runs)


MACHINE_A = "192.0.2.177"


def test_case_20_passes_only_when_dry_run_held_and_nothing_was_enforced(tmp_path, key):
    started = (T0, "service_started", None, {"dry_run": True, "adapter": "nftables"})
    acted = (T0 + 5_000, "would_block", MACHINE_A, {"reason": "dry_run"})
    (ok,) = evaluate(tmp_path, key, [started, acted], [run(20, T0 + 1_000, T0 + 9_000)])
    assert ok.verdict == results.PASS and ok.counts["would_block"] == 1

    enforcing = (T0, "service_started", None, {"dry_run": False, "adapter": "nftables"})
    (bad,) = evaluate(tmp_path / "a", key, [enforcing], [run(20, T0 + 1_000, T0 + 9_000)])
    assert bad.verdict == results.FAIL and "dry-run" in bad.why

    restarted = (T0 + 4_000, "service_started", None, {"dry_run": False, "adapter": "nftables"})
    (mid,) = evaluate(tmp_path / "b", key, [started, restarted], [run(20, T0 + 1_000, T0 + 9_000)])
    assert mid.verdict == results.FAIL

    blocked = (T0 + 5_000, "block", MACHINE_A, {"applied": True})
    (worse,) = evaluate(tmp_path / "c", key, [started, blocked], [run(20, T0 + 1_000, T0 + 9_000)])
    assert worse.verdict == results.FAIL

    (unknown,) = evaluate(tmp_path / "d", key, [acted], [run(20, T0 + 1_000, T0 + 9_000)])
    assert unknown.verdict == results.FAIL  # no service_started: dry-run not shown


def test_events_from_other_sources_or_times_are_not_counted(tmp_path, key):
    events = [
        (T0, "service_started", None, {"dry_run": True, "adapter": "log-only"}),
        (T0 + 5_000, "block", "192.0.2.152", {}),
        (T0 + 30 * 60_000, "block", MACHINE_A, {}),
    ]
    (result,) = evaluate(tmp_path, key, events, [run(20, T0 + 1_000, T0 + 9_000)])
    assert result.verdict == results.PASS and result.counts["block"] == 0


def test_rolled_up_hits_count_and_count_as_counted(tmp_path, key):
    events = [
        (T0 + 1_000, "cross_site", MACHINE_A, {}),
        (T0 + 2_000, "rollup", MACHINE_A, {"of": "canary_hit", "key": "x", "count": 3}),
    ]
    (result,) = evaluate(tmp_path, key, events, [run(8, T0, T0 + 5_000)])
    assert result.counts["canary_hit"] == 3 and result.verdict == results.FAIL


def test_case_verdicts(tmp_path, key):
    def one(case, events, **extra):
        directory = tmp_path / f"run{len(list(tmp_path.iterdir()))}"
        return evaluate(directory, key, events, [run(case, T0, T0 + 5_000, **extra)])[0]

    hit = (T0 + 1_000, "canary_hit", MACHINE_A, {"counted": True, "placement": "p", "lure": "bait"})
    sig = (T0 + 1_500, "attack_signal", MACHINE_A, {"signal": "path:tree:/.env"})
    assert one(1, [hit]).verdict == results.PASS
    assert one(1, [hit, (T0 + 2_000, "would_block", MACHINE_A, {})]).verdict == results.FAIL
    assert one(3, [sig]).verdict == results.PASS
    assert one(3, [sig, hit]).verdict == results.FAIL
    assert one(4, []).verdict == results.PASS
    assert one(4, [sig]).verdict == results.FAIL
    allow = (T0 + 1_000, "would_block", MACHINE_A, {"reason": "allowlisted"})
    assert one(7, [allow]).verdict == results.PASS
    assert one(7, [allow, (T0 + 2_000, "block", MACHINE_A, {})]).verdict == results.FAIL
    dry = (T0 + 1_000, "would_block", MACHINE_A, {"reason": "dry_run"})
    assert one(7, [dry]).verdict == results.FAIL  # dry-run is not the allowlist at work
    assert one(9, [hit]).verdict == results.PASS
    relayed = (T0 + 1_000, "canary_relayed", MACHINE_A, {})
    assert one(10, [relayed], part="hit").verdict == results.PASS
    assert one(12, [], part="probe").verdict == results.LIMIT
    sig2 = (T0 + 1_600, "attack_signal", MACHINE_A, {"signal": "path:tree:/.git"})
    assert one(15, [sig, sig2], statuses={"429": 150}).verdict == results.PASS
    assert one(15, [sig, sig2], statuses={"404": 200}).verdict == results.FAIL
    assert one(17, [sig, sig2], sent=2).verdict == results.PASS
    assert one(17, [sig], sent=2).verdict == results.FAIL
    assert (
        one(18, [(T0 + 1_000, "decision", MACHINE_A, {"outcome": "log_only_range"})]).verdict
        == "pass"
    )
    assert one(5, []).verdict == results.RECORD
    assert one(14, [], part="backlog").verdict == results.PASS
    assert one(14, [(T0 + 1_000, "block", MACHINE_A, {})], part="backlog").verdict == results.FAIL


def test_case_2_needs_a_block_and_its_expiry_unless_in_dry_run(tmp_path, key):
    enforcing = (T0 - 10, "service_started", None, {"dry_run": False, "adapter": "nftables"})
    block = (T0 + 1_000, "block", MACHINE_A, {})
    expired = (T0 + 6 * 60_000, "block_expired", MACHINE_A, {})
    (both,) = evaluate(tmp_path, key, [enforcing, block, expired], [run(2, T0, T0 + 5_000)])
    assert both.verdict == results.PASS
    (no_expiry,) = evaluate(tmp_path / "a", key, [enforcing, block], [run(2, T0, T0 + 5_000)])
    assert no_expiry.verdict == results.FAIL
    dry = (T0 - 10, "service_started", None, {"dry_run": True, "adapter": "log-only"})
    would = (T0 + 1_000, "would_block", MACHINE_A, {})
    (rehearsal,) = evaluate(tmp_path / "b", key, [dry, would], [run(2, T0, T0 + 5_000)])
    assert rehearsal.verdict == results.PASS and "dry-run" in rehearsal.why


@pytest.mark.parametrize("value", HOSTILE_STRINGS)
def test_safe_text_leaves_only_printable_ascii(value):
    text = results.safe_text(value)
    assert all(32 <= ord(char) < 127 for char in text)
    assert len(text) <= results.MAX_TEXT_CHARS


@pytest.mark.parametrize("value", ["=1+2", "+cmd", "-2", "@SUM(A1)", '=HYPERLINK("x")'])
def test_csv_cells_never_start_a_formula(value):
    assert results.csv_cell(value).startswith("'")


def test_markdown_cells_cannot_break_the_table_or_add_markup():
    cell = results.md("a | b <script> [x](http://e) `c` *d*\n| e")
    assert "|" not in cell.replace("\\|", "")
    for raw in ("<script>", "[x]", "`c`", "*d*"):
        assert raw not in cell


def test_the_export_refuses_a_log_that_does_not_verify(tmp_path, key):
    log = tmp_path / "events.log"
    write_log(log, key, [(T0, "service_started", None, {"dry_run": True})] * 3, FakeClock(T0))
    lines = log.read_bytes().splitlines(keepends=True)
    log.write_bytes(lines[0] + lines[2])
    runs = [run(4, T0, T0 + 1)]
    report, _rows, written = results.export(log, key.public_key_hex, [], runs, tmp_path / "out")
    assert not report.ok and written == [] and not (tmp_path / "out").exists()
    _, _, written = results.export(
        log, key.public_key_hex, [], runs, tmp_path / "out", allow_unverified=True
    )
    for path in written:
        assert "UNVERIFIED" in path.read_text().splitlines()[0]


def test_the_export_escapes_everything_from_the_ledger_and_the_log(tmp_path, key):
    log = tmp_path / "events.log"
    hostile = '=cmd|"/c calc"!A1 \x1b[2J <img src=x> | ‮'
    events = [
        (T0, "service_started", None, {"dry_run": True, "adapter": "log-only"}),
        (
            T0 + 1_000,
            "canary_hit",
            MACHINE_A,
            {"placement": hostile, "lure": hostile, "counted": True},
        ),
    ]
    write_log(log, key, events, FakeClock(T0))
    runs = [run(1, T0, T0 + 5_000, label=hostile, note=hostile)]
    _, _, written = results.export(log, key.public_key_hex, [], runs, tmp_path / "out")
    for path in written:
        text = path.read_text(encoding="ascii")
        assert "\x1b" not in text and "\u202e" not in text
        assert "\n=cmd" not in text and ",=cmd" not in text
    markdown = (tmp_path / "out" / "results.md").read_text()
    # Markdown renders HTML; CSV does not. Every < arrives escaped.
    assert re.search(r"(?<!\\)<", markdown) is None and "\\<img" in markdown
    assert "| case 1: " in markdown  # the hit-rate table


# -- the checkpoint job ---------------------------------------------------------------------------


def checkpoint_sender(body: bytes, status: int = 200):
    def send(target, request):
        assert target == LAB and request.startswith(b"GET /lurewall-checkpoint.json HTTP/1.1\r\n")
        return Response(status, (), body)

    return send


URL = "http://192.0.2.160/lurewall-checkpoint.json"


def signed(key, seq, head="ab" * 32):
    return json.dumps(make_checkpoint(key, seq, head, T0)).encode()


def test_pull_stores_commits_and_pushes_only_when_asked(tmp_path, key):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    calls = []

    def runner(argv, cwd):
        calls.append(argv)
        return 0

    result = anchorjob.pull(
        URL,
        key.public_key_hex,
        repo,
        sender=checkpoint_sender(signed(key, 7)),
        run=runner,
        git="git",
    )
    assert (result.status, result.seq, result.committed, result.pushed) == (
        "stored",
        7,
        True,
        False,
    )
    stored = repo / "checkpoints" / "000000000007.json"
    assert json.loads(stored.read_bytes())["seq"] == 7
    assert calls == [
        ["git", "add", "--", "checkpoints"],
        ["git", "commit", "-q", "-m", "checkpoint 7"],
    ]

    calls.clear()
    result = anchorjob.pull(
        URL,
        key.public_key_hex,
        repo,
        sender=checkpoint_sender(signed(key, 9)),
        run=runner,
        git="git",
        ots="/usr/local/bin/ots",
        push=True,
    )
    assert result.stamped and result.pushed
    assert calls[0] == [
        "/usr/local/bin/ots",
        "stamp",
        str(repo / "checkpoints" / "000000000009.json"),
    ]
    assert calls[-1] == ["git", "push", "-q"]


def test_pull_refuses_two_histories_and_flags_going_back(tmp_path, key):
    repo = tmp_path / "repo"
    no_git = lambda argv, cwd: 1  # noqa: E731
    pull = lambda body: anchorjob.pull(  # noqa: E731
        URL, key.public_key_hex, repo, sender=checkpoint_sender(body), run=no_git
    )
    assert pull(signed(key, 5)).status == "stored"
    assert pull(signed(key, 5)).status == "unchanged"
    fork = pull(signed(key, 5, head="cd" * 32))
    assert fork.status == "conflict" and not fork.ok
    assert (
        json.loads((repo / "checkpoints" / "000000000005.json").read_bytes())["head_hash"]
        == "ab" * 32
    )
    assert pull(signed(key, 3)).status == "went_back"


def test_pull_refuses_bad_checkpoints_and_bad_urls(tmp_path, key):
    other = signing.EurekaSigner.generate(tmp_path / "other.key")
    for body, status in (
        (signed(other, 5), "bad_checkpoint"),
        (b"not json", "bad_checkpoint"),
        (b"[" * 70_000, "fetch_failed"),
        (b'{"seq": 1}', "bad_checkpoint"),
    ):
        result = anchorjob.pull(
            URL, key.public_key_hex, tmp_path / "r", sender=checkpoint_sender(body)
        )
        assert result.status == status
    assert (
        anchorjob.pull(
            URL, key.public_key_hex, tmp_path / "r", sender=checkpoint_sender(b"", 404)
        ).status
        == "fetch_failed"
    )
    for url in (
        "http://8.8.8.8/c.json",
        "https://192.0.2.160/c.json",
        "http://192.0.2.160/c?x",
    ):
        with pytest.raises(labclient.TargetError):
            anchorjob.pull(url, key.public_key_hex, tmp_path / "r", sender=checkpoint_sender(b""))
    assert not list((tmp_path / "r").glob("checkpoints/*.json"))


def test_pulled_checkpoints_are_anchors_verify_reads(tmp_path, key):
    from lurewall.verify import verify_log

    clock = FakeClock(T0)
    log = tmp_path / "events.log"
    checkpoint = tmp_path / "served" / "checkpoint.json"
    checkpoint.parent.mkdir()
    with EventLog(log, key, clock=clock, fsync=False, checkpoint_path=checkpoint) as events:
        for n in range(5):
            events.append("service_started", None, {"n": n})
        events.checkpoint()
    repo = tmp_path / "repo"
    anchorjob.pull(URL, key.public_key_hex, repo, sender=checkpoint_sender(checkpoint.read_bytes()))
    report = verify_log(log, key.public_key_hex, [repo / "checkpoints"])
    assert report.ok and report.anchors_matched == 1
    log.write_bytes(b"".join(log.read_bytes().splitlines(keepends=True)[:3]))
    assert verify_log(log, key.public_key_hex, [repo / "checkpoints"]).truncated_missing > 0


# -- commands ----------------------------------------------------------------------------


def test_lab_list_names_every_case(capsys):
    assert cli.main(["lab", "list"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 20 and "[dry-run only]" in out


def test_lab_case_refuses_a_public_target(capsys, tmp_path):
    argv = [
        "lab",
        "case",
        "3",
        "--from",
        "machine-a",
        "--target",
        "http://93.184.216.34",
        "--ledger",
        str(tmp_path / "l"),
    ]
    assert cli.main(argv) == cli.EXIT_USAGE
    assert "not a private" in capsys.readouterr().err
    assert not (tmp_path / "l").exists()


def test_the_tamper_command_catches_all_four(tmp_path, key, capsys):
    clock = FakeClock(T0)
    log = tmp_path / "events.log"
    checkpoint = tmp_path / "anchors" / "checkpoint.json"
    checkpoint.parent.mkdir()
    with EventLog(log, key, clock=clock, fsync=False, checkpoint_path=checkpoint) as events:
        for n in range(12):
            clock.advance(1000)
            events.append("service_started", None, {"n": n})
        events.checkpoint()
    argv = ["lab", "tamper", "--log", str(log), "--pubkey", key.public_key_hex,
            "--anchors", str(checkpoint.parent), "--work", str(tmp_path / "work")]  # fmt: skip
    assert cli.main(argv) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "NOT CAUGHT" not in out
    assert "truncated: 1 entries missing" in out  # the anchored last entry


def test_the_truncated_copy_cuts_past_the_last_anchor(tmp_path, key, capsys):
    # Entries after the last anchor can't be shown missing; the copy must cut deeper.
    clock = FakeClock(T0)
    log = tmp_path / "events.log"
    checkpoint = tmp_path / "anchors" / "checkpoint.json"
    checkpoint.parent.mkdir()
    with EventLog(log, key, clock=clock, fsync=False, checkpoint_path=checkpoint) as events:
        for n in range(12):
            clock.advance(1000)
            events.append("service_started", None, {"n": n})
        events.checkpoint()
        for n in range(5):  # an unanchored tail, as on a live log
            clock.advance(1000)
            events.append("service_started", None, {"n": n})
    argv = ["lab", "tamper", "--log", str(log), "--pubkey", key.public_key_hex,
            "--anchors", str(checkpoint.parent), "--work", str(tmp_path / "work")]  # fmt: skip
    assert cli.main(argv) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "NOT CAUGHT" not in out
    assert re.search(r"truncate\s+truncated: \d+ entries missing", out)


def test_the_truncated_copy_without_anchors_drops_three(tmp_path):
    log = tmp_path / "events.log"
    log.write_bytes(b"".join(b'{"seq":%d}\n' % n for n in range(1, 11)))
    copies = labcases.tamper_copies(log, tmp_path / "work")
    assert copies["truncate"].read_bytes().count(b"\n") == 7


def test_the_checkpoint_command_refuses_a_public_url(tmp_path, key, capsys):
    argv = ["checkpoint", "pull", "--url", "http://8.8.8.8/x.json", "--pubkey", key.public_key_hex,
            "--repo", str(tmp_path / "repo")]  # fmt: skip
    assert cli.main(argv) == cli.EXIT_USAGE


# -- deploy files ------------------------------------------------------------------------


def test_logrotate_rotates_the_access_log_by_size_and_often():
    timer = (REPO / "deploy" / "logrotate" / "logrotate.timer.d-lurewall.conf").read_text()
    assert "OnCalendar=\nOnCalendar=*:0/15" in timer
    assert "RandomizedDelaySec=0" in timer  # Debian's unit adds up to 1h of random delay
    runbook = (REPO / "docs" / "lab-runbook.md").read_text()
    assert "maxsize 100M" in runbook and "/etc/logrotate.d/nginx" in runbook


def test_the_runbook_keeps_case_20_in_dry_run():
    # Since Nov 18, 2026 test machine A runs 6B's scripted cases (the operator's call: a
    # block only drops traffic into the lab container). Case 20, the careful agent from
    # test machine A, stays dry-run.
    runbook = (REPO / "docs" / "lab-runbook.md").read_text()
    dry, enforcing = runbook.split("### 6B", 1)
    assert "lurewall lab case 20 --from machine-a" in dry
    assert "case 20" not in enforcing.split("## Phase 7", 1)[0]
    assert labcases.CASES[20].dry_run_only


def test_the_launchd_job_runs_the_pull_command_every_five_minutes():
    with open(REPO / "deploy" / "launchd" / "org.lurewall.checkpoint-pull.plist", "rb") as handle:
        job = plistlib.load(handle)
    assert job["StartInterval"] == 300
    args = job["ProgramArguments"]
    assert args[1:3] == ["checkpoint", "pull"] and "--pubkey" in args and "--repo" in args
    assert "--push" not in args  # pushing is a choice the runbook leaves to the operator
    cli._build_parser().parse_args(args[1:])


def test_the_service_unit_writes_the_checkpoint_where_nginx_serves_it():
    unit = (REPO / "deploy" / "systemd" / "lurewall.service").read_text()
    assert "--checkpoint /srv/lurewall/checkpoint/checkpoint.json" in unit
    assert "ReadWritePaths=/var/lib/lurewall /srv/lurewall/checkpoint" in unit


def test_case_14_backlog_part_sends_the_scripted_attack():
    site = FakeSite()
    labcases.run_case(labcases.CASES[14], context(site, part="backlog"))
    assert site.paths() == ["/", REF, "/.env", "/.git/config"]


def test_results_merge_ledgers_from_both_clients(tmp_path, key, capsys):
    log = tmp_path / "events.log"
    write_log(log, key, [(T0, "service_started", None, {"dry_run": True})], FakeClock(T0))
    ledger_a, ledger_b = tmp_path / "machine-a.jsonl", tmp_path / "machine-b.jsonl"
    labcases.append_run(ledger_a, run(4, T0 + 10, T0 + 20))
    labcases.append_run(ledger_b, run(3, T0 + 5, T0 + 9, source="192.0.2.152"))
    argv = ["lab", "results", "--log", str(log), "--pubkey", key.public_key_hex,
            "--ledger", str(ledger_a), "--ledger", str(ledger_b),
            "--out", str(tmp_path / "out")]  # fmt: skip
    assert cli.main(argv) == cli.EXIT_OK
    rows = (tmp_path / "out" / "results.csv").read_text().splitlines()[2:]
    assert [row.split(",")[0] for row in rows] == ["3", "4"]


def test_results_report_hits_per_family_and_signal_and_per_agent(tmp_path, key):
    log = tmp_path / "events.log"
    events = [
        (T0, "service_started", None, {"dry_run": True, "adapter": "log-only"}),
        # A v1 log entry has no family or signal: it reads as v1-imperative, ai.
        (T0 + 1_000, "canary_hit", MACHINE_A, {"placement": "api_doc", "lure": "bait",
                                               "counted": True}),
        (T0 + 2_000, "canary_hit", MACHINE_A, {"placement": "footer_comment", "lure": "destination",
                                         "family": "v2-quiet", "signal": "ai", "counted": True}),
        (T0 + 3_000, "canary_hit", MACHINE_A, {"placement": "security_txt", "lure": "destination",
                                         "family": "v2-quiet", "signal": "research",
                                         "counted": False}),
        (T0 + 600_000, "canary_hit", MACHINE_A, {"placement": "robots_disallow",
                                                 "lure": "destination",
                                          "family": "v2-quiet", "signal": "recon",
                                          "counted": True}),
    ]  # fmt: skip
    write_log(log, key, events, FakeClock(T0))
    runs = [
        run(1, T0, T0 + 5_000, label="agent x"),
        run(1, T0 + 599_000, T0 + 601_000, label="agent y"),
    ]
    _, rows, _written = results.export(log, key.public_key_hex, [], runs, tmp_path / "out")
    assert rows[0].families == {("v1-imperative", "ai"): 1, ("v2-quiet", "ai"): 1,
                                ("v2-quiet", "research"): 1}  # fmt: skip
    assert results.family_hit_rates(rows) == [
        ("case 1: agent x", 1, 1, 1),
        ("case 1: agent y", 0, 1, 1),
    ]
    markdown = (tmp_path / "out" / "results.md").read_text()
    assert "| v2\\-quiet | recon | 1 |" in markdown and "| v1\\-imperative | ai | 1 |" in markdown
    assert "never counted" in markdown
