# SPDX-License-Identifier: AGPL-3.0-only
"""The tailer: rotation, restart, hostile lines, floods, lag and staleness.

The rule under test throughout: every line in the access log ends up as a
record, or in a signed parse_failure event, or counted in a signed roll-up.
"""

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

import nginx_emu
from lurewall.accesslog import MAX_LINE_BYTES
from lurewall.canonical import sha256_hex
from lurewall.entry import check_entry_line
from lurewall.logreader import LogReader
from lurewall.verify import verify_log
from nginx_emu import NOW_MS, line

REPO = Path(__file__).resolve().parents[1]
MARKER = b"ATTACKER-TEXT-5d1e"


@pytest.fixture
def access(tmp_path):
    return tmp_path / "lurewall.json.log"


@pytest.fixture
def sink(make_log):
    return make_log("events.log")


@pytest.fixture
def make_reader(tmp_path, access, sink, clock):
    clock.now = NOW_MS
    opened = []

    def _make(**kwargs):
        kwargs.setdefault("clock", clock)
        reader = LogReader(access, tmp_path / "reader.state", kwargs.pop("sink", sink), **kwargs)
        opened.append(reader)
        return reader

    yield _make
    for reader in opened:
        reader.close()


def events(sink, kind=None):
    lines = sink.path.read_bytes().splitlines()
    found = [check_entry_line(raw, sink.public_key_hex) for raw in lines]
    return [item for item in found if kind is None or item.type == kind]


def append(path, data: bytes):
    with open(path, "ab") as handle:
        handle.write(data)


def uris(records):
    return [record.uri for record in records]


def numbered(first, last, **kwargs):
    return b"".join(line(uri=b"/n/%d" % n, **kwargs) for n in range(first, last + 1))


def expect_uris(first, last):
    return [f"/n/{n}" for n in range(first, last + 1)]


# -- plain reading ---------------------------------------------------------------


def test_reads_lines_in_order_with_their_offsets(make_reader, access):
    first, second = line(uri=b"/a"), line(uri=b"/b")
    append(access, first + second)
    reader = make_reader()
    records = reader.poll()
    assert uris(records) == ["/a", "/b"]
    assert [r.offset for r in records] == [0, len(first)]
    assert records[1].line_sha256 == sha256_hex(second[:-1])
    assert reader.poll() == []
    append(access, line(uri=b"/c"))
    assert uris(reader.poll()) == ["/c"]


def test_a_line_still_being_written_waits_for_its_newline(make_reader, access):
    whole = line(uri=b"/slow")
    append(access, line(uri=b"/a") + whole[:40])
    reader = make_reader()
    assert uris(reader.poll()) == ["/a"]
    reader.commit()
    append(access, whole[40:-1])
    assert reader.poll() == []
    append(access, b"\n")
    assert uris(reader.poll()) == ["/slow"]


def test_per_poll_byte_limit_bounds_the_work_and_loses_nothing(make_reader, access):
    append(access, numbered(1, 500))
    reader = make_reader(max_bytes_per_poll=4096)
    seen = []
    polls = 0
    while True:
        batch = reader.poll()
        if not batch:
            break
        assert len(batch) <= 4096 // 100 + 1
        seen += uris(batch)
        polls += 1
    assert seen == expect_uris(1, 500) and polls > 10


# -- restart and the saved offset ---------------------------------------------------


def test_restart_resumes_after_the_last_commit(make_reader, access, tmp_path):
    append(access, numbered(1, 3))
    reader = make_reader()
    assert uris(reader.poll()) == expect_uris(1, 3)
    reader.commit()
    reader.close()
    state = tmp_path / "reader.state"
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert json.loads(state.read_text())["offset"] == access.stat().st_size
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".reader-state-")] == []

    append(access, numbered(4, 5))
    assert uris(make_reader().poll()) == expect_uris(4, 5)


def test_uncommitted_lines_are_read_again_not_lost(make_reader, access):
    append(access, numbered(1, 3))
    reader = make_reader()
    reader.poll()
    reader.commit()
    append(access, numbered(4, 6))
    assert uris(reader.poll()) == expect_uris(4, 6)
    reader.close()  # crashed before commit
    assert uris(make_reader().poll()) == expect_uris(4, 6)


def test_commit_never_points_into_the_middle_of_a_line(make_reader, access):
    whole = line(uri=b"/partial")
    append(access, numbered(1, 2) + whole[:30])
    reader = make_reader()
    reader.poll()
    reader.commit()
    reader.close()
    append(access, whole[30:])
    assert uris(make_reader().poll()) == ["/partial"]


@pytest.mark.parametrize(
    "junk",
    [
        b"",
        b"not json",
        b"[]",
        b'{"v":2}',
        b'{"v":1,"dev":1,"inode":1,"offset":-5,"head_len":0,"head_sha256":""}',
        b'{"v":1,"dev":1,"inode":1,"offset":1.5,"head_len":0,"head_sha256":""}',
        b'{"v":1,"dev":1,"inode":1,"offset":"0","head_len":0,"head_sha256":""}',
        b'{"v":1,"dev":1,"inode":1,"offset":0,"head_len":99999,"head_sha256":""}',
        b'{"v":1,"dev":true,"inode":1,"offset":0,"head_len":0,"head_sha256":""}',
        b"[" * 3000,
        b"x" * 100_000,
    ],
)
def test_unusable_saved_state_is_logged_and_everything_is_read_again(
    make_reader, access, sink, tmp_path, junk
):
    (tmp_path / "reader.state").write_bytes(junk)
    append(access, numbered(1, 3))
    reader = make_reader()
    assert uris(reader.poll()) == expect_uris(1, 3)
    assert [e.detail for e in events(sink, "reader_state_invalid")] == [{"reason": "not_valid"}]


# -- rotation ---------------------------------------------------------------------


def rotate(access, suffix=".1"):
    os.rename(access, str(access) + suffix)


def test_rotation_while_running_finishes_the_old_file_first(make_reader, access, sink):
    append(access, numbered(1, 3))
    reader = make_reader()
    assert uris(reader.poll()) == expect_uris(1, 3)
    old_inode = access.stat().st_ino
    rotate(access)
    # nginx still holds the old file and writes to it until told to reopen.
    append(str(access) + ".1", numbered(4, 5))
    append(access, numbered(6, 7))
    seen = []
    for _ in range(4):
        seen += uris(reader.poll())
    assert seen == expect_uris(4, 7)
    (rotated,) = events(sink, "log_rotated")
    assert rotated.detail["old_inode"] == old_inode
    assert rotated.detail["new_inode"] == access.stat().st_ino
    assert events(sink, "rotation_gap") == []


def test_late_writes_to_the_old_file_during_the_grace_poll_are_read(make_reader, access):
    append(access, numbered(1, 2))
    reader = make_reader()
    reader.poll()
    rotate(access)
    append(access, numbered(5, 5))
    assert reader.poll() == []  # sees the new file, gives the old one a poll more
    append(str(access) + ".1", numbered(3, 4))
    seen = uris(reader.poll()) + uris(reader.poll()) + uris(reader.poll())
    assert seen == expect_uris(3, 5)


def test_rotation_with_no_new_file_yet_keeps_the_old_one(make_reader, access, sink):
    append(access, numbered(1, 2))
    reader = make_reader()
    reader.poll()
    rotate(access)
    for _ in range(3):
        assert reader.poll() == []
    append(str(access) + ".1", numbered(3, 3))
    assert uris(reader.poll()) == expect_uris(3, 3)
    append(access, numbered(4, 4))
    assert uris(reader.poll()) + uris(reader.poll()) == expect_uris(4, 4)
    assert events(sink, "access_log_unavailable") == []


def test_rotation_while_stopped_reads_the_rest_of_the_rotated_file(make_reader, access, sink):
    append(access, numbered(1, 3))
    reader = make_reader()
    reader.poll()
    reader.commit()
    reader.close()
    append(access, numbered(4, 6))
    rotate(access)
    append(access, numbered(7, 8))
    again = make_reader()
    seen = []
    for _ in range(4):
        seen += uris(again.poll())
    assert seen == expect_uris(4, 8)
    assert len(events(sink, "log_rotated")) == 1 and events(sink, "rotation_gap") == []


@pytest.mark.parametrize("missing", [False, True])
def test_restart_reads_intermediate_rotations(make_reader, access, sink, missing):
    append(access, numbered(1, 1))
    before = make_reader()
    before.poll()
    before.commit()
    before.close()

    append(access, numbered(2, 2))
    rotate(access, ".3" if missing else ".2")
    append(access, numbered(3, 3))
    rotate(access)
    append(access, numbered(4, 4))
    if missing:
        (access.parent / "2").write_bytes(numbered(99, 99))

    after = make_reader()
    seen = [uri for _ in range(4) for uri in uris(after.poll())]
    assert seen == expect_uris(2, 4)
    assert len(events(sink, "log_rotated")) == 2
    gaps = [event.detail for event in events(sink, "rotation_gap")]
    assert len(gaps) == int(missing)
    if missing:
        assert (gaps[0]["reason"], gaps[0]["missing"]) == ("numbered_rotation_unavailable", 1)


def test_rotated_file_gone_is_a_logged_gap_not_a_silent_skip(make_reader, access, sink):
    append(access, numbered(1, 3))
    reader = make_reader()
    reader.poll()
    reader.commit()
    reader.close()
    saved_inode, saved_offset = access.stat().st_ino, access.stat().st_size
    append(access, numbered(4, 6))
    rotate(access)
    # The new file is created while the old one still exists, so the old inode
    # number cannot be handed to it (Linux reuses a freed number at once; that
    # case is the same-inode tests below).
    append(access, numbered(7, 8))
    shutil.copy(str(access) + ".1", str(access) + ".1.gz")  # "compressed": a new inode
    os.unlink(str(access) + ".1")
    assert uris(make_reader().poll()) == expect_uris(7, 8)
    (gap,) = events(sink, "rotation_gap")
    assert gap.detail == {
        "saved_inode": saved_inode,
        "saved_offset": saved_offset,
        "reason": "rotated_file_not_found",
    }


def test_same_inode_but_different_content_is_not_resumed_into(make_reader, access, sink):
    append(access, numbered(1, 3))
    reader = make_reader()
    reader.poll()
    reader.commit()
    reader.close()
    # The file is rewritten in place: same inode, longer, different lines.
    access.write_bytes(numbered(50, 60))
    assert uris(make_reader().poll()) == expect_uris(50, 60)
    assert [e.detail["reason"] for e in events(sink, "rotation_gap")] == ["file_replaced"]


def test_file_shorter_than_the_saved_offset_is_logged_and_read_from_the_top(
    make_reader, access, sink
):
    append(access, numbered(1, 9))
    reader = make_reader()
    reader.poll()
    reader.commit()
    reader.close()
    access.write_bytes(numbered(10, 11))
    assert uris(make_reader().poll()) == expect_uris(10, 11)
    (cut,) = events(sink, "log_truncated")
    assert cut.detail["size"] == access.stat().st_size


def test_truncation_while_running_is_logged(make_reader, access, sink):
    append(access, numbered(1, 9))
    reader = make_reader()
    reader.poll()
    with open(access, "r+b") as handle:
        handle.truncate(0)
    append(access, numbered(10, 11))
    assert uris(reader.poll()) == expect_uris(10, 11)
    assert len(events(sink, "log_truncated")) == 1


@pytest.mark.parametrize("restart", [False, True])
def test_regrown_log_is_read_from_the_start(make_reader, access, sink, restart):
    append(access, numbered(1, 4))
    reader = make_reader()
    assert uris(reader.poll()) == expect_uris(1, 4)
    previous = access.stat()

    access.write_bytes(numbered(10, 20))
    current = access.stat()
    assert current.st_ino == previous.st_ino and current.st_size > previous.st_size
    if restart:
        reader.commit()
        reader.close()
        reader = make_reader()

    assert uris(reader.poll()) == expect_uris(10, 20)
    assert len(events(sink, "log_truncated")) == 1


def test_a_final_line_cut_off_by_rotation_is_a_parse_failure(make_reader, access, sink):
    cut = line(uri=b"/cut")[:50]
    append(access, numbered(1, 1) + cut)
    reader = make_reader()
    reader.poll()
    rotate(access)
    append(access, numbered(2, 2))
    seen = uris(reader.poll()) + uris(reader.poll()) + uris(reader.poll())
    assert seen == expect_uris(2, 2)
    (failure,) = events(sink, "parse_failure")
    assert failure.detail["reason"] == "unterminated_line"
    assert failure.detail["sha256"] == sha256_hex(cut) and failure.detail["bytes"] == 50


# -- unavailable log ----------------------------------------------------------------


def test_missing_log_is_reported_once_per_interval_then_read_when_it_appears(
    make_reader, access, sink, clock
):
    reader = make_reader(report_interval_ms=60_000)
    for _ in range(50):
        assert reader.poll() == []
        clock.advance(100)
    assert [e.detail for e in events(sink, "access_log_unavailable")] == [{"reason": "missing"}]
    clock.advance(60_000)
    reader.poll()
    assert len(events(sink, "access_log_unavailable")) == 2
    append(access, numbered(1, 2))
    assert uris(reader.poll()) == expect_uris(1, 2)


def test_a_directory_or_fifo_in_place_of_the_log_never_hangs(make_reader, access, sink):
    os.mkfifo(access)
    reader = make_reader()
    assert reader.poll() == []
    os.unlink(access)
    access.mkdir()
    assert make_reader().poll() == []
    reasons = {e.detail["reason"] for e in events(sink, "access_log_unavailable")}
    assert reasons == {"not_a_regular_file"}


# -- hostile lines -----------------------------------------------------------------


def test_fixture_log_every_line_is_a_record_or_a_signed_failure(make_reader, access, sink):
    fixture = (REPO / "tests" / "fixtures" / "nginx_access.fixture").read_bytes()
    access.write_bytes(fixture)
    reader = make_reader(max_age_ms=10**12)
    records = []
    while batch := reader.poll():
        records += batch
    failures = events(sink, "parse_failure")
    total_lines = fixture.count(b"\n")
    assert len(records) == nginx_emu.FIXTURE_RECORDS
    assert len(failures) == nginx_emu.FIXTURE_FAILURES
    assert len(records) + len(failures) == total_lines

    # Each line is pinned by offset and hash, by one or the other.
    by_offset = {r.offset: r.line_sha256 for r in records}
    by_offset.update({f.detail["offset"]: f.detail["sha256"] for f in failures})
    offset = 0
    for raw in fixture.split(b"\n")[:-1]:
        assert by_offset[offset] == sha256_hex(raw)
        offset += len(raw) + 1
    assert sorted(f.detail["reason"] for f in failures) == [
        "bad_ip",
        "duplicate_field",
        "not_json",
        "not_json",
        "not_json",
        "unexpected_fields",
    ]

    # No hostile value moved a request to another address or status.
    hostile = [r for r in records if r.ip.startswith(("198.51.100.", "2001:db8::"))]
    assert len(hostile) == 3 * len(nginx_emu.HOSTILE_VALUES)
    assert all(r.ip != "203.0.113.99" for r in records)
    assert all(r.status in (200, 404) for r in hostile)
    assert uris(records)[-1] == "/after-the-junk"
    assert any(r.invalid_utf8 for r in records)
    assert [r.ip for r in records if r.uri == "/.env"] == ["203.0.113.8"]

    sink.close()
    assert verify_log(sink.path, sink.public_key_hex).ok


def test_hostile_values_survive_into_the_signed_log_as_data(make_reader, access, sink):
    """What later stages will do with a record: sign its text. One entry each, verifiable."""
    values = [raw for _name, raw, _expected in nginx_emu.HOSTILE_VALUES]
    access.write_bytes(b"".join(line(ua=raw, uri=b"/x/" + raw) for raw in values))
    reader = make_reader()
    records = reader.poll()
    assert len(records) == len(values)
    for record in records:
        sink.append("probe", record.ip, {"ua": record.ua, "uri": record.uri})
    sink.close()
    report = verify_log(sink.path, sink.public_key_hex)
    assert report.ok and report.entries == len(values)
    assert sink.path.read_bytes().count(b"\n") == len(values)


def test_parse_failure_events_hold_no_line_content(make_reader, access, sink):
    append(access, b'{"ua":"' + MARKER + b'"}\n' + MARKER + b" \x1b[2J\n")
    make_reader().poll()
    sink.close()
    assert len(events(sink, "parse_failure")) == 2
    raw = sink.path.read_bytes()
    assert MARKER not in raw and b"x1b" not in raw and b"u001b" not in raw


def test_overlong_line_is_one_failure_and_the_next_line_still_parses(make_reader, access, sink):
    huge = b'{"ua":"' + b"A" * (3 * MAX_LINE_BYTES) + b'"}'
    append(access, numbered(1, 1) + huge + b"\n" + numbered(2, 2))
    reader = make_reader(max_bytes_per_poll=10 * 1024 * 1024)
    assert uris(reader.poll()) == expect_uris(1, 2)
    (failure,) = events(sink, "parse_failure")
    assert failure.detail == {
        "inode": access.stat().st_ino,
        "offset": len(numbered(1, 1)),
        "bytes": len(huge),
        "sha256": sha256_hex(huge),
        "reason": "line_too_long",
    }


def test_overlong_line_with_no_end_does_not_grow_memory_and_is_logged_at_rotation(
    make_reader, access, sink
):
    append(access, b"B" * (2 * MAX_LINE_BYTES))
    reader = make_reader(max_bytes_per_poll=10 * 1024 * 1024)
    assert reader.poll() == []
    assert len(reader._buf) == 0  # hashed, not kept
    append(access, b"B" * MAX_LINE_BYTES)
    reader.poll()
    rotate(access)
    append(access, numbered(1, 1))
    seen = uris(reader.poll()) + uris(reader.poll())
    assert seen == expect_uris(1, 1)
    (failure,) = events(sink, "parse_failure")
    assert failure.detail["reason"] == "line_too_long"
    assert failure.detail["bytes"] == 3 * MAX_LINE_BYTES
    assert failure.detail["sha256"] == sha256_hex(b"B" * (3 * MAX_LINE_BYTES))


def test_a_flood_of_bad_lines_is_bounded_in_the_signed_log_and_fully_counted(
    make_reader, access, sink, clock
):
    bad = [b"junk line %d " % n + MARKER for n in range(5000)]
    append(access, b"".join(raw + b"\n" for raw in bad) + numbered(1, 1))
    reader = make_reader(failure_detail_budget=100, failure_window_ms=60_000)
    records = []
    while batch := reader.poll():
        records += batch
    assert uris(records) == expect_uris(1, 1)  # the real request in the flood is not lost
    assert len(events(sink, "parse_failure")) == 100
    assert events(sink, "parse_failure_rollup") == []
    clock.advance(60_000)
    reader.poll()
    (rollup,) = events(sink, "parse_failure_rollup")
    assert rollup.detail["count"] == 4900
    digest = hashlib.sha256()
    for raw in bad[100:]:
        digest.update(hashlib.sha256(raw).digest())
    assert rollup.detail["digest"] == digest.hexdigest()
    offsets = [sum(len(raw) + 1 for raw in bad[:n]) for n in (100, 4999)]
    assert [rollup.detail["first_offset"], rollup.detail["last_offset"]] == offsets
    assert len(events(sink)) == 101
    assert MARKER not in sink.path.read_bytes()


def test_failure_budget_refills_each_window_and_close_flushes_the_count(
    make_reader, access, sink, clock
):
    reader = make_reader(failure_detail_budget=2, failure_window_ms=1000)
    append(access, b"bad\n" * 5)
    reader.poll()
    clock.advance(1000)
    append(access, b"bad\n" * 5)
    reader.poll()
    reader.close()
    assert len(events(sink, "parse_failure")) == 4
    assert [e.detail["count"] for e in events(sink, "parse_failure_rollup")] == [3, 3]


def test_committed_parse_failures_are_accounted_for_after_restart(
    make_reader, access, sink, monkeypatch
):
    malformed = b"invalid log record"
    append(access, malformed + b"\n")
    before = make_reader(failure_detail_budget=0)
    assert before.poll() == []
    before.commit()
    assert events(sink, "parse_failure_rollup") == []

    # Simulate shutdown without allowing the in-memory summary to flush.
    monkeypatch.setattr(before, "_flush_failures", lambda: None)
    before.close()
    after = make_reader(failure_detail_budget=0)
    assert after.poll() == []
    after.close()

    (rollup,) = events(sink, "parse_failure_rollup")
    assert rollup.detail["count"] == 1
    assert rollup.detail["digest"] == sha256_hex(hashlib.sha256(malformed).digest())
    assert rollup.detail["first_offset"] == rollup.detail["last_offset"] == 0
    (first, last) = rollup.detail["first_inode"], rollup.detail["last_inode"]
    assert first == last == access.stat().st_ino

    make_reader().close()
    assert len(events(sink, "parse_failure_rollup")) == 1


def test_clean_close_preserves_the_cursor_and_does_not_republish_its_rollup(
    make_reader, access, sink
):
    append(access, b"invalid log record\n")
    before = make_reader(failure_detail_budget=0)
    before.poll()
    before.commit()
    append(access, numbered(1, 1))
    assert uris(before.poll()) == expect_uris(1, 1)
    before.close()

    after = make_reader(failure_detail_budget=0)
    assert uris(after.poll()) == expect_uris(1, 1)
    after.close()
    assert len(events(sink, "parse_failure_rollup")) == 1


# -- lag and staleness --------------------------------------------------------------


def test_lag_is_measured_logged_and_cleared(make_reader, access, sink, clock):
    append(access, numbered(1, 400, ts_ms=NOW_MS - 45_000))
    size = access.stat().st_size
    reader = make_reader(
        max_bytes_per_poll=8192, lag_bytes_threshold=16_384, lag_ms_threshold=30_000
    )
    assert reader.lag().bytes_behind == size
    reader.poll()
    lag = reader.lag()
    assert 0 < lag.bytes_behind < size and lag.ms_behind == 45_000
    (first,) = events(sink, "reader_lag")
    assert first.detail == {"bytes_behind": lag.bytes_behind, "ms_behind": 45_000}
    while reader.poll():
        clock.advance(10)
    reader.poll()
    assert reader.lag().bytes_behind == 0 and reader.lag().ms_behind == 0
    assert len(events(sink, "reader_lag")) == 1  # once per interval, not once per poll
    assert len(events(sink, "reader_caught_up")) == 1


def test_lag_is_reported_again_each_interval_while_it_lasts(make_reader, access, sink, clock):
    append(access, numbered(1, 400))
    reader = make_reader(max_bytes_per_poll=1024, lag_bytes_threshold=2048)
    for _ in range(5):
        reader.poll()
        clock.advance(20_000)
    assert len(events(sink, "reader_lag")) == 2
    assert events(sink, "reader_caught_up") == []


def test_lag_counts_a_new_file_waiting_behind_the_old_one(make_reader, access):
    append(access, numbered(1, 2))
    reader = make_reader()
    reader.poll()
    rotate(access)
    append(access, numbered(3, 9))
    assert reader.lag().bytes_behind == access.stat().st_size


def test_backlog_after_downtime_is_marked_stale_and_logged(make_reader, access, sink, clock):
    append(access, numbered(1, 50, ts_ms=NOW_MS - 3_600_000))
    append(access, numbered(51, 52, ts_ms=NOW_MS - 300_001))
    append(access, numbered(53, 55, ts_ms=NOW_MS - 1000))
    reader = make_reader()
    records = reader.poll()
    assert [r.stale for r in records] == [True] * 52 + [False] * 3
    (backlog,) = events(sink, "stale_backlog")
    assert backlog.detail == {
        "count": 52,
        "oldest_ts": NOW_MS - 3_600_000,
        "newest_ts": NOW_MS - 300_001,
        "max_age_ms": 300_000,
    }


def test_stale_backlog_is_summarised_once_per_interval_and_at_close(
    make_reader, access, sink, clock
):
    append(access, numbered(1, 300, ts_ms=NOW_MS - 3_600_000))
    reader = make_reader(
        max_bytes_per_poll=4096, lag_bytes_threshold=10**9, lag_ms_threshold=10**12
    )
    total = 0
    while batch := reader.poll():
        total += len(batch)
    reader.close()
    counts = [e.detail["count"] for e in events(sink, "stale_backlog")]
    assert total == 300 and len(counts) == 2 and sum(counts) == 300


# -- misuse ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"max_age_ms": 0},
        {"max_bytes_per_poll": 0},
        {"failure_window_ms": 0},
        {"lag_bytes_threshold": 0},
        {"lag_ms_threshold": 0},
        {"report_interval_ms": 0},
        {"failure_detail_budget": -1},
    ],
)
def test_nonsense_settings_are_refused(make_reader, bad):
    with pytest.raises(ValueError, match="must"):
        make_reader(**bad)


def test_closed_reader_refuses_to_poll(make_reader, access):
    reader = make_reader()
    reader.close()
    reader.close()
    with pytest.raises(ValueError, match="closed"):
        reader.poll()
