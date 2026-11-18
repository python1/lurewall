# SPDX-License-Identifier: AGPL-3.0-only
"""The log writer: chaining, hostile input, roll-ups, the disk floor, checkpoints."""

import errno
import json
import logging
import os
import stat

import pytest

from conftest import HOSTILE_STRINGS, read_lines, signed_line
from lurewall import eventlog, signing
from lurewall.canonical import ZERO_HASH, sha256_hex
from lurewall.entry import CHECKPOINT_KEYS, check_checkpoint, check_entry_line
from lurewall.eventlog import EventLog, LogCorruptError, LogLockedError
from lurewall.verify import verify_log


def entries(log):
    return [check_entry_line(line[:-1], log.public_key_hex) for line in read_lines(log.path)]


def types(log):
    return [item.type for item in entries(log)]


# -- chain ------------------------------------------------------------------


def test_entries_are_chained_and_signed(make_log):
    log = make_log()
    first = log.append("canary_hit", "192.0.2.1", {"path": "/x"})
    second = log.append("decision", "192.0.2.1", {"action": "would_block"})
    assert (first.seq, first.prev_hash) == (1, ZERO_HASH)
    assert (second.seq, second.prev_hash) == (2, first.hash)
    lines = read_lines(log.path)
    assert [sha256_hex(line[:-1]) for line in lines] == [first.hash, second.hash]
    assert set(json.loads(lines[0])) == {
        "seq",
        "ts",
        "type",
        "source",
        "detail",
        "prev_hash",
        "sig",
    }
    assert (log.seq, log.head_hash) == (2, second.hash)
    assert verify_log(log.path, log.public_key_hex).ok


def test_log_file_is_private(make_log):
    log = make_log()
    assert stat.S_IMODE(os.stat(log.path).st_mode) == 0o600


def test_log_path_must_not_be_a_symlink(tmp_path, signer):
    target = tmp_path / "elsewhere"
    target.write_bytes(b"")
    (tmp_path / "events.log").symlink_to(target)
    with pytest.raises(OSError, match=r".*"):
        EventLog(tmp_path / "events.log", signer)


def test_times_are_integers_from_the_clock(make_log, clock):
    log = make_log()
    clock.now = 1234
    assert log.append("probe").ts == 1234
    clock.now = -5  # a broken clock must not produce an invalid entry
    assert log.append("probe").ts == 0
    assert verify_log(log.path, log.public_key_hex).ok


# -- hostile input ------------------------------------------------------------


@pytest.mark.parametrize("text", HOSTILE_STRINGS)
def test_hostile_text_is_one_entry_on_one_line(make_log, text):
    log = make_log()
    log.append("probe", "192.0.2.7", {"ua": text, "path": text, "nested": [{"q": text}]})
    log.append("probe", text[:256], {text: text})
    raw = log.path.read_bytes()
    assert raw.count(b"\n") == 2 and raw.endswith(b"\n")
    assert all(byte == 0x0A or 0x20 <= byte <= 0x7F for byte in raw)
    first, second = entries(log)
    assert first.detail["ua"] == text and first.detail["nested"][0]["q"] == text
    assert second.source == text[:256] and second.detail == {text: text}
    assert verify_log(log.path, log.public_key_hex).ok


def test_a_real_log_line_in_a_user_agent_cannot_add_an_entry(make_log):
    log = make_log()
    log.append("block", "192.0.2.1", {"ttl": 86400})
    genuine = read_lines(log.path)[0].decode()
    forged_unblock = signed_line(
        signing.EurekaSigner.ephemeral(), 2, log.head_hash, type="unblock"
    ).decode()
    log.append("probe", "203.0.113.9", {"ua": "x\n" + genuine + forged_unblock, "path": genuine})
    assert types(log) == ["block", "probe"]
    report = verify_log(log.path, log.public_key_hex)
    assert report.ok and report.entries == 2


def test_floats_in_detail_are_refused_and_nothing_is_written(make_log):
    log = make_log()
    for bad in (float("nan"), float("inf"), float("-inf"), 0.5):
        with pytest.raises(ValueError, match="floats"):
            log.append("probe", None, {"score": bad})
        with pytest.raises(ValueError, match="floats"):
            log.append("probe", None, {"a": [{"b": bad}]}, rollup_key="k")
    assert log.seq == 0 and log.path.read_bytes() == b""


@pytest.mark.parametrize(
    "bad_type", ["", "Probe", "pro be", "probe\n", "9lives", "a" * 65, None, 5]
)
def test_event_type_is_a_fixed_word(make_log, bad_type):
    log = make_log()
    with pytest.raises(ValueError, match="event type"):
        log.append(bad_type)
    assert log.seq == 0


def test_bad_source_or_detail_is_a_programming_error(make_log):
    log = make_log()
    for source in ("x" * 257, 5, b"1.2.3.4"):
        with pytest.raises(ValueError, match="source"):
            log.append("probe", source)
    with pytest.raises(ValueError, match="detail"):
        log.append("probe", None, ["not", "a", "dict"])
    assert log.seq == 0


def test_oversized_detail_keeps_the_event_and_pins_the_hash(make_log):
    log = make_log(max_entry_bytes=2048)
    written = log.append("parse_failure", "192.0.2.1", {"raw": "A" * 5000})
    assert written.detail["oversize"] is True
    assert written.detail["bytes"] > 5000 and len(written.detail["sha256"]) == 64
    assert len(read_lines(log.path)[0]) <= 2048
    assert verify_log(log.path, log.public_key_hex).ok


# -- reopening ----------------------------------------------------------------


def test_reopening_continues_the_chain(make_log):
    log = make_log()
    log.append("probe")
    second = log.append("probe")
    log.close()
    again = make_log()
    assert (again.seq, again.head_hash) == (2, second.hash)
    assert again.append("probe").prev_hash == second.hash
    assert verify_log(again.path, again.public_key_hex).entries == 3


def test_only_one_writer_at_a_time(make_log):
    make_log()
    with pytest.raises(LogLockedError):
        make_log()


def test_closed_log_refuses_use(make_log):
    log = make_log()
    log.close()
    log.close()  # harmless
    with pytest.raises(ValueError, match="closed"):
        log.append("probe")
    with pytest.raises(ValueError, match="closed"):
        log.tick()


def test_a_different_key_will_not_extend_the_log(make_log):
    log = make_log()
    log.append("probe")
    log.close()
    with pytest.raises(LogCorruptError, match="bad_signature"):
        make_log(signer=signing.EurekaSigner.ephemeral())
    assert len(read_lines(log.path)) == 1  # untouched


@pytest.mark.parametrize(
    "garbage",
    [b"not json\n", b"{}\n", b"\n", b'{"seq":2}\n', b"\xff\xfe\n", b"A" * 3_000_000 + b"\n"],
)
def test_a_corrupt_last_line_is_never_extended(make_log, garbage):
    log = make_log()
    log.append("probe")
    log.close()
    before = log.path.read_bytes() + garbage
    log.path.write_bytes(before)
    with pytest.raises(LogCorruptError):
        make_log()
    assert log.path.read_bytes() == before


def test_a_cut_off_final_write_is_removed_and_recorded(make_log):
    log = make_log()
    log.append("probe")
    kept = log.append("probe")
    log.close()
    torn = b'{"detail":{"ua":"half a li'
    with open(log.path, "ab") as handle:
        handle.write(torn)
    again = make_log()
    repaired = entries(again)[-1]
    assert repaired.type == "torn_tail_repaired"
    assert repaired.detail == {"bytes": len(torn), "sha256": sha256_hex(torn)}
    assert (repaired.seq, repaired.prev_hash) == (3, kept.hash)
    assert verify_log(again.path, again.public_key_hex).ok


def test_a_cut_off_only_line_leaves_an_empty_log(make_log, tmp_path):
    (tmp_path / "events.log").write_bytes(b'{"detail":')
    log = make_log()
    assert types(log) == ["torn_tail_repaired"] and log.seq == 1


def test_an_endless_unterminated_tail_is_refused(make_log, tmp_path):
    (tmp_path / "events.log").write_bytes(b"A" * (2 * 1024 * 1024 + 500))
    with pytest.raises(LogCorruptError):
        make_log()


# -- roll-ups -------------------------------------------------------------------


def test_repeats_are_counted_not_written(make_log, clock):
    log = make_log(rollup_window_ms=60_000)
    assert log.append("probe", "192.0.2.1", {"path": "/.env"}, rollup_key="env") is not None
    start = clock.now
    for _ in range(500):
        clock.advance(10)
        assert log.append("probe", "192.0.2.1", {"path": "/.env"}, rollup_key="env") is None
    assert types(log) == ["probe"]
    clock.now = start + 60_000
    log.tick()
    rollup = entries(log)[-1]
    assert (rollup.type, rollup.source) == ("rollup", "192.0.2.1")
    assert rollup.detail == {
        "of": "probe",
        "key": "env",
        "count": 500,
        "first_ts": start,
        "last_ts": start + 5000,
    }


def test_a_flood_cannot_grow_the_log_one_line_per_request(make_log, clock):
    log = make_log(rollup_window_ms=60_000)
    for _ in range(600):  # ten minutes of flood, 100 requests a second
        for _ in range(100):
            log.append("rate_limited", "203.0.113.5", {"status": 429}, rollup_key="429")
        clock.advance(1000)
    log.close()
    found = entries(log)
    assert len(found) <= 12  # one first sighting, then one roll-up per minute
    counted = sum(item.detail["count"] for item in found if item.type == "rollup")
    assert counted + 1 == 60_000  # every request is accounted for
    assert verify_log(log.path, log.public_key_hex).ok


def test_a_real_probe_during_a_flood_is_written_at_once(make_log, clock):
    log = make_log()
    for index in range(5000):
        log.append("rate_limited", "203.0.113.5", None, rollup_key="429")
        if index == 2500:
            real = log.append("probe", "203.0.113.5", {"path": "/.git/config"}, rollup_key="git")
            other = log.append("probe", "198.51.100.2", {"path": "/.env"}, rollup_key="env")
            assert real is not None and other is not None
        clock.advance(1)
    assert types(log) == ["rate_limited", "probe", "probe"]


def test_keys_are_separate_per_type_source_and_key(make_log):
    log = make_log()
    assert log.append("probe", "a", rollup_key="k") is not None
    assert log.append("probe", "b", rollup_key="k") is not None
    assert log.append("probe", "a", rollup_key="other") is not None
    assert log.append("canary_hit", "a", rollup_key="k") is not None
    assert log.append("probe", None, rollup_key="k") is not None
    assert log.append("probe", "a", rollup_key="k") is None


def test_an_idle_key_is_forgotten_and_a_busy_one_keeps_rolling(make_log, clock):
    log = make_log(rollup_window_ms=1000)
    log.append("probe", "a", rollup_key="k")
    log.append("probe", "a", rollup_key="k")
    clock.advance(1000)
    log.tick()  # writes the roll-up, keeps suppressing
    assert types(log) == ["probe", "rollup"]
    assert log.append("probe", "a", rollup_key="k") is None
    clock.advance(1000)
    log.tick()
    clock.advance(1000)
    log.tick()  # a whole window with no repeats: forgotten
    assert types(log) == ["probe", "rollup", "rollup"]
    assert log.append("probe", "a", rollup_key="k") is not None


def test_rollup_state_is_bounded_and_drops_are_counted(make_log, clock):
    log = make_log(rollup_max_keys=8)
    for index in range(50):
        log.append("probe", f"198.51.100.{index}", rollup_key="k")
        log.append("probe", f"198.51.100.{index}", rollup_key="k")
    assert len(log._rolls) == 8
    clock.advance(1000)
    log.tick()
    found = entries(log)
    evicted = [item for item in found if item.type == "rollup_evicted"]
    assert [item.detail for item in evicted] == [{"count": 42}]
    rollups = [item for item in found if item.type == "rollup"]
    assert len(rollups) == 42 and all(item.detail["count"] == 1 for item in rollups)
    log.tick()
    assert len([item for item in entries(log) if item.type == "rollup_evicted"]) == 1


def test_close_writes_pending_counts(make_log):
    log = make_log()
    for _ in range(4):
        log.append("probe", "a", rollup_key="k")
    log.close()
    assert types(log) == ["probe", "rollup"]
    assert entries(log)[-1].detail["count"] == 3


def test_rollup_key_must_be_a_short_string(make_log):
    log = make_log()
    for bad in ("k" * 257, 5, b"k"):
        with pytest.raises(ValueError, match="rollup_key"):
            log.append("probe", "a", rollup_key=bad)


def test_a_clock_that_jumps_backwards_does_no_harm(make_log, clock):
    log = make_log(rollup_window_ms=1000)
    log.append("probe", "a", rollup_key="k")
    clock.advance(-10_000_000)
    assert log.append("probe", "a", rollup_key="k") is None
    log.tick()
    clock.advance(20_000_000)
    log.tick()
    assert types(log) == ["probe", "rollup"]
    assert verify_log(log.path, log.public_key_hex).ok


# -- free-disk floor ------------------------------------------------------------


def test_writer_stops_below_the_floor_and_says_so_once(make_log, disk):
    log = make_log(disk_floor_bytes=1000)
    log.append("probe")
    disk.free = 999
    for _ in range(50):
        assert log.append("probe", "a", {"path": "/admin"}) is None
    assert log.stopped and log.dropped == 50
    stopped = entries(log)[-1]
    assert types(log) == ["probe", "writer_stopped"]
    assert stopped.detail == {"free_bytes": 999, "floor_bytes": 1000}


def test_writer_resumes_and_reports_what_it_dropped(make_log, disk, clock):
    log = make_log(disk_floor_bytes=1000)
    disk.free = 10
    for _ in range(7):
        log.append("probe")
    for _ in range(5):
        log.append("probe", "a", rollup_key="k")
    disk.free = 5000
    assert log.append("probe", "b") is not None
    assert not log.stopped and log.dropped == 0
    assert types(log) == ["writer_stopped", "writer_resumed", "probe"]
    # 7 plain events and the first sighting of the rolled-up one were dropped.
    assert entries(log)[1].detail == {"dropped": 8, "stop_recorded": True}
    # Its 4 repeats were only ever counted, so they still arrive as a roll-up.
    log.close()
    assert entries(log)[-1].detail["count"] == 4
    assert verify_log(log.path, log.public_key_hex).ok


def test_rollup_counts_lost_while_stopped_are_counted_as_dropped(make_log, disk, clock):
    log = make_log(disk_floor_bytes=1000, rollup_window_ms=1000)
    for _ in range(10):
        log.append("probe", "a", rollup_key="k")
    disk.free = 0
    clock.advance(1000)
    log.tick()  # the roll-up of 9 cannot be written
    assert log.dropped == 9
    disk.free = 5000
    log.append("probe", "b")
    assert entries(log)[-2].detail["dropped"] == 9


def test_unreadable_disk_state_counts_as_full(make_log):
    def broken(_path):
        raise OSError(errno.EIO, "statvfs failed")

    log = make_log(disk_free=broken, disk_floor_bytes=1)
    assert log.append("probe") is None and log.stopped


def test_disk_full_mid_write_leaves_no_partial_line(make_log, monkeypatch, disk):
    log = make_log(disk_floor_bytes=1000)
    log.append("probe")
    whole = log.path.read_bytes()
    real_write = os.write

    def failing_write(fd, data):
        if fd == log._fd:
            real_write(fd, bytes(data[:20]))  # part of the line lands, then the disk fills
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(eventlog.os, "write", failing_write)
    assert log.append("probe", "a", {"path": "/.env"}) is None
    assert log.path.read_bytes() == whole
    assert log.stopped and log.dropped == 1 and log.seq == 1

    monkeypatch.setattr(eventlog.os, "write", real_write)
    assert log.append("probe") is not None
    assert types(log) == ["probe", "writer_resumed", "probe"]
    assert entries(log)[1].detail == {"dropped": 1, "stop_recorded": False}
    assert verify_log(log.path, log.public_key_hex).ok


def test_other_write_errors_surface_and_leave_no_partial_line(make_log, monkeypatch):
    log = make_log()
    log.append("probe")
    whole = log.path.read_bytes()
    real_write = os.write

    def failing_write(fd, data):
        if fd == log._fd:
            real_write(fd, bytes(data[:20]))
            raise OSError(errno.EIO, "I/O error")
        return real_write(fd, data)

    monkeypatch.setattr(eventlog.os, "write", failing_write)
    with pytest.raises(OSError, match="I/O error"):
        log.append("probe")
    monkeypatch.setattr(eventlog.os, "write", real_write)
    assert log.path.read_bytes() == whole and log.seq == 1


# -- checkpoints ------------------------------------------------------------------


def read_checkpoint(log, path):
    return check_checkpoint(json.loads(path.read_bytes()), log.public_key_hex)


def test_checkpoint_every_n_entries(make_log, tmp_path):
    path = tmp_path / "checkpoint.json"
    log = make_log(checkpoint_path=path, checkpoint_every=10, checkpoint_interval_ms=10**12)
    log.checkpoint()  # sets the time base; nothing to sign yet
    assert not path.exists()
    hashes = [log.append("probe").hash for _ in range(9)]
    first = read_checkpoint(log, path)  # the first entry is checkpointed straight away
    assert first["seq"] == 1 and first["head_hash"] == hashes[0]
    hashes += [log.append("probe").hash for _ in range(16)]
    latest = read_checkpoint(log, path)
    assert latest["seq"] == 21 and latest["head_hash"] == hashes[20]


def test_checkpoint_after_t_milliseconds_even_with_no_new_events(make_log, tmp_path, clock):
    path = tmp_path / "checkpoint.json"
    log = make_log(checkpoint_path=path, checkpoint_every=10**9, checkpoint_interval_ms=300_000)
    log.append("probe")
    log.append("probe")
    last = log.append("probe")
    assert read_checkpoint(log, path)["seq"] == 1
    clock.advance(299_999)
    log.tick()
    assert read_checkpoint(log, path)["seq"] == 1
    clock.advance(1)
    log.tick()
    checkpoint = read_checkpoint(log, path)
    assert (checkpoint["seq"], checkpoint["head_hash"], checkpoint["ts"]) == (
        3,
        last.hash,
        clock.now,
    )


def test_checkpoint_holds_hashes_only(make_log, tmp_path):
    path = tmp_path / "checkpoint.json"
    log = make_log(checkpoint_path=path, checkpoint_every=1)
    log.append("canary_hit", "203.0.113.77", {"ua": "SecretAgent/9", "path": "/private-decoy"})
    raw = path.read_bytes()
    assert set(json.loads(raw)) == CHECKPOINT_KEYS == {"seq", "head_hash", "ts", "sig"}
    for leaked in (b"203.0.113.77", b"SecretAgent", b"private-decoy", b"canary_hit"):
        assert leaked not in raw
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    assert [item.name for item in tmp_path.iterdir() if item.name.startswith(".checkpoint-")] == []


@pytest.mark.parametrize("alias", [False, True], ids=["same-path", "directory-alias"])
def test_checkpoint_target_cannot_share_the_event_log(make_log, tmp_path, alias):
    log = make_log()
    log.append("probe")
    log.close()
    original = log.path.read_bytes()
    checkpoint_path = log.path
    if alias:
        directory_alias = tmp_path / "alias"
        directory_alias.symlink_to(tmp_path, target_is_directory=True)
        checkpoint_path = directory_alias / log.path.name

    with pytest.raises(ValueError, match="checkpoint path must differ from the event log"):
        make_log(checkpoint_path=checkpoint_path)

    assert log.path.read_bytes() == original


def test_close_writes_a_final_checkpoint(make_log, tmp_path):
    path = tmp_path / "checkpoint.json"
    log = make_log(checkpoint_path=path, checkpoint_every=10**9, checkpoint_interval_ms=10**12)
    log.append("probe")
    for _ in range(3):
        log.append("probe", "a", rollup_key="k")
    log.close()
    final = entries(log)[-1]
    assert final.type == "rollup"
    checkpoint = read_checkpoint(log, path)
    assert (checkpoint["seq"], checkpoint["head_hash"]) == (final.seq, final.hash)


def test_restart_does_not_lose_the_checkpoint_position(make_log, tmp_path):
    path = tmp_path / "checkpoint.json"
    settings = {"checkpoint_path": path, "checkpoint_every": 5, "checkpoint_interval_ms": 10**12}
    log = make_log(**settings)
    for _ in range(3):
        log.append("probe")
    log.close()
    assert read_checkpoint(log, path)["seq"] == 3
    again = make_log(**settings)
    for _ in range(4):
        again.append("probe")
    assert read_checkpoint(again, path)["seq"] == 3
    again.append("probe")
    assert read_checkpoint(again, path)["seq"] == 8


@pytest.mark.parametrize("reason", ["missing", "unreadable", "invalid"])
def test_unavailable_checkpoint_warns_and_keeps_logging(make_log, tmp_path, caplog, reason):
    original = make_log()
    first = original.append("probe")
    original.close()
    path = tmp_path / "checkpoint.json"
    if reason == "unreadable":
        path.mkdir()
    elif reason == "invalid":
        path.write_bytes(b"invalid checkpoint fixture")

    again = make_log(checkpoint_path=path)

    assert caplog.record_tuples == [
        (
            eventlog.__name__,
            logging.WARNING,
            f"startup checkpoint check skipped: configured file is {reason}",
        )
    ]
    assert again.seq == first.seq
    assert again.append("probe").prev_hash == first.hash
    assert verify_log(again.path, again.public_key_hex).ok


def test_unconfigured_checkpoint_needs_no_warning(make_log, caplog):
    make_log()
    assert caplog.record_tuples == []


def test_restart_refuses_a_log_shorter_than_its_checkpoint(make_log, tmp_path):
    checkpoint_path = tmp_path / "checkpoint.json"
    log = make_log(checkpoint_path=checkpoint_path)
    log.append("probe")
    log.append("probe")
    log.close()
    checkpoint = checkpoint_path.read_bytes()
    first, last = read_lines(log.path)
    interrupted = first + last[:-1]
    log.path.write_bytes(interrupted)

    with pytest.raises(LogCorruptError, match="checkpoint"):
        make_log(checkpoint_path=checkpoint_path)

    assert log.path.read_bytes() == interrupted
    assert checkpoint_path.read_bytes() == checkpoint


def test_restart_refuses_a_log_head_that_disagrees_with_its_checkpoint(make_log, tmp_path):
    checkpoint_path = tmp_path / "checkpoint.json"
    original = make_log(checkpoint_path=checkpoint_path)
    original.append("probe")
    original.close()
    checkpoint = checkpoint_path.read_bytes()
    backup = make_log(name="backup.log")
    backup.append("probe", detail={"fixture": "backup"})
    backup.close()
    restored = backup.path.read_bytes()
    original.path.write_bytes(restored)

    with pytest.raises(LogCorruptError, match="checkpoint"):
        make_log(checkpoint_path=checkpoint_path)

    assert original.path.read_bytes() == restored
    assert checkpoint_path.read_bytes() == checkpoint


def test_restart_repairs_a_torn_write_after_the_checkpoint(make_log, tmp_path):
    checkpoint_path = tmp_path / "checkpoint.json"
    log = make_log(checkpoint_path=checkpoint_path)
    checkpointed = log.append("probe")
    log.close()
    torn = b'{"detail":'
    log.path.write_bytes(log.path.read_bytes() + torn)

    restarted = make_log(checkpoint_path=checkpoint_path)

    repaired = entries(restarted)[-1]
    assert (repaired.type, repaired.prev_hash) == ("torn_tail_repaired", checkpointed.hash)
    assert verify_log(log.path, log.public_key_hex).ok


@pytest.mark.parametrize("junk", [b"", b"not json", b"[]", b'{"seq":999}', b"[" * 100_000])
def test_an_unusable_checkpoint_file_is_replaced(make_log, tmp_path, junk):
    path = tmp_path / "checkpoint.json"
    path.write_bytes(junk)
    log = make_log(checkpoint_path=path, checkpoint_every=1)
    log.append("probe")
    assert read_checkpoint(log, path)["seq"] == 1


def test_a_checkpoint_from_another_key_is_ignored(make_log, tmp_path):
    path = tmp_path / "checkpoint.json"
    other = make_log(
        name="other.log", signer=signing.EurekaSigner.ephemeral(), checkpoint_path=path
    )
    for _ in range(3):
        other.append("probe")
    other.close()
    log = make_log(checkpoint_path=path, checkpoint_every=2, checkpoint_interval_ms=10**12)
    assert log._checkpoint_seq == 0


def test_checkpoint_failure_is_logged_once_per_interval_not_per_entry(make_log, tmp_path, clock):
    path = tmp_path / "no-such-directory" / "checkpoint.json"
    log = make_log(checkpoint_path=path, checkpoint_every=1, checkpoint_interval_ms=60_000)
    for _ in range(100):
        log.append("probe")
    assert types(log).count("checkpoint_error") == 1
    assert entries(log)[1].detail == {"errno": errno.ENOENT}
    clock.advance(60_000)
    log.append("probe")
    assert types(log).count("checkpoint_error") == 2
    path.parent.mkdir()
    clock.advance(60_000)
    log.append("probe")
    assert read_checkpoint(log, path)["seq"] == log.seq
    assert verify_log(log.path, log.public_key_hex).ok


@pytest.mark.parametrize(
    "bad",
    [
        {"max_entry_bytes": 10},
        {"max_entry_bytes": 10**9},
        {"checkpoint_every": 0},
        {"checkpoint_interval_ms": 0},
        {"rollup_window_ms": 0},
        {"rollup_max_keys": 0},
        {"disk_floor_bytes": -1},
    ],
)
def test_nonsense_settings_are_refused(tmp_path, signer, bad):
    with pytest.raises(ValueError, match="must"):
        EventLog(tmp_path / "events.log", signer, **bad)
