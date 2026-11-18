# SPDX-License-Identifier: AGPL-3.0-only
"""Tail nginx's access log: every line becomes a record or a logged failure.

The reader never sits in the request path. It follows one file, survives
logrotate, resumes from a saved offset after a restart, and accounts for every
byte it passes over:

* A line that parses is returned as a ``Record``.
* A line that does not parse is written to the signed log as a
  ``parse_failure`` event with its offset, length and hash. Past a per-window
  budget, failures are counted in one ``parse_failure_rollup`` event that pins
  them with a digest, so a flood of bad lines cannot grow the signed log one
  entry per line, and still none goes unrecorded.
* Anything the reader could not read at all (a rotated file that is gone, a
  file cut short under it) is written as an event saying so.

Delivery is at-least-once. ``poll`` returns records; the caller handles them
and then calls ``commit``, which saves the offset. After a crash between the
two, the same lines are read again rather than lost. Pending failure roll-ups
are saved with the offset and published when a reader resumes.

The reader also reports its own lag behind the access log, and marks records
older than the staleness limit so nothing downstream enforces on a backlog.

No event written here contains log content. Line text is attacker-controlled;
events carry offsets, lengths, hashes and fixed reason words only.
"""

from __future__ import annotations

import contextlib
import hashlib
import itertools
import json
import os
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Protocol

from lurewall import accesslog
from lurewall.accesslog import MAX_LINE_BYTES, ParseFailure, Record
from lurewall.canonical import MAX_INT, sha256_hex
from lurewall.entry import is_hash

DEFAULT_MAX_AGE_MS = 5 * 60 * 1000
DEFAULT_MAX_BYTES_PER_POLL = 1024 * 1024
DEFAULT_FAILURE_DETAIL_BUDGET = 100
DEFAULT_FAILURE_WINDOW_MS = 60_000
DEFAULT_LAG_BYTES_THRESHOLD = 1024 * 1024
DEFAULT_LAG_MS_THRESHOLD = 30_000
DEFAULT_REPORT_INTERVAL_MS = 60_000

_CHUNK_BYTES = 64 * 1024
_HEAD_BYTES = 256
_READ_TAIL_BYTES = 256
_STATE_VERSION = 1
_MAX_STATE_BYTES = 4096
_MAX_ROTATED_CANDIDATES = 10_000
_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
_ROLLUP_COUNTS = ("count", "first_inode", "first_offset", "last_inode", "last_offset")


class Sink(Protocol):
    """Where the reader writes its own events. ``EventLog`` fits."""

    def append(
        self,
        type: str,
        source: str | None = None,
        detail: dict | None = None,
        *,
        rollup_key: str | None = None,
    ) -> object: ...


@dataclass(frozen=True)
class Lag:
    bytes_behind: int  # logged bytes not yet processed
    ms_behind: int  # age of the last processed record, while bytes remain


@dataclass(frozen=True)
class _Saved:
    dev: int
    inode: int
    offset: int
    head_len: int
    head_sha256: str
    failure_rollup: dict | None = None


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _is_count(value: object) -> bool:
    return type(value) is int and value >= 0


class LogReader:
    def __init__(
        self,
        path: str | Path,
        state_path: str | Path,
        sink: Sink,
        *,
        max_age_ms: int = DEFAULT_MAX_AGE_MS,
        max_bytes_per_poll: int = DEFAULT_MAX_BYTES_PER_POLL,
        failure_detail_budget: int = DEFAULT_FAILURE_DETAIL_BUDGET,
        failure_window_ms: int = DEFAULT_FAILURE_WINDOW_MS,
        lag_bytes_threshold: int = DEFAULT_LAG_BYTES_THRESHOLD,
        lag_ms_threshold: int = DEFAULT_LAG_MS_THRESHOLD,
        report_interval_ms: int = DEFAULT_REPORT_INTERVAL_MS,
        clock: Callable[[], int] = _now_ms,
    ) -> None:
        for name, value in (
            ("max_age_ms", max_age_ms),
            ("max_bytes_per_poll", max_bytes_per_poll),
            ("failure_window_ms", failure_window_ms),
            ("lag_bytes_threshold", lag_bytes_threshold),
            ("lag_ms_threshold", lag_ms_threshold),
            ("report_interval_ms", report_interval_ms),
        ):
            if value < 1:
                raise ValueError(f"{name} must be positive")
        if failure_detail_budget < 0:
            raise ValueError("failure_detail_budget must not be negative")

        self.path = Path(path)
        self.state_path = Path(state_path)
        self._sink = sink
        self._max_age_ms = max_age_ms
        self._max_bytes_per_poll = max_bytes_per_poll
        self._failure_detail_budget = failure_detail_budget
        self._failure_window_ms = failure_window_ms
        self._lag_bytes_threshold = lag_bytes_threshold
        self._lag_ms_threshold = lag_ms_threshold
        self._report_interval_ms = report_interval_ms
        self._clock = clock

        # The file being read.
        self._fd: int | None = None
        self._dev = 0
        self._inode = 0
        self._read_pos = 0  # next byte to read
        self._read_tail = b""  # bytes immediately before the next read
        self._line_start = 0  # offset of the first byte not yet turned into a line
        self._buf = b""  # the unfinished line, when it is short enough to keep
        self._long_hash: hashlib._Hash | None = None  # set while skipping an overlong line
        self._long_len = 0
        self._rotation_polls = 0

        # Reporting state.
        self._fail_window_start: int | None = None
        self._fail_detailed = 0
        self._roll_count = 0
        self._roll_first: tuple[int, int] | None = None
        self._roll_last: tuple[int, int] | None = None
        self._roll_digest = hashlib.sha256()
        self._last_record_ts: int | None = None
        self._lag_reported = False
        self._lag_reported_at: int | None = None
        self._stale_count = 0
        self._stale_oldest = 0
        self._stale_newest = 0
        self._stale_reported_at: int | None = None
        self._unavailable_reported_at: int | None = None
        self._closed = False

        self._saved = self._load_state()
        self._committed = self._saved
        if self._saved is not None and self._saved.failure_rollup is not None:
            # The old process's digest is complete for its committed segment.
            # Publish it separately so subsequent windows keep the same digest format.
            self._sink.append("parse_failure_rollup", None, self._saved.failure_rollup)
            self._clear_committed_rollup()

    # -- saved offset ---------------------------------------------------------

    def _load_state(self) -> _Saved | None:
        try:
            with open(self.state_path, "rb") as handle:
                raw = handle.read(_MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            return None
        except OSError:
            self._sink.append("reader_state_invalid", None, {"reason": "unreadable"})
            return None
        try:
            obj = json.loads(raw)
            if (
                len(raw) > _MAX_STATE_BYTES
                or type(obj) is not dict
                or obj.get("v") != _STATE_VERSION
            ):
                raise ValueError("version")
            saved = _Saved(
                dev=obj["dev"],
                inode=obj["inode"],
                offset=obj["offset"],
                head_len=obj["head_len"],
                head_sha256=obj["head_sha256"],
                failure_rollup=obj.get("failure_rollup"),
            )
            if not (
                all(_is_count(v) for v in (saved.dev, saved.inode, saved.offset, saved.head_len))
                and saved.head_len <= _HEAD_BYTES
                and type(saved.head_sha256) is str
            ):
                raise ValueError("fields")
            rollup = saved.failure_rollup
            if rollup is not None and not (
                type(rollup) is dict
                and set(rollup) == {*_ROLLUP_COUNTS, "digest"}
                and is_hash(rollup["digest"])
                and all(_is_count(rollup[key]) and rollup[key] <= MAX_INT for key in _ROLLUP_COUNTS)
                and rollup["count"] > 0
            ):
                raise ValueError("failure_rollup")
        except (ValueError, KeyError, RecursionError):
            # Starting again from the top re-reads lines; it never skips any.
            self._sink.append("reader_state_invalid", None, {"reason": "not_valid"})
            return None
        return saved

    def commit(self) -> None:
        """Save the position after the last complete line handed out by ``poll``.

        Call it once the records from ``poll`` have been dealt with.
        """
        if self._fd is None:
            return
        self._check_truncated()
        head_len = min(_HEAD_BYTES, self._line_start)
        self._write_state(
            _Saved(
                self._dev,
                self._inode,
                self._line_start,
                head_len,
                sha256_hex(os.pread(self._fd, head_len, 0)),
                self._failure_rollup(),
            )
        )

    def _write_state(self, saved: _Saved) -> None:
        data = (json.dumps({"v": _STATE_VERSION, **asdict(saved)}, sort_keys=True) + "\n").encode(
            "ascii"
        )
        fd, temp_name = tempfile.mkstemp(
            dir=self.state_path.parent, prefix=".reader-state-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "wb") as handle:  # mkstemp creates the file 0600
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.state_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp_name)
            raise
        self._committed = saved

    def _clear_committed_rollup(self) -> None:
        if self._committed is not None and self._committed.failure_rollup is not None:
            # An interruption between the append and this write can replay the
            # summary, just as it can replay records before their cursor is saved.
            self._write_state(replace(self._committed, failure_rollup=None))

    # -- opening and rotation -------------------------------------------------

    def _attach(self, fd: int, info: os.stat_result, start: int) -> None:
        self._fd = fd
        self._dev = info.st_dev
        self._inode = info.st_ino
        self._read_pos = start
        tail_len = min(_READ_TAIL_BYTES, start)
        self._read_tail = os.pread(fd, tail_len, start - tail_len) if tail_len else b""
        self._line_start = start
        self._buf = b""
        self._long_hash = None
        self._long_len = 0
        self._rotation_polls = 0

    def _open_path(self, now: int) -> tuple[int, os.stat_result] | None:
        try:
            fd = os.open(self.path, _OPEN_FLAGS)
        except OSError as exc:
            reason = "missing" if isinstance(exc, FileNotFoundError) else "cannot_open"
            self._report_unavailable(now, reason)
            return None
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            self._report_unavailable(now, "not_a_regular_file")
            return None
        self._unavailable_reported_at = None
        return fd, info

    def _report_unavailable(self, now: int, reason: str) -> None:
        if self._due(self._unavailable_reported_at, now):
            self._unavailable_reported_at = now
            self._sink.append("access_log_unavailable", None, {"reason": reason})

    def _due(self, last: int | None, now: int) -> bool:
        return last is None or not 0 <= now - last < self._report_interval_ms

    def _head_matches(self, fd: int, saved: _Saved) -> bool:
        head = os.pread(fd, saved.head_len, 0)
        return len(head) == saved.head_len and sha256_hex(head) == saved.head_sha256

    def _open_first(self, now: int) -> bool:
        """Open the log, resuming from the saved position where that is still sound."""
        opened = self._open_path(now)
        if opened is None:
            return False
        fd, info = opened
        saved, self._saved = self._saved, None
        if saved is None:
            self._attach(fd, info, 0)
            return True
        gap = {"saved_inode": saved.inode, "saved_offset": saved.offset}
        if (info.st_dev, info.st_ino) == (saved.dev, saved.inode):
            if saved.offset > info.st_size:
                self._sink.append("log_truncated", None, {**gap, "size": info.st_size})
                self._attach(fd, info, 0)
            elif not self._head_matches(fd, saved):
                # Same inode number, different file: the offset means nothing here.
                self._sink.append("rotation_gap", None, {**gap, "reason": "file_replaced"})
                self._attach(fd, info, 0)
            else:
                self._attach(fd, info, saved.offset)
            return True
        rotated = self._find_rotated(saved)
        if rotated is None:
            # The lines between the saved offset and the end of the old file
            # were never read and cannot be now. Say so.
            self._sink.append("rotation_gap", None, {**gap, "reason": "rotated_file_not_found"})
            self._attach(fd, info, 0)
            return True
        # Finish the rotated file first; the usual end-of-file check then moves on.
        os.close(fd)
        self._attach(rotated[0], rotated[1], saved.offset)
        return True

    def _find_rotated(self, saved: _Saved) -> tuple[int, os.stat_result] | None:
        """Find the file the saved offset belongs to, under its rotated name."""
        try:
            entries = os.scandir(self.path.parent)
        except OSError:
            return None
        with entries:
            for index, item in enumerate(entries):
                if index >= _MAX_ROTATED_CANDIDATES:
                    break
                if item.name == self.path.name or not item.name.startswith(self.path.name):
                    continue
                try:
                    info = item.stat(follow_symlinks=False)
                except OSError:
                    continue
                if (info.st_dev, info.st_ino) != (saved.dev, saved.inode):
                    continue
                opened = self._open_rotated(item.path, info)
                if opened is None:
                    continue
                fd, info = opened
                if saved.offset <= info.st_size and self._head_matches(fd, saved):
                    return fd, info
                os.close(fd)
        return None

    @staticmethod
    def _open_rotated(path: str, expected: os.stat_result) -> tuple[int, os.stat_result] | None:
        # A rotation may rename or replace the candidate between stat and open.
        try:
            fd = os.open(path, _OPEN_FLAGS | os.O_NOFOLLOW)
        except OSError:
            return None
        try:
            info = os.fstat(fd)
        except OSError:
            os.close(fd)
            return None
        if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == (
            expected.st_dev,
            expected.st_ino,
        ):
            return fd, info
        os.close(fd)
        return None

    def _next_numbered_rotation(self) -> tuple[tuple[int, os.stat_result] | None, int]:
        """Find the next retained uncompressed rotation and count intervening gaps."""
        prefix = self.path.name + "."
        candidates: dict[int, tuple[str, os.stat_result]] = {}
        current = None
        try:
            with os.scandir(self.path.parent) as entries:
                for item in itertools.islice(entries, _MAX_ROTATED_CANDIDATES):
                    if not item.name.startswith(prefix):
                        continue
                    suffix = item.name.removeprefix(prefix)
                    if not (suffix.isascii() and suffix.isdecimal() and not suffix.startswith("0")):
                        continue
                    try:
                        info = item.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    number = int(suffix)
                    if number > MAX_INT:
                        continue
                    if (info.st_dev, info.st_ino) == (self._dev, self._inode):
                        current = number
                    else:
                        candidates[number] = (item.path, info)
        except OSError:
            return None, 0
        if current is None:
            return None, 0
        for number in sorted(candidates, reverse=True):
            if number >= current:
                continue
            opened = self._open_rotated(*candidates[number])
            if opened is not None:
                return opened, current - number - 1
        return None, current - 1

    def _rotate_if_due(self, now: int) -> bool:
        """At end of file: has the path moved on to a new file? Returns True after a switch.

        nginx keeps writing to the old file until it is told to reopen its
        logs, so the old file is given one more poll to go quiet before the
        reader lets go of it.
        """
        try:
            info = os.stat(self.path)
        except OSError:
            self._rotation_polls = 0
            return False  # nothing new yet: keep the old file
        if (info.st_dev, info.st_ino) == (self._dev, self._inode):
            self._rotation_polls = 0
            return False
        self._rotation_polls += 1
        if self._rotation_polls < 2:
            return False
        opened, missing = self._next_numbered_rotation()
        if opened is None:
            opened = self._open_path(now)
        if opened is None:
            return False
        fd, info = opened
        if (info.st_dev, info.st_ino) == (self._dev, self._inode):
            os.close(fd)
            return False
        old = {"old_inode": self._inode, "old_offset": self._line_start}
        try:
            self._end_file(now)
        except BaseException:
            os.close(fd)
            raise
        self._attach(fd, info, 0)
        if missing:
            self._sink.append(
                "rotation_gap",
                None,
                {**old, "reason": "numbered_rotation_unavailable", "missing": missing},
            )
        self._sink.append("log_rotated", None, {**old, "new_inode": self._inode})
        return True

    def _end_file(self, now: int) -> None:
        """Let go of the current file. A final line with no newline is still accounted for."""
        if self._fd is None:
            return
        if self._long_hash is not None:
            self._failure(
                ParseFailure(
                    self._line_start, self._long_hash.hexdigest(), self._long_len, "line_too_long"
                ),
                now,
            )
        elif self._buf:
            self._failure(
                ParseFailure(
                    self._line_start, sha256_hex(self._buf), len(self._buf), "unterminated_line"
                ),
                now,
            )
        os.close(self._fd)
        self._fd = None
        self._buf = b""
        self._long_hash = None

    def _check_truncated(self) -> None:
        size = os.fstat(self._fd).st_size
        if size >= self._read_pos:
            tail_len = len(self._read_tail)
            if not tail_len or os.pread(self._fd, tail_len, self._read_pos - tail_len) == (
                self._read_tail
            ):
                return
        # A same-inode rewrite can already have grown past the old cursor.
        self._sink.append(
            "log_truncated",
            None,
            {"saved_inode": self._inode, "saved_offset": self._read_pos, "size": size},
        )
        self._read_pos = self._line_start = 0
        self._read_tail = b""
        self._buf = b""
        self._long_hash = None
        self._long_len = 0

    # -- reading --------------------------------------------------------------

    def poll(self) -> list[Record]:
        """Read what is new, up to the per-poll byte limit. Never blocks."""
        if self._closed:
            raise ValueError("log reader is closed")
        now = self._clock()
        records: list[Record] = []
        budget = self._max_bytes_per_poll
        if self._fd is None and not self._open_first(now):
            self._report(now)
            return records
        while budget > 0 and self._fd is not None:
            self._check_truncated()
            chunk = os.pread(self._fd, min(_CHUNK_BYTES, budget), self._read_pos)
            if not chunk:
                if self._rotate_if_due(now):
                    continue
                break
            self._rotation_polls = 0
            self._read_pos += len(chunk)
            self._read_tail = (self._read_tail + chunk[-_READ_TAIL_BYTES:])[-_READ_TAIL_BYTES:]
            budget -= len(chunk)
            self._feed(chunk, records, now)
        self._report(now)
        return records

    def _feed(self, chunk: bytes, records: list[Record], now: int) -> None:
        position = 0
        while True:
            newline = chunk.find(b"\n", position)
            if newline == -1:
                rest = chunk[position:]
                if self._long_hash is not None:
                    self._long_hash.update(rest)
                    self._long_len += len(rest)
                else:
                    self._buf += rest
                    if len(self._buf) > MAX_LINE_BYTES:
                        # Too long to be a log line. Stop keeping it, but keep
                        # hashing it, so its failure event still pins it.
                        self._long_hash = hashlib.sha256(self._buf)
                        self._long_len = len(self._buf)
                        self._buf = b""
                return
            piece = chunk[position:newline]
            position = newline + 1
            if self._long_hash is not None:
                self._long_hash.update(piece)
                length = self._long_len + len(piece)
                self._failure(
                    ParseFailure(
                        self._line_start, self._long_hash.hexdigest(), length, "line_too_long"
                    ),
                    now,
                )
                self._long_hash = None
                self._long_len = 0
            else:
                line = self._buf + piece if self._buf else piece
                self._buf = b""
                length = len(line)
                parsed = accesslog.parse_line(
                    line, self._line_start, now_ms=now, max_age_ms=self._max_age_ms
                )
                if isinstance(parsed, ParseFailure):
                    self._failure(parsed, now)
                else:
                    self._note_record(parsed)
                    records.append(parsed)
            self._line_start += length + 1

    def _note_record(self, record: Record) -> None:
        self._last_record_ts = record.ts_ms
        if record.stale:
            if self._stale_count == 0:
                self._stale_oldest = self._stale_newest = record.ts_ms
            self._stale_count += 1
            self._stale_oldest = min(self._stale_oldest, record.ts_ms)
            self._stale_newest = max(self._stale_newest, record.ts_ms)

    # -- parse failures ---------------------------------------------------------

    def _failure(self, failure: ParseFailure, now: int) -> None:
        start = self._fail_window_start
        if start is None or not 0 <= now - start < self._failure_window_ms:
            self._flush_failures()
            self._fail_window_start = now
            self._fail_detailed = 0
        if self._fail_detailed < self._failure_detail_budget:
            self._fail_detailed += 1
            self._sink.append(
                "parse_failure",
                None,
                {
                    "inode": self._inode,
                    "offset": failure.offset,
                    "bytes": failure.length,
                    "sha256": failure.line_sha256,
                    "reason": failure.reason,
                },
            )
            return
        where = (self._inode, failure.offset)
        if self._roll_count == 0:
            self._roll_first = where
        self._roll_last = where
        self._roll_count += 1
        self._roll_digest.update(bytes.fromhex(failure.line_sha256))

    def _failure_rollup(self) -> dict | None:
        if self._roll_count == 0:
            return None
        first, last = self._roll_first, self._roll_last
        return {
            "count": self._roll_count,
            "first_inode": first[0],
            "first_offset": first[1],
            "last_inode": last[0],
            "last_offset": last[1],
            # SHA-256 over the 32-byte hashes of the failed lines, in order.
            "digest": self._roll_digest.hexdigest(),
        }

    def _flush_failures(self) -> None:
        detail = self._failure_rollup()
        if detail is None:
            return
        self._sink.append("parse_failure_rollup", None, detail)
        self._clear_committed_rollup()
        self._roll_count = 0
        self._roll_first = self._roll_last = None
        self._roll_digest = hashlib.sha256()

    # -- lag and staleness --------------------------------------------------------

    def lag(self) -> Lag:
        """How far the reader is behind the access log right now."""
        behind = 0
        if self._fd is not None:
            behind = max(0, os.fstat(self._fd).st_size - self._line_start)
        with contextlib.suppress(OSError):
            info = os.stat(self.path)
            if self._fd is None or (info.st_dev, info.st_ino) != (self._dev, self._inode):
                behind += info.st_size  # a new file is waiting behind this one
        age = 0
        if behind and self._last_record_ts is not None:
            age = max(0, self._clock() - self._last_record_ts)
        return Lag(bytes_behind=behind, ms_behind=age)

    def _report(self, now: int) -> None:
        start = self._fail_window_start
        if start is not None and not 0 <= now - start < self._failure_window_ms:
            self._flush_failures()
            self._fail_window_start = None

        if self._stale_count and self._due(self._stale_reported_at, now):
            self._stale_reported_at = now
            self._sink.append(
                "stale_backlog",
                None,
                {
                    "count": self._stale_count,
                    "oldest_ts": self._stale_oldest,
                    "newest_ts": self._stale_newest,
                    "max_age_ms": self._max_age_ms,
                },
            )
            self._stale_count = 0

        lag = self.lag()
        lagging = (
            lag.bytes_behind >= self._lag_bytes_threshold or lag.ms_behind >= self._lag_ms_threshold
        )
        if lagging:
            if not self._lag_reported or self._due(self._lag_reported_at, now):
                self._lag_reported = True
                self._lag_reported_at = now
                detail = {"bytes_behind": lag.bytes_behind, "ms_behind": lag.ms_behind}
                self._sink.append("reader_lag", None, detail)
        elif self._lag_reported:
            self._lag_reported = False
            self._sink.append("reader_caught_up", None, {})

    # -- closing ----------------------------------------------------------------

    def close(self) -> None:
        """Write out pending counts and release the file. Does not commit."""
        if self._closed:
            return
        self._closed = True
        try:
            self._flush_failures()
            if self._stale_count:
                detail = {
                    "count": self._stale_count,
                    "oldest_ts": self._stale_oldest,
                    "newest_ts": self._stale_newest,
                    "max_age_ms": self._max_age_ms,
                }
                self._sink.append("stale_backlog", None, detail)
                self._stale_count = 0
        finally:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> LogReader:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
