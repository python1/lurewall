# SPDX-License-Identifier: AGPL-3.0-only
"""The signed, hash-chained event log: the writer.

One writer process appends entries to one file. Each entry is signed and
carries the hash of the line before it (see ``entry.py``). Around that sit the
flood and failure controls:

* **Roll-ups.** A repeat of the same event from the same source is counted, not
  written. The first occurrence is written at once, so nothing waits to be
  seen; the count follows in one ``rollup`` entry per window.
* **Bounded state.** The roll-up table has a fixed size. When it is full the
  least recently seen key is dropped, its count is written out, and the number
  of drops is logged.
* **Free-disk floor.** Below the floor the writer records that it stopped and
  writes nothing more. When space returns it records how many events it
  dropped while stopped.
* **Checkpoints.** Every N entries or T milliseconds the head hash is signed
  and written to a small file for the web server to serve.

All times are integer milliseconds. Not thread-safe: one writer, one thread.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import shutil
import tempfile
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

from lurewall import entry as entry_mod
from lurewall import signing
from lurewall.canonical import ZERO_HASH, canonical_bytes, check_value, sha256_hex
from lurewall.entry import MAX_LINE_BYTES, Entry, EntryError

DEFAULT_MAX_ENTRY_BYTES = 64 * 1024
DEFAULT_DISK_FLOOR_BYTES = 256 * 1024 * 1024
DEFAULT_ROLLUP_WINDOW_MS = 60_000
DEFAULT_ROLLUP_MAX_KEYS = 4096
DEFAULT_CHECKPOINT_EVERY = 100
DEFAULT_CHECKPOINT_INTERVAL_MS = 300_000
MAX_ROLLUP_KEY_CHARS = 256

_HOUSEKEEP_EVERY_MS = 1000
_DISK_FULL_ERRNOS = frozenset({errno.ENOSPC, errno.EDQUOT})


class LogCorruptError(RuntimeError):
    """The existing log does not end in a valid entry signed by this key."""


class LogLockedError(RuntimeError):
    """Another writer holds the log."""


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _disk_free(path: Path) -> int:
    return shutil.disk_usage(path).free


class _Roll:
    __slots__ = ("count", "first_ts", "last_ts", "window_start")

    def __init__(self, now: int) -> None:
        self.count = 0
        self.first_ts = now
        self.last_ts = now
        self.window_start = now


class EventLog:
    def __init__(
        self,
        path: str | Path,
        signer: signing.Signer,
        *,
        checkpoint_path: str | Path | None = None,
        checkpoint_every: int = DEFAULT_CHECKPOINT_EVERY,
        checkpoint_interval_ms: int = DEFAULT_CHECKPOINT_INTERVAL_MS,
        rollup_window_ms: int = DEFAULT_ROLLUP_WINDOW_MS,
        rollup_max_keys: int = DEFAULT_ROLLUP_MAX_KEYS,
        disk_floor_bytes: int = DEFAULT_DISK_FLOOR_BYTES,
        max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES,
        fsync: bool = True,
        clock: Callable[[], int] = _now_ms,
        disk_free: Callable[[Path], int] = _disk_free,
    ) -> None:
        if not 1024 <= max_entry_bytes <= MAX_LINE_BYTES:
            raise ValueError("max_entry_bytes must be between 1024 and MAX_LINE_BYTES")
        if checkpoint_every < 1 or checkpoint_interval_ms < 1:
            raise ValueError("checkpoint settings must be positive")
        if rollup_window_ms < 1 or rollup_max_keys < 1:
            raise ValueError("rollup settings must be positive")
        if disk_floor_bytes < 0:
            raise ValueError("disk_floor_bytes must not be negative")

        self.path = Path(path)
        self._signer = signer
        self._public_key = signer.public_key_hex
        self._checkpoint_path = Path(checkpoint_path) if checkpoint_path is not None else None
        self._checkpoint_every = checkpoint_every
        self._checkpoint_interval_ms = checkpoint_interval_ms
        self._rollup_window_ms = rollup_window_ms
        self._rollup_max_keys = rollup_max_keys
        self._disk_floor_bytes = disk_floor_bytes
        self._max_entry_bytes = max_entry_bytes
        self._fsync = fsync
        self._clock = clock
        self._disk_free = disk_free

        self._seq = 0
        self._head = ZERO_HASH
        self._size = 0
        self._rolls: OrderedDict[tuple[str, str | None, str], _Roll] = OrderedDict()
        self._evicted = 0
        self._last_housekeep = 0
        self._stopped = False
        self._stop_recorded = False
        self._dropped = 0
        self._checkpoint_seq = 0
        self._checkpoint_ts = 0
        self._checkpoint_retry_at = 0
        self._closed = False

        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        self._fd = os.open(self.path, flags, 0o600)
        try:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LogLockedError(f"{self.path} is locked by another writer") from exc
            if self._checkpoint_path is not None:
                with contextlib.suppress(OSError):
                    if os.path.samestat(os.fstat(self._fd), self._checkpoint_path.stat()):
                        raise ValueError("checkpoint path must differ from the event log path")
            torn = self._recover()
            self._load_checkpoint_state()
            if torn is not None:
                os.ftruncate(self._fd, self._size)
                os.fsync(self._fd)
                now = self._clock()
                self._write_guarded("torn_tail_repaired", None, torn, now)
        except BaseException:
            os.close(self._fd)
            raise

    # -- state ------------------------------------------------------------

    @property
    def seq(self) -> int:
        """Sequence number of the last entry written (0 for an empty log)."""
        return self._seq

    @property
    def head_hash(self) -> str:
        return self._head

    @property
    def stopped(self) -> bool:
        """True while the writer is below the free-disk floor."""
        return self._stopped

    @property
    def dropped(self) -> int:
        """Events not written since the writer last stopped."""
        return self._dropped

    @property
    def public_key_hex(self) -> str:
        return self._public_key

    # -- opening an existing log --------------------------------------------

    def _recover(self) -> dict | None:
        """Find the last entry of an existing log. Returns torn-tail details, if any.

        Only the last line is checked here; ``lurewall verify`` checks the
        whole chain. A final line with no newline is treated as an incomplete
        write. The caller removes it and logs the removal after checking the
        checkpoint. A complete last line that does not verify is never
        "repaired": the writer refuses to extend it.
        """
        size = os.fstat(self._fd).st_size
        torn: dict | None = None
        window = 2 * MAX_LINE_BYTES + 2
        buf = os.pread(self._fd, min(size, window), max(0, size - window)) if size else b""
        if buf and not buf.endswith(b"\n"):
            cut = buf.rfind(b"\n")
            if cut == -1 and len(buf) < size:
                raise LogCorruptError("log ends in an unterminated run longer than any entry")
            tail = buf[cut + 1 :]
            size -= len(tail)
            buf = buf[: cut + 1]
            torn = {"bytes": len(tail), "sha256": sha256_hex(tail)}
        self._size = size
        if not buf:
            return torn
        start = buf.rfind(b"\n", 0, len(buf) - 1)
        if start == -1 and len(buf) < size:
            raise LogCorruptError("last line is longer than any entry")
        try:
            last = entry_mod.check_entry_line(buf[start + 1 : -1], self._public_key)
        except EntryError as exc:
            raise LogCorruptError(
                f"last entry of {self.path} is not valid under this key ({exc.code}); "
                "refusing to append. Run `lurewall verify`."
            ) from exc
        self._seq = last.seq
        self._head = last.hash
        return torn

    def _load_checkpoint_state(self) -> None:
        if self._checkpoint_path is None:
            return
        try:
            with open(self._checkpoint_path, "rb") as handle:
                raw = handle.read(MAX_LINE_BYTES + 1)
            checkpoint = entry_mod.check_checkpoint(json.loads(raw), self._public_key)
        except (OSError, ValueError, RecursionError):
            return  # missing or unusable: the next checkpoint replaces it
        seq = checkpoint["seq"]
        if seq > self._seq:
            raise LogCorruptError("published checkpoint is ahead of the log; refusing to append")
        if seq == self._seq and checkpoint["head_hash"] != self._head:
            raise LogCorruptError(
                "published checkpoint disagrees with the log head; refusing to append"
            )
        self._checkpoint_seq = seq
        self._checkpoint_ts = checkpoint["ts"]

    # -- appending ----------------------------------------------------------

    def append(
        self,
        type: str,
        source: str | None = None,
        detail: dict | None = None,
        *,
        rollup_key: str | None = None,
    ) -> Entry | None:
        """Record one event. Returns the entry written, or None if none was.

        With ``rollup_key``, repeats of the same ``(type, source, rollup_key)``
        inside one window are counted instead of written. None is also returned
        while the writer is stopped below the free-disk floor; those events are
        counted in ``dropped`` and reported when it resumes.

        Raises ValueError for arguments only a programming error can produce
        (a malformed type or a float in ``detail``). Hostile strings are never
        an error: any text is a valid string value.
        """
        self._require_open()
        detail = {} if detail is None else detail
        if not entry_mod.is_event_type(type):
            raise ValueError("event type must match [a-z][a-z0-9_]{0,63}")
        if not entry_mod.is_source(source):
            raise ValueError("source must be None or a string of at most 256 characters")
        if not isinstance(detail, dict):
            raise ValueError("detail must be a dict")
        check_value(detail)

        now = self._clock()
        self._housekeep(now)
        if rollup_key is None:
            return self._write_guarded(type, source, detail, now)

        if not (isinstance(rollup_key, str) and len(rollup_key) <= MAX_ROLLUP_KEY_CHARS):
            raise ValueError("rollup_key must be a string of at most 256 characters")
        key = (type, source, rollup_key)
        roll = self._rolls.get(key)
        if roll is not None:
            roll.count += 1
            roll.last_ts = now
            self._rolls.move_to_end(key)
            return None
        while len(self._rolls) >= self._rollup_max_keys:
            old_key, old_roll = self._rolls.popitem(last=False)
            self._write_rollup(old_key, old_roll, now)
            self._evicted += 1
        self._rolls[key] = _Roll(now)
        return self._write_guarded(type, source, detail, now)

    def tick(self) -> None:
        """Run timed work: flush finished roll-up windows, write a due checkpoint.

        ``append`` does this too. Call ``tick`` from the main loop so it also
        happens when no events arrive.
        """
        self._require_open()
        now = self._clock()
        self._housekeep(now, force=True)
        self._maybe_checkpoint(now)

    def _housekeep(self, now: int, *, force: bool = False) -> None:
        if not force and 0 <= now - self._last_housekeep < _HOUSEKEEP_EVERY_MS:
            return
        self._last_housekeep = now
        for key, roll in list(self._rolls.items()):
            if now - roll.window_start < self._rollup_window_ms:
                continue
            if roll.count == 0:
                del self._rolls[key]  # idle for a whole window
                continue
            self._write_rollup(key, roll, now)
            roll.count = 0
            roll.first_ts = roll.last_ts = roll.window_start = now
        self._report_evictions(now)

    def _write_rollup(self, key: tuple[str, str | None, str], roll: _Roll, now: int) -> None:
        if roll.count == 0:
            return
        of_type, source, rollup_key = key
        detail = {
            "of": of_type,
            "key": rollup_key,
            "count": roll.count,
            "first_ts": roll.first_ts,
            "last_ts": roll.last_ts,
        }
        self._write_guarded("rollup", source, detail, now, weight=roll.count)

    def _report_evictions(self, now: int) -> None:
        if self._evicted == 0:
            return
        count = self._evicted
        if self._write_guarded("rollup_evicted", None, {"count": count}, now, weight=0):
            self._evicted -= count

    def _write_guarded(
        self, type: str, source: str | None, detail: dict, now: int, *, weight: int = 1
    ) -> Entry | None:
        """Write one entry unless the disk is below the floor.

        ``weight`` is how many events this entry stands for, so that a roll-up
        lost while stopped is counted as all of its events.
        """
        try:
            free = self._disk_free(self.path.parent)
        except OSError:
            free = 0  # cannot tell: assume the worst rather than fill the disk
        if free < self._disk_floor_bytes:
            if not self._stopped:
                self._stopped = True
                # One small entry is written below the floor, so the log says
                # why it goes quiet. The floor is the reserve that pays for it.
                stop_detail = {"free_bytes": free, "floor_bytes": self._disk_floor_bytes}
                written = self._write("writer_stopped", None, stop_detail, now, checkpoint=False)
                self._stop_recorded = written is not None
            self._dropped += weight
            return None
        if self._stopped:
            resume_detail = {"dropped": self._dropped, "stop_recorded": self._stop_recorded}
            if self._write("writer_resumed", None, resume_detail, now) is None:
                self._dropped += weight
                return None
            self._stopped = False
            self._stop_recorded = False
            self._dropped = 0
        written = self._write(type, source, detail, now)
        if written is None:
            self._dropped += weight
        return written

    def _write(
        self, type: str, source: str | None, detail: dict, now: int, *, checkpoint: bool = True
    ) -> Entry | None:
        """Sign and append one entry. Returns None if the disk filled mid-write."""
        now = max(now, 0)  # a clock before 1970 must not produce an invalid entry
        line, sig = self._build_line(type, source, detail, now)
        if len(line) > self._max_entry_bytes:
            # Keep the event; drop the oversized detail but pin its hash.
            body = canonical_bytes(detail)
            detail = {"oversize": True, "bytes": len(body), "sha256": sha256_hex(body)}
            line, sig = self._build_line(type, source, detail, now)
        data = line + b"\n"
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(self._fd, view) :]
            if self._fsync:
                os.fsync(self._fd)
        except OSError as exc:
            # Never leave half a line behind: cut back to the last whole entry.
            with contextlib.suppress(OSError):
                os.ftruncate(self._fd, self._size)
            if exc.errno not in _DISK_FULL_ERRNOS:
                raise
            self._stopped = True
            return None
        written = Entry(
            seq=self._seq + 1,
            ts=now,
            type=type,
            source=source,
            detail=detail,
            prev_hash=self._head,
            sig=sig,
            hash=sha256_hex(line),
        )
        self._seq = written.seq
        self._head = written.hash
        self._size += len(data)
        if checkpoint:
            self._maybe_checkpoint(now)
        return written

    def _build_line(
        self, type: str, source: str | None, detail: dict, now: int
    ) -> tuple[bytes, str]:
        body = {
            "seq": self._seq + 1,
            "ts": now,
            "type": type,
            "source": source,
            "detail": detail,
            "prev_hash": self._head,
        }
        sig = self._signer.sign(body, signing.DOMAIN_EVENT)
        return canonical_bytes({**body, "sig": sig}), sig

    # -- checkpoints --------------------------------------------------------

    def _maybe_checkpoint(self, now: int) -> None:
        if self._checkpoint_path is None or self._seq == self._checkpoint_seq:
            return
        due = (
            self._seq - self._checkpoint_seq >= self._checkpoint_every
            or now - self._checkpoint_ts >= self._checkpoint_interval_ms
        )
        if due and now >= self._checkpoint_retry_at:
            self.checkpoint()

    def checkpoint(self) -> dict | None:
        """Sign the current head and publish it. Returns the checkpoint, or None.

        The file holds a sequence number, a hash, a time and a signature:
        nothing about any visitor. It is replaced atomically, so the web server
        never serves half a checkpoint.
        """
        self._require_open()
        if self._checkpoint_path is None or self._seq == 0:
            return None
        now = max(self._clock(), 0)
        checkpoint = entry_mod.make_checkpoint(self._signer, self._seq, self._head, now)
        data = canonical_bytes(checkpoint) + b"\n"
        target = self._checkpoint_path
        try:
            fd, temp_name = tempfile.mkstemp(
                dir=target.parent, prefix=".checkpoint-", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_name, 0o644)  # public by design: nginx serves it
                os.replace(temp_name, target)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(temp_name)
                raise
        except OSError as exc:
            # Back off for one interval, and say so once, rather than failing
            # (and logging) on every append.
            self._checkpoint_retry_at = now + self._checkpoint_interval_ms
            detail = {"errno": exc.errno if exc.errno is not None else -1}
            self._write("checkpoint_error", None, detail, now, checkpoint=False)
            return None
        self._checkpoint_seq = checkpoint["seq"]
        self._checkpoint_ts = now
        return checkpoint

    # -- closing ------------------------------------------------------------

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("event log is closed")

    def close(self) -> None:
        """Write out pending roll-up counts and a final checkpoint, then release the log."""
        if self._closed:
            return
        try:
            now = self._clock()
            for key, roll in list(self._rolls.items()):
                self._write_rollup(key, roll, now)
            self._rolls.clear()
            self._report_evictions(now)
            if self._checkpoint_path is not None and self._seq != self._checkpoint_seq:
                self.checkpoint()
        finally:
            self._closed = True
            os.close(self._fd)

    def __enter__(self) -> EventLog:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
