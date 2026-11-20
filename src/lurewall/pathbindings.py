# SPDX-License-Identifier: AGPL-3.0-only
"""Short-lived origin issuance receipts, saved beside the engine state.

The njs origin keeps a source's path for its three-to-seven-day lease, so the
detector must remember what it issued across a restart. The saved copy is
bounded: at most ``PERSIST_LIMIT`` of the most recently issued live receipts.
It holds issued paths, so it is private like the canary state.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace

from lurewall import canaries

STATE_VERSION = 1
PERSIST_LIMIT = 10_000
MAX_STATE_BYTES = 4 * 1024 * 1024
# The njs lease is at most seven days. Anything claiming longer is not ours.
_MAX_LEASE_MS = 7 * 86_400_000
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
_HASH_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True)
class Issuance:
    source: str | None  # None if this path appeared under more than one binding
    placement: str
    issued_ms: int
    until_ms: int
    page_request_id: str
    page_line: str


class IssuedPaths:
    def __init__(self, limit: int):
        self._entries: dict[str, Issuance] = {}
        self._limit = limit
        self._pruned_ms = 0
        self.dirty = False

    def record(self, path: str, receipt: Issuance) -> bool:
        """False when full. Never displace a still-live receipt to admit a new one."""
        if receipt.issued_ms - self._pruned_ms >= 60_000:
            self._prune(receipt.issued_ms)
        old = self._entries.get(path)
        if old is None and len(self._entries) >= self._limit:
            return False
        if old is None or old.until_ms <= receipt.issued_ms:
            self._entries[path] = receipt
            self.dirty = True
        elif (old.source, old.placement, old.until_ms) != (
            receipt.source,
            receipt.placement,
            receipt.until_ms,
        ):
            self._entries[path] = replace(
                old, source=None, until_ms=max(old.until_ms, receipt.until_ms)
            )
            self.dirty = True
        return True

    def lookup(self, path: str, at_ms: int) -> Issuance | None:
        item = self._entries.get(path)
        if item is not None and item.issued_ms <= at_ms < item.until_ms:
            return item
        return None

    def forget(self, source: str) -> None:
        kept = {path: item for path, item in self._entries.items() if item.source != source}
        if len(kept) != len(self._entries):
            self._entries = kept
            self.dirty = True

    def _prune(self, now_ms: int) -> None:
        kept = {path: item for path, item in self._entries.items() if item.until_ms > now_ms}
        if len(kept) != len(self._entries):
            self.dirty = True
        self._entries = kept
        self._pruned_ms = now_ms

    # -- saved copy -------------------------------------------------------------------

    def dumps(self, now_ms: int) -> bytes:
        """The live receipts, newest first, capped by count and size."""
        live = sorted(
            ((path, item) for path, item in self._entries.items() if item.until_ms > now_ms),
            key=lambda pair: pair[1].issued_ms,
            reverse=True,
        )[:PERSIST_LIMIT]
        rows = [
            [
                path,
                item.source,
                item.placement,
                item.issued_ms,
                item.until_ms,
                item.page_request_id,
                item.page_line,
            ]
            for path, item in live
        ]
        while True:
            data = json.dumps({"version": STATE_VERSION, "receipts": rows}).encode()
            if len(data) <= MAX_STATE_BYTES:
                return data
            rows = rows[: len(rows) * 3 // 4]  # drop the oldest quarter until it fits

    def loads(self, raw: bytes, now_ms: int, checked_source: Callable[[object], str]) -> int:
        """Restore saved receipts. Raises ValueError on anything unexpected."""
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("too large")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except RecursionError as exc:
            raise ValueError("too deep") from exc
        if type(doc) is not dict or set(doc) != {"version", "receipts"}:
            raise ValueError("shape")
        if doc["version"] != STATE_VERSION or type(doc["receipts"]) is not list:
            raise ValueError("version")
        restored: dict[str, Issuance] = {}
        for row in doc["receipts"][:PERSIST_LIMIT]:
            if type(row) is not list or len(row) != 7:
                raise ValueError("receipt")
            path, source, placement, issued, until, request_id, line = row
            if not canaries.is_natural_path(path) or placement not in canaries.QUIET_PLACEMENTS:
                raise ValueError("receipt")
            if not all(type(v) is int and 0 <= v < 2**53 for v in (issued, until)):
                raise ValueError("receipt")
            if not 0 < until - issued <= _MAX_LEASE_MS:
                raise ValueError("receipt")
            if type(request_id) is not str or not _REQUEST_ID_RE.fullmatch(request_id):
                raise ValueError("receipt")
            if type(line) is not str or not _HASH_RE.fullmatch(line):
                raise ValueError("receipt")
            source = None if source is None else checked_source(source)
            if until > now_ms and path not in restored and len(restored) < self._limit:
                restored[path] = Issuance(source, placement, issued, until, request_id, line)
        self._entries = restored
        self._pruned_ms = now_ms
        self.dirty = False
        return len(restored)
