# SPDX-License-Identifier: AGPL-3.0-only
"""Short-lived origin issuance receipts. Rebuilt from traffic after a restart."""

from __future__ import annotations

from dataclasses import dataclass, replace


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

    def record(self, path: str, receipt: Issuance) -> bool:
        """False when full. Never displace a still-live receipt to admit a new one."""
        if receipt.issued_ms - self._pruned_ms >= 60_000:
            self._entries = {
                path: item
                for path, item in self._entries.items()
                if item.until_ms > receipt.issued_ms
            }
            self._pruned_ms = receipt.issued_ms
        old = self._entries.get(path)
        if old is None and len(self._entries) >= self._limit:
            return False
        if old is None or old.until_ms <= receipt.issued_ms:
            self._entries[path] = receipt
        elif (old.source, old.placement, old.until_ms) != (
            receipt.source,
            receipt.placement,
            receipt.until_ms,
        ):
            self._entries[path] = replace(
                old, source=None, until_ms=max(old.until_ms, receipt.until_ms)
            )
        return True

    def lookup(self, path: str, at_ms: int) -> Issuance | None:
        item = self._entries.get(path)
        if item is not None and item.issued_ms <= at_ms < item.until_ms:
            return item
        return None

    def forget(self, source: str) -> None:
        self._entries = {
            path: item for path, item in self._entries.items() if item.source != source
        }
