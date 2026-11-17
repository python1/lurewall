# SPDX-License-Identifier: AGPL-3.0-only
"""Per-source signal state: who has shown what, inside one window.

- A source is an IPv4 address, or the /64 of an IPv6 address, so one host
  cannot spread its signals over the addresses of its own /64.
- The attack threshold is two or more *distinct* attack signals inside the
  window, from at least two separate requests. Repeats of one signal, in any
  spelling, are one signal, and one request that raises two signals is not
  enough. Behavior signals (speed, order, headers) are never counted: nothing
  here can add them to the attack count.
- Attack signals on cross-site requests count for nothing. They are kept
  apart, per source, only so that a decision can say they were seen.
- The table has a fixed size. The source idle longest is dropped first and
  every drop is counted. Each source's own state is bounded too.
- A source that also shows ordinary browsing in the window (asset loads,
  browser fetch metadata) is marked, so a later block's TTL is not doubled:
  that pattern suggests a shared address with innocent users behind it.

Nothing here blocks anything. The decision engine reads these views.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict, deque
from dataclasses import dataclass
from itertools import pairwise

from lurewall.accesslog import Record
from lurewall.sigconfig import MIN_DISTINCT_ATTACK_SIGNALS
from lurewall.signals import ATTACK, ATTACK_KINDS, BEHAVIOR, RAW, Classification, Signal

MAX_KEYS_PER_SOURCE = 16
# Attack signals must come from at least this many separate requests. Fixed:
# no config can make a single request enough.
MIN_ATTACK_REQUESTS = 2
RECENT_REQUESTS = 16
_MAX_PATH_CHARS = 128

# Timing signals need this many requests before they say anything.
_MIN_TIMED = 8
_MIN_SPACING_MS = 200
_MIN_ORDERED = 6


def source_key(ip: str) -> str:
    """The key a source is tracked and blocked under."""
    address = ipaddress.ip_address(ip)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.version == 4:
        return address.compressed
    return ipaddress.ip_network((int(address) >> 64 << 64, 64)).compressed


@dataclass(frozen=True)
class SourceView:
    """What is known about one source at one moment."""

    source: str
    attack_keys: tuple[str, ...]  # distinct attack signals inside the window
    attack_requests: int  # separate requests that raised them (counted up to a small limit)
    threshold_met: bool
    cross_site_keys: tuple[str, ...]  # seen on cross-site requests; never counted
    normal_browsing: bool
    behavior: tuple[Signal, ...]

    @property
    def ttl_may_double(self) -> bool:
        """False when the source also shows ordinary browsing in the window."""
        return not self.normal_browsing


class _State:
    __slots__ = (
        "attack",
        "attack_requests",
        "cross_site",
        "last_asset",
        "last_browser",
        "last_seen",
        "recent",
    )

    def __init__(self) -> None:
        self.last_seen = 0
        self.attack: dict[str, int] = {}  # signal key -> when last seen
        self.cross_site: dict[str, int] = {}  # the same, for cross-site requests
        # nginx request ID -> when. A line read twice after a crash is one request.
        self.attack_requests: OrderedDict[str, int] = OrderedDict()
        self.last_asset: int | None = None
        self.last_browser: int | None = None
        self.recent: deque[tuple[int, str, bool]] = deque(maxlen=RECENT_REQUESTS)


class SignalTracker:
    def __init__(
        self,
        *,
        window_ms: int = 15 * 60_000,
        threshold: int = MIN_DISTINCT_ATTACK_SIGNALS,
        max_sources: int = 10_000,
    ) -> None:
        if type(threshold) is not int or threshold < MIN_DISTINCT_ATTACK_SIGNALS:
            raise ValueError(
                f"the attack threshold cannot be below {MIN_DISTINCT_ATTACK_SIGNALS} "
                "distinct signals"
            )
        if threshold > MAX_KEYS_PER_SOURCE:
            raise ValueError(f"the attack threshold cannot exceed {MAX_KEYS_PER_SOURCE}")
        if type(window_ms) is not int or window_ms < 1:
            raise ValueError("window_ms must be a positive whole number")
        if type(max_sources) is not int or max_sources < 1:
            raise ValueError("max_sources must be a positive whole number")
        self._window = window_ms
        self._threshold = threshold
        self._max_sources = max_sources
        self._sources: OrderedDict[str, _State] = OrderedDict()
        self._now = 0
        self._evicted = 0

    def __len__(self) -> int:
        return len(self._sources)

    def take_evictions(self) -> int:
        """Sources dropped at the size limit since the last call."""
        count, self._evicted = self._evicted, 0
        return count

    def observe(self, record: Record, classification: Classification) -> SourceView:
        """Take in one classified record and return the source's view.

        A stale record changes nothing: a backlog is logged, never acted on.
        Time is the newest log time seen, so a late line cannot rewind it.
        """
        source = source_key(record.ip)
        if record.stale:
            return self.view(source)
        self._now = max(self._now, record.ts_ms)
        when = min(record.ts_ms, self._now)
        state = self._state(source)
        state.last_seen = self._now

        counted = False
        for signal in classification.attack:
            # The class and the kind are both checked: only an attack signal
            # of a known attack kind is ever counted.
            if signal.cls != ATTACK or signal.kind not in ATTACK_KINDS:
                continue
            state.attack[signal.key] = max(when, state.attack.get(signal.key, 0))
            counted = True
        if counted:
            state.attack_requests[record.request_id] = when
            state.attack_requests.move_to_end(record.request_id)
        for signal in classification.suppressed:
            if signal.cls == ATTACK and signal.kind in ATTACK_KINDS:
                state.cross_site[signal.key] = max(when, state.cross_site.get(signal.key, 0))
        self._trim(state)

        if classification.cross_site is None:
            if classification.asset:
                state.last_asset = when
            if classification.browser_metadata:
                state.last_browser = when
            path = (classification.path or "")[:_MAX_PATH_CHARS]
            state.recent.append((when, path, classification.asset))
        return self.view(source)

    def view(self, source: str) -> SourceView:
        state = self._sources.get(source)
        if state is None:
            return SourceView(source, (), 0, False, (), False, ())
        floor = self._now - self._window
        keys = tuple(sorted(key for key, seen in state.attack.items() if seen > floor))
        requests = sum(1 for seen in state.attack_requests.values() if seen > floor)
        normal = any(
            seen is not None and seen > floor for seen in (state.last_asset, state.last_browser)
        )
        return SourceView(
            source=source,
            attack_keys=keys,
            attack_requests=requests,
            threshold_met=len(keys) >= self._threshold and requests >= MIN_ATTACK_REQUESTS,
            cross_site_keys=tuple(
                sorted(key for key, seen in state.cross_site.items() if seen > floor)
            ),
            normal_browsing=normal,
            behavior=tuple(self._behavior(state, floor)),
        )

    def forget_attack(self, source: str, up_to_ms: int | None = None) -> None:
        """Drop a source's attack signals, all of them or those seen up to a time.

        Called when a block starts and when it ends, so a later block needs
        fresh evidence, not the signals already acted on.
        """
        state = self._sources.get(source)
        if state is None:
            return
        for table in (state.attack, state.attack_requests):
            for key in [k for k, seen in table.items() if up_to_ms is None or seen <= up_to_ms]:
                del table[key]

    # -- internals ---------------------------------------------------------------

    def _state(self, source: str) -> _State:
        state = self._sources.get(source)
        if state is not None:
            self._sources.move_to_end(source)
            return state
        floor = self._now - self._window
        while self._sources:
            # Sources idle for a whole window hold nothing live: free them first.
            oldest = next(iter(self._sources.values()))
            if oldest.last_seen > floor:
                break
            self._sources.popitem(last=False)
        while len(self._sources) >= self._max_sources:
            self._sources.popitem(last=False)  # the source idle longest
            self._evicted += 1
        state = self._sources[source] = _State()
        return state

    def _trim(self, state: _State) -> None:
        floor = self._now - self._window
        for table in (state.attack, state.cross_site, state.attack_requests):
            for key in [key for key, seen in table.items() if seen <= floor]:
                del table[key]
        for table in (state.attack, state.cross_site):
            while len(table) > MAX_KEYS_PER_SOURCE:
                del table[min(table, key=table.__getitem__)]
        while len(state.attack_requests) > MAX_KEYS_PER_SOURCE:
            state.attack_requests.popitem(last=False)

    def _behavior(self, state: _State, floor: int) -> list[Signal]:
        recent = [item for item in state.recent if item[0] > floor]
        found = []
        if len(recent) >= _MIN_TIMED:
            times = sorted(item[0] for item in recent)
            gaps = [later - earlier for earlier, later in pairwise(times)]
            mean = sum(gaps) // len(gaps)
            if min(gaps) >= _MIN_SPACING_MS and max(gaps) - min(gaps) <= mean // 5:
                found.append(Signal(BEHAVIOR, "steady_timing", "", RAW))
            if not any(item[2] for item in recent):
                found.append(Signal(BEHAVIOR, "no_asset_loads", "", RAW))
        paths = list(dict.fromkeys(item[1] for item in recent if item[1]))
        if len(paths) >= _MIN_ORDERED and paths == sorted(paths):
            found.append(Signal(BEHAVIOR, "methodical_order", "", RAW))
        return found
