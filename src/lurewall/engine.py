# SPDX-License-Identifier: AGPL-3.0-only
"""The decision engine: a small, deterministic rule set over per-source state.

A source is blocked only when two kinds of evidence agree:

- a **counted canary hit** in the last 7 days: a decoy request, not
  cross-site, whose request ID was issued to the same source on a page nginx
  served it. An ID issued to another source is ``relayed`` and counts for
  nobody; an ID never issued counts for nobody either;
- the **attack threshold**: two or more distinct attack signals from at least
  two separate requests inside the window (kept by the signal tracker).

    counted hit | threshold | outcome
    ------------+-----------+------------------------------------------
    no          | no        | nothing
    yes         | no        | content reader, no attack signal; no block
    no          | yes       | attack, no canary hit; no block in v1
    yes         | yes       | block with a TTL

Before any block: sources inside published provider ranges are log-only, the
allowlist is checked, the cap on active blocks is checked, and in dry-run (the
default) the block is logged as ``would_block`` and nothing is enforced.
Nothing older than the staleness limit is acted on.

The engine never calls a firewall. It hands a block, with its absolute expiry
time, to an adapter. There is no ML here: every decision can be explained from
the log.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import sys
import tempfile
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from lurewall.canaries import refuse_git_work_tree
from lurewall.collector import Observation
from lurewall.engineconfig import EngineConfig, Network
from lurewall.logreader import Sink
from lurewall.sigconfig import MIN_DISTINCT_ATTACK_SIGNALS
from lurewall.sources import SignalTracker

STATE_VERSION = 1
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_HISTORY_SOURCES = 10_000
_SAVE_INTERVAL_MS = 5_000

# Outcomes a decision can have.
CONTENT_READER = "content_reader"
CONTENT_READER_CROSS_SITE = "content_reader_cross_site_probes_not_counted"
ATTACK_NO_CANARY = "attack_no_canary"
LOG_ONLY_RANGE = "log_only_range"
ALLOWLISTED = "allowlisted"
CAP_REACHED = "cap_reached"
WOULD_BLOCK = "would_block"
BLOCK = "block"
ALREADY_BLOCKED = "already_blocked"


class Adapter(Protocol):
    """What enforces a block. The engine knows nothing else about it."""

    def block(self, source: str, expiry_ms: int) -> None: ...

    def unblock(self, source: str) -> None: ...


class LogOnlyAdapter:
    """Blocks nothing. The only adapter until the nftables one exists."""

    def block(self, source: str, expiry_ms: int) -> None:
        return None

    def unblock(self, source: str) -> None:
        return None


@dataclass(frozen=True)
class Decision:
    outcome: str
    source: str
    ttl_ms: int | None = None
    expiry_ms: int | None = None


@dataclass
class _Block:
    start: int
    expiry: int
    ttl: int
    enforced: bool


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def journal_alert(message: str) -> None:
    """An error-level line for the system journal (sd-daemon priority prefix)."""
    print(f"<3>lurewall: {message}", file=sys.stderr, flush=True)


def source_network(source: str) -> Network:
    return ipaddress.ip_network(source, strict=True)


def ack_path(state_path: Path) -> Path:
    return state_path.with_name(state_path.name + ".ack")


def _is_ms(value: object) -> bool:
    return type(value) is int and 0 <= value < 2**53


class Engine:
    def __init__(
        self,
        config: EngineConfig,
        sink: Sink,
        tracker: SignalTracker,
        *,
        adapter: Adapter | None = None,
        state_path: str | Path | None = None,
        clock: Callable[[], int] = _now_ms,
        alert: Callable[[str], None] = journal_alert,
    ) -> None:
        self.config = config
        self._sink = sink
        self._tracker = tracker
        self._adapter = adapter if adapter is not None else LogOnlyAdapter()
        self._clock = clock
        self._alert_out = alert
        self._state_path = None if state_path is None else Path(state_path)
        if self._state_path is not None:
            refuse_git_work_tree(self._state_path.parent, "engine state location")

        # request ID -> (source it was issued to, when)
        self._issued: OrderedDict[str, tuple[str, int]] = OrderedDict()
        self._issued_by: dict[str, deque[str]] = {}
        # source -> (when the counted hit was seen, canary id)
        self._hits: OrderedDict[str, tuple[int, str]] = OrderedDict()
        self._blocks: dict[str, _Block] = {}
        # source -> (TTL of its last block, when that block ends)
        self._history: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._alert_raised: int | None = None
        self._dirty = False
        self._last_save = 0
        if self._state_path is not None:
            self._load()

    # -- public ----------------------------------------------------------------------

    def handle(self, observation: Observation) -> Decision | None:
        """Take in one observation. Returns the decision reached, if any."""
        record = observation.record
        result = observation.classification
        view = observation.view
        source = view.source
        now = self._clock()
        if source in self._expire(now):
            # This source's block just ended and its spent signals were
            # dropped: the view taken before that no longer holds.
            view = self._tracker.view(source)
            observation = replace(observation, view=view)

        counted_now = False
        if result.canary is None:
            # Any page nginx served this source may carry canary references
            # stamped with this request's ID.
            self._issue(record.request_id, source, record.ts_ms)
        elif result.cross_site is None:
            counted_now = self._canary_request(observation)
        # A cross-site decoy request counts for nothing; the collector logged it.

        if record.stale:
            return None  # a backlog is logged, never acted on
        if counted_now or result.attack:
            decision = self._decide(observation, now)
        elif result.suppressed:
            # A cross-site probe is never evidence. At most it is named.
            decision = self._note_cross_site(observation, now)
        else:
            return None
        self._save(now)
        return decision

    def tick(self, now_ms: int | None = None) -> None:
        """Expire blocks that are due and save state. Safe to call often."""
        now = self._clock() if now_ms is None else now_ms
        self._expire(now)
        self._save(now)

    def close(self) -> None:
        self._save(self._clock(), force=True)

    def active_blocks(self) -> dict[str, int]:
        """source -> absolute expiry time, for every block not yet expired."""
        return {source: block.expiry for source, block in self._blocks.items()}

    def has_counted_hit(self, source: str, now_ms: int | None = None) -> bool:
        now = self._clock() if now_ms is None else now_ms
        hit = self._hits.get(source)
        return hit is not None and now - hit[0] <= self.config.sticky_ms

    def alert_standing(self) -> bool:
        return self._alert_raised is not None and self._ack_time() < self._alert_raised

    # -- request-ID binding ---------------------------------------------------------------

    def _issue(self, request_id: str, source: str, when: int) -> None:
        known = self._issued.get(request_id)
        if known is not None:
            return  # a line read twice, or an ID already bound: first issue wins
        mine = self._issued_by.setdefault(source, deque())
        while len(mine) >= self.config.max_ids_per_source:
            # A source rotates out its own oldest IDs before anyone else's.
            self._issued.pop(mine.popleft(), None)
        while len(self._issued) >= self.config.max_issued_ids:
            old_id, (old_source, _when) = self._issued.popitem(last=False)
            theirs = self._issued_by.get(old_source)
            if theirs:
                with contextlib.suppress(ValueError):
                    theirs.remove(old_id)
                if not theirs:
                    del self._issued_by[old_source]
            self._sink.append("engine_state_evicted", None, {"table": "issued_id"}, rollup_key="id")
        self._issued[request_id] = (source, when)
        mine.append(request_id)

    def _canary_request(self, observation: Observation) -> bool:
        """Log a same-site decoy request. Returns True if it is a counted hit."""
        record = observation.record
        hit = observation.classification.canary
        source = observation.view.source
        canary = hit.canary
        detail: dict = {
            "request_id": record.request_id,
            "line": record.line_sha256,
            "canary": canary.id,
            "lure": canary.lure,
            "placement": canary.placement,
        }
        if record.stale:
            detail["stale"] = True

        if hit.request_id is None:
            self._sink.append(
                "canary_unbound", source, {**detail, "reason": "no_id"}, rollup_key="no_id"
            )
            return False
        detail["page_request_id"] = hit.request_id
        issued = self._issued.get(hit.request_id)
        if issued is None:
            # Guessed, made up, issued before a restart, or rotated out.
            self._sink.append(
                "canary_unbound", source, {**detail, "reason": "unknown_id"}, rollup_key="unknown"
            )
            return False
        issued_to, issued_at = issued
        if issued_to != source:
            # Counts for nobody: neither the reader of the page nor the requester.
            self._sink.append(
                "canary_relayed", source, {**detail, "issued_to": issued_to}, rollup_key=canary.id
            )
            return False
        age = record.ts_ms - issued_at
        if age < 0 or age > self.config.id_ttl_ms:
            self._sink.append(
                "canary_unbound", source, {**detail, "reason": "expired_id"}, rollup_key="expired"
            )
            return False

        counted = not record.stale
        self._sink.append(
            "canary_hit", source, {**detail, "counted": counted}, rollup_key=canary.id
        )
        if not counted:
            return False
        self._hits[source] = (record.ts_ms, canary.id)
        self._hits.move_to_end(source)
        while len(self._hits) > self.config.max_hit_sources:
            self._hits.popitem(last=False)
            self._sink.append(
                "engine_state_evicted", None, {"table": "canary_hit"}, rollup_key="hit"
            )
        self._dirty = True
        return True

    # -- the decision table ----------------------------------------------------------------

    def _note_cross_site(self, observation: Observation, now: int) -> Decision | None:
        view = observation.view
        if view.threshold_met or not self.has_counted_hit(view.source, now):
            return None
        if len(view.cross_site_keys) < MIN_DISTINCT_ATTACK_SIGNALS:
            return None
        record = observation.record
        self._sink.append(
            "decision",
            view.source,
            {
                "request_id": record.request_id,
                "line": record.line_sha256,
                "outcome": CONTENT_READER_CROSS_SITE,
                "cross_site_signals": list(view.cross_site_keys),
            },
            rollup_key=CONTENT_READER_CROSS_SITE,
        )
        return Decision(CONTENT_READER_CROSS_SITE, view.source)

    def _decide(self, observation: Observation, now: int) -> Decision | None:
        record = observation.record
        view = observation.view
        source = view.source
        has_hit = self.has_counted_hit(source, now)
        where = {"request_id": record.request_id, "line": record.line_sha256}

        def log(outcome: str, **extra: object) -> Decision:
            self._sink.append(
                "decision", source, {**where, "outcome": outcome, **extra}, rollup_key=outcome
            )
            return Decision(outcome, source)

        if not view.threshold_met:
            if not has_hit:
                return None
            if len(view.cross_site_keys) >= MIN_DISTINCT_ATTACK_SIGNALS:
                # Seen, named, and deliberately not counted.
                return log(CONTENT_READER_CROSS_SITE, cross_site_signals=list(view.cross_site_keys))
            return log(CONTENT_READER)
        if not has_hit:
            return log(ATTACK_NO_CANARY, signals=list(view.attack_keys))

        # A counted canary hit and the attack threshold: the block row.
        if source in self._blocks:
            return Decision(ALREADY_BLOCKED, source)
        signals = list(view.attack_keys)
        network = source_network(source)
        if _overlaps(network, self.config.log_only):
            return log(LOG_ONLY_RANGE, signals=signals)
        if _overlaps(network, self.config.allowlist):
            self._sink.append(
                "would_block",
                source,
                {**where, "reason": ALLOWLISTED, "signals": signals},
                rollup_key=ALLOWLISTED,
            )
            return Decision(ALLOWLISTED, source)
        if len(self._blocks) >= self.config.cap:
            self._sink.append(
                "cap_reached",
                source,
                {**where, "cap": self.config.cap, "signals": signals},
                rollup_key="cap",
            )
            self._raise_alert(now)
            return Decision(CAP_REACHED, source)

        ttl = self._ttl(source, view.normal_browsing, now)
        expiry = now + ttl
        enforced = not self.config.dry_run
        detail = {
            **where,
            "signals": signals,
            "canary": self._hits[source][1],
            "ttl_ms": ttl,
            "expiry_ms": expiry,
            "normal_browsing": view.normal_browsing,
        }
        if enforced:
            self._adapter.block(source, expiry)
            self._sink.append("block", source, detail)
        else:
            self._sink.append("would_block", source, {**detail, "reason": "dry_run"})
        self._blocks[source] = _Block(start=now, expiry=expiry, ttl=ttl, enforced=enforced)
        self._history[source] = (ttl, expiry)
        self._history.move_to_end(source)
        while len(self._history) > MAX_HISTORY_SOURCES:
            self._history.popitem(last=False)
        # The signals are spent: a later block needs fresh evidence.
        self._tracker.forget_attack(source)
        self._dirty = True
        self._save(now, force=True)
        return Decision(BLOCK if enforced else WOULD_BLOCK, source, ttl, expiry)

    def _ttl(self, source: str, normal_browsing: bool, now: int) -> int:
        config = self.config
        last = self._history.get(source)
        if last is None or now - last[1] > config.max_ttl_ms:
            return config.ttl_ms
        last_ttl = max(last[0], config.ttl_ms)
        if normal_browsing:
            # Ordinary browsing beside the attack suggests a shared address
            # with innocent users behind it: the TTL does not grow.
            return min(last_ttl, config.max_ttl_ms)
        return min(last_ttl * 2, config.max_ttl_ms)

    def _expire(self, now: int) -> list[str]:
        due = [source for source, block in self._blocks.items() if block.expiry <= now]
        for source in due:
            block = self._blocks.pop(source)
            if block.enforced:
                self._adapter.unblock(source)
            self._sink.append(
                "block_expired",
                source,
                {"ttl_ms": block.ttl, "expiry_ms": block.expiry, "enforced": block.enforced},
            )
            # In dry-run the source kept sending while "blocked". None of that
            # may carry over: after a real block there would be nothing. What
            # it sent after the block ended is new evidence and stays.
            self._tracker.forget_attack(source, up_to_ms=block.expiry)
            self._dirty = True
        if due:
            self._save(now, force=True)
        return due

    # -- the cap alert ---------------------------------------------------------------------

    def _ack_time(self) -> int:
        if self._state_path is None:
            return -1
        return read_ack(self._state_path)

    def _raise_alert(self, now: int) -> None:
        if self.alert_standing():
            return
        self._alert_raised = now
        self._dirty = True
        self._alert_out(
            f"block cap of {self.config.cap} reached: new blocks are refused. "
            "Clear with `lurewall alerts clear` once reviewed."
        )
        self._save(now, force=True)

    # -- saved state ------------------------------------------------------------------------

    def _snapshot(self) -> dict:
        return {
            "version": STATE_VERSION,
            "hits": {source: list(hit) for source, hit in self._hits.items()},
            "blocks": {
                source: [block.start, block.expiry, block.ttl, block.enforced]
                for source, block in self._blocks.items()
            },
            "history": {source: list(item) for source, item in self._history.items()},
            "alert_raised": self._alert_raised,
        }

    def _save(self, now: int, *, force: bool = False) -> None:
        if self._state_path is None or not self._dirty:
            return
        if not force and 0 <= now - self._last_save < _SAVE_INTERVAL_MS:
            return
        write_private(self._state_path, json.dumps(self._snapshot(), sort_keys=True).encode())
        self._dirty = False
        self._last_save = now

    def _load(self) -> None:
        try:
            with self._state_path.open("rb") as handle:
                raw = handle.read(MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            return
        except OSError:
            self._sink.append("engine_state_invalid", None, {"reason": "unreadable"})
            return
        try:
            state = parse_state(raw)
        except ValueError:
            # Start empty rather than trust any part of a damaged file. Sticky
            # hits and block history are lost, which only ever means fewer
            # blocks. Live firewall entries carry their own expiry.
            self._sink.append("engine_state_invalid", None, {"reason": "malformed"})
            return
        self._hits = OrderedDict(sorted(state["hits"].items(), key=lambda item: item[1][0]))
        self._blocks = state["blocks"]
        self._history = OrderedDict(sorted(state["history"].items(), key=lambda item: item[1][1]))
        self._alert_raised = state["alert_raised"]


def _overlaps(network: Network, ranges: tuple[Network, ...]) -> bool:
    return any(item.version == network.version and item.overlaps(network) for item in ranges)


def write_private(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically at mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".lurewall-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:  # mkstemp creates the file 0600
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        raise


def _checked_source(value: object) -> str:
    if type(value) is not str or len(value) > 64:
        raise ValueError("source")
    network = ipaddress.ip_network(value, strict=True)
    if network.version == 4:
        if network.prefixlen != 32 or value != str(network.network_address):
            raise ValueError("source")
    elif network.prefixlen != 64 or value != network.compressed:
        raise ValueError("source")
    return value


def parse_state(raw: bytes) -> dict:
    """Validate saved engine state. Raises ValueError on anything unexpected."""
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError("too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except RecursionError as exc:
        raise ValueError("too deep") from exc
    if type(doc) is not dict or set(doc) != {
        "version",
        "hits",
        "blocks",
        "history",
        "alert_raised",
    }:
        raise ValueError("shape")
    if type(doc["version"]) is not int or doc["version"] != STATE_VERSION:
        raise ValueError("version")
    for name in ("hits", "blocks", "history"):
        if type(doc[name]) is not dict:
            raise ValueError(name)
    hits = {}
    for source, item in doc["hits"].items():
        if type(item) is not list or len(item) != 2 or not _is_ms(item[0]):
            raise ValueError("hit")
        if type(item[1]) is not str or len(item[1]) > 64:
            raise ValueError("hit")
        hits[_checked_source(source)] = (item[0], item[1])
    blocks = {}
    for source, item in doc["blocks"].items():
        if type(item) is not list or len(item) != 4 or type(item[3]) is not bool:
            raise ValueError("block")
        if not all(_is_ms(value) for value in item[:3]):
            raise ValueError("block")
        blocks[_checked_source(source)] = _Block(item[0], item[1], item[2], item[3])
    history = {}
    for source, item in doc["history"].items():
        if type(item) is not list or len(item) != 2 or not all(_is_ms(value) for value in item):
            raise ValueError("history")
        history[_checked_source(source)] = (item[0], item[1])
    alert = doc["alert_raised"]
    if alert is not None and not _is_ms(alert):
        raise ValueError("alert")
    return {"hits": hits, "blocks": blocks, "history": history, "alert_raised": alert}


def read_ack(state_path: Path) -> int:
    """When the standing alert was last cleared, or -1."""
    try:
        text = ack_path(state_path).read_bytes()[:32].decode("ascii").strip()
        value = int(text)
    except (OSError, ValueError):
        return -1
    return value if _is_ms(value) else -1


def clear_alert(state_path: str | Path, now_ms: int | None = None) -> None:
    """Record that the operator has seen the alert. The engine never writes this."""
    state_path = Path(state_path)
    now = _now_ms() if now_ms is None else now_ms
    write_private(ack_path(state_path), f"{now}\n".encode("ascii"))


def read_status(state_path: str | Path, now_ms: int | None = None) -> dict:
    """What the saved state says, for ``lurewall status``. Raises ValueError/OSError."""
    state_path = Path(state_path)
    now = _now_ms() if now_ms is None else now_ms
    with state_path.open("rb") as handle:
        state = parse_state(handle.read(MAX_STATE_BYTES + 1))
    active = {s: b for s, b in state["blocks"].items() if b.expiry > now}
    raised = state["alert_raised"]
    return {
        "active_blocks": len(active),
        "enforced_blocks": sum(1 for block in active.values() if block.enforced),
        "blocks": sorted(
            (block.expiry, source, block.enforced) for source, block in active.items()
        ),
        "sources_with_canary_hit": len(state["hits"]),
        "alert_standing": raised is not None and read_ack(state_path) < raised,
        "alert_raised_ms": raised,
    }
