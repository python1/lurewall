# SPDX-License-Identifier: AGPL-3.0-only
"""The main service, and the sweeper that runs apart from it.

The service tails nginx's access log and feeds each record through the
collector and the decision engine. It never sits in the request path. On
startup it reconciles the enforcement adapter with its saved state.

The sweeper is a separate command, run by its own systemd timer. It reads
expiry times from the live nftables entries and removes what is past due. It
needs neither the service nor the service's state, so a block still ends on
time when the service is stopped. It writes to its own signed log: the main
log has one writer, and that writer may be running or may not.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from lurewall import canaries, engineconfig, labsite, sigconfig, signing
from lurewall.collector import SignalCollector
from lurewall.engine import Adapter, Engine, LogOnlyAdapter, journal_alert
from lurewall.eventlog import EventLog
from lurewall.logreader import LogReader
from lurewall.nft import NftAdapter, NftError, Runner, system_runner
from lurewall.observability import Telemetry
from lurewall.operator import consume_unblock, read_allowlist, validate_control_dir
from lurewall.signals import Classifier


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class Paths:
    access_log: Path
    reader_state: Path
    event_log: Path
    key: Path
    canaries: Path
    signals: Path
    engine_config: Path
    engine_state: Path
    checkpoint: Path | None = None
    allowlist_file: Path | None = None
    operator_dir: Path | None = None
    require_peer_log: bool = False
    telemetry_dir: Path | None = None


def make_adapter(
    config: engineconfig.EngineConfig,
    *,
    runner: Runner | None = None,
    clock: Callable[[], int] = _now_ms,
) -> Adapter:
    """The adapter the config asks for. Nothing enforces while dry-run is on."""
    if config.adapter == "nftables":
        return NftAdapter(
            runner if runner is not None else system_runner(config.nft_path),
            clock=clock,
            dry_run=config.dry_run,
            tcp_ports=config.tcp_ports,
        )
    return LogOnlyAdapter()


class Service:
    def __init__(
        self,
        paths: Paths,
        *,
        clock: Callable[[], int] = _now_ms,
        runner: Runner | None = None,
        alert: Callable[[str], None] = journal_alert,
        fsync: bool = True,
    ) -> None:
        # Everything that can be wrong with the files is found before the
        # signed log is opened, so a bad config writes nothing.
        config = engineconfig.load(paths.engine_config)
        if paths.allowlist_file is not None:
            config = replace(
                config,
                allowlist=tuple(
                    dict.fromkeys((*config.allowlist, *read_allowlist(paths.allowlist_file)))
                ),
            )
        self._operator_dir = paths.operator_dir
        self._clock = clock
        self._next_unblock_ms = 0
        if self._operator_dir is not None:
            validate_control_dir(self._operator_dir)
        if paths.require_peer_log and config.enforcing and not config.tcp_ports:
            raise engineconfig.EngineConfigError(
                "operator enforcement requires explicit enforcement.tcp_ports"
            )
        canary_set = canaries.load_state(paths.canaries)
        routes = labsite.site_routes()
        # A decoy that collides with a real route is disabled, not served as a
        # trap: a real page must never count as a canary hit.
        disabled = sorted(
            {canary_id for canary_id, _route in canaries.find_collisions(canary_set, routes)}
        )
        if disabled:
            canary_set = replace(
                canary_set, canaries=tuple(c for c in canary_set.canaries if c.id not in disabled)
            )
        classifier = Classifier(
            sigconfig.load(paths.signals),
            canary_set,
            routes,
            labsite.quiet_carriers(canary_set),
        )
        signer = signing.EurekaSigner.load(paths.key)

        self.config = config
        self.telemetry = Telemetry(paths.telemetry_dir) if paths.telemetry_dir is not None else None
        self.events = EventLog(
            paths.event_log, signer, checkpoint_path=paths.checkpoint, fsync=fsync, clock=clock
        )
        try:
            sink = self.telemetry.sink(self.events) if self.telemetry is not None else self.events
            self.collector = SignalCollector(classifier, sink)
            self.adapter = make_adapter(config, runner=runner, clock=clock)
            self.engine = Engine(
                config,
                sink,
                self.collector.tracker,
                adapter=self.adapter,
                state_path=paths.engine_state,
                clock=clock,
                alert=alert,
            )
            self.reader = LogReader(
                paths.access_log,
                paths.reader_state,
                sink,
                clock=clock,
                require_peer_log=paths.require_peer_log,
                trusted_proxies=config.trusted_proxies,
            )
            self.events.append(
                "service_started", None, {"dry_run": config.dry_run, "adapter": config.adapter}
            )
            for canary_id in disabled:
                self.events.append("canary_disabled_collision", None, {"canary": canary_id})
            self._process_control()
            report = self.engine.start()
            if paths.require_peer_log and config.enforcing and report is None:
                raise NftError(
                    "initial nftables reconciliation failed; check the unit and firewall"
                )
        except BaseException:
            self.events.close()
            raise

    def step(self) -> int:
        """Read what is new in the access log and act on it. Returns the record count."""
        self._process_control()
        records = self.reader.poll()
        for record in records:
            self.engine.handle(self.collector.handle(record))
        # Saved only after the records were dealt with: after a crash they are
        # read again, never skipped.
        self.reader.commit()
        self.engine.tick()
        self.events.tick()
        if self.telemetry is not None:
            self.telemetry.publish(
                records=len(records),
                active_blocks=len(self.engine.active_blocks()),
                lag_bytes=self.reader.lag().bytes_behind,
                enforcing=self.config.enforcing,
                log_stopped=self.events.stopped,
            )
        return len(records)

    def _process_control(self) -> None:
        if self._operator_dir is None:
            return
        now = self._clock()
        if now >= self._next_unblock_ms and not consume_unblock(self._operator_dir, self.engine):
            self._next_unblock_ms = now + 5_000

    def run(self, stop: threading.Event, interval_s: float = 1.0) -> None:
        while not stop.is_set():
            if self.step() == 0:
                stop.wait(interval_s)

    def close(self) -> None:
        try:
            self.engine.close()
            self.reader.close()
            self.events.append("service_stopped", None, {})
            # A clean stop leaves a checkpoint over everything written so far.
            self.events.checkpoint()
        finally:
            try:
                self.events.close()
            finally:
                if self.telemetry is not None:
                    self.telemetry.publish(up=False, force=True)


def sweep(
    event_log: Path,
    key: Path,
    *,
    nft_path: str = "/usr/sbin/nft",
    runner: Runner | None = None,
    clock: Callable[[], int] = _now_ms,
    fsync: bool = True,
) -> tuple[int, bool]:
    """One sweeper run. Returns (entries removed, whether the run succeeded).

    A run that finds nothing to remove writes nothing, so a timer firing every
    minute does not grow the log.
    """
    adapter = NftAdapter(
        runner if runner is not None else system_runner(nft_path), clock=clock, dry_run=False
    )
    error = None
    removed: list[tuple[str, str]] = []
    try:
        removed = adapter.sweep()
    except NftError as exc:
        error = type(exc).__name__
    if not removed and error is None:
        return 0, True
    signer = signing.EurekaSigner.load(key)
    log = EventLog(event_log, signer, fsync=fsync, clock=clock)
    try:
        for element, reason in removed:
            log.append("sweep_removed", None, {"element": element, "reason": reason})
        if error is not None:
            # Logged, and tried again on the next run.
            log.append("sweep_failed", None, {"error": error})
    finally:
        log.close()
    return len(removed), error is None
