# SPDX-License-Identifier: AGPL-3.0-only
"""Optional local metrics and isolated, coalescing webhook delivery.

The detector only updates a textfile and empty alert markers. The separate
notifier does the network I/O and retains failed markers for the next run.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import ssl
import stat
import time
from collections import Counter
from collections.abc import Callable
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from typing import Literal
from urllib.parse import SplitResult, urlsplit

from lurewall.agentfeeds import NAME
from lurewall.logreader import Sink

WEBHOOK_ENV = "LUREWALL_WEBHOOK_URL"
METRICS_FILE = "lurewall.prom"
_PUBLISH_INTERVAL_S = 15
_HEALTH_WARNING_INTERVAL_S = 60
_WEBHOOK_TIMEOUT_S = 5
_ALERTS = ("integrity_stop", "service_failure", "block_applied", "impersonation")
_HEALTH_MESSAGES = {
    "enforcement_failed": "Lurewall could not apply or reconcile firewall state",
    "access_log_unavailable": "Lurewall cannot read the configured nginx access log",
    "access_log_parse_failure": "Lurewall could not parse nginx log records. Run lurewall doctor",
    "signed_log_stopped": "Lurewall signed-log writes are paused",
    "agent_config_invalid": (
        "Lurewall could not apply /etc/lurewall/agents.toml. Run lurewall agent-check"
    ),
}
_LOGGER = logging.getLogger(__name__)

Alert = Literal["integrity_stop", "service_failure", "block_applied", "impersonation"]
Sender = Callable[[SplitResult, Alert], bool]


def _check_directory(directory: Path) -> None:
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise OSError("telemetry path is not a directory")


def _mark(directory: Path, event: Alert) -> None:
    _check_directory(directory)
    path = directory / f"{event}.pending"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        return
    os.close(fd)


def record_alert(directory: Path | None, event: Alert) -> bool:
    """Record a fixed alert kind without contacting the network."""
    if directory is None:
        return True
    if event not in _ALERTS:
        raise ValueError("unknown alert event")
    try:
        _mark(directory, event)
    except OSError:
        _LOGGER.warning("Could not queue a Lurewall alert")
        return False
    return True


def _publish_file(directory: Path, content: str) -> None:
    _check_directory(directory)
    # The detector is the sole writer. A fixed temporary name bounds leftovers
    # even across repeated interruptions during an atomic replacement.
    pending = directory / (METRICS_FILE + ".tmp")
    pending.unlink(missing_ok=True)
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            os.fchmod(stream.fileno(), 0o640)
            stream.write(content)
        os.replace(pending, directory / METRICS_FILE)
    finally:
        pending.unlink(missing_ok=True)


class Telemetry:
    """Aggregate service metrics and record block alerts locally."""

    def __init__(self, directory: Path, *, clock: Callable[[], float] = time.time) -> None:
        self._directory = directory
        self._clock = clock
        self._published_at: float | None = None
        self._agent_counts = Counter()
        self._metrics = {
            "agent_verified_total": 0,
            "agent_impersonation_total": 0,
            "agent_indeterminate_total": 0,
            "records_processed_total": 0,
            "blocks_applied_total": 0,
            "would_block_total": 0,
            "enforcement_failures_total": 0,
            "access_log_unavailable_total": 0,
            "access_log_parse_failures_total": 0,
            "active_blocks": 0,
            "access_log_lag_bytes": 0,
            "enforcing": 0,
            "signed_log_stopped": 0,
        }
        self._publish_warning = False
        self._spool_warning = False
        self._health_warning_at: dict[str, float] = {}

    def sink(self, target: Sink) -> Sink:
        return _ObservedSink(target, self)

    def _event(self, kind: str, detail: dict | None) -> None:
        if kind == "agent_identity":
            status = (detail or {}).get("verdict")
            if status in ("verified", "impersonation", "indeterminate"):
                self._metrics[f"agent_{status}_total"] += 1
                claim = detail.get("claim", "")
                method = detail.get("reason") if status == "verified" else "none"
                if (
                    isinstance(claim, str)
                    and NAME.fullmatch(claim)
                    and method in ("signature", "ip_range", "both", "none")
                ):
                    self._agent_counts[status, claim, method] += 1
            if status == "impersonation" and (detail or {}).get("alert") is True:
                self._queue("impersonation")
        elif kind == "block_applied" or (kind == "block" and (detail or {}).get("applied") is True):
            self._metrics["blocks_applied_total"] += 1
            self._queue("block_applied")
        elif kind == "would_block":
            self._metrics["would_block_total"] += 1
        elif kind == "enforcement_failed":
            self._metrics["enforcement_failures_total"] += 1
            self._warn_health(kind)
        elif kind == "agent_config_invalid":
            self._warn_health(kind)
        elif kind == "access_log_unavailable":
            self._metrics["access_log_unavailable_total"] += 1
            self._warn_health(kind)
        elif kind in {"parse_failure", "parse_failure_rollup"}:
            count = (detail or {}).get("count", 1) if kind == "parse_failure_rollup" else 1
            self._metrics["access_log_parse_failures_total"] += count
            self._warn_health("access_log_parse_failure")

    def _queue(self, event: Alert) -> None:
        try:
            _mark(self._directory, event)
        except OSError:
            if not self._spool_warning:
                _LOGGER.warning("Could not queue a Lurewall alert")
            self._spool_warning = True
        else:
            self._spool_warning = False

    def _warn_health(self, kind: str) -> None:
        now = self._clock()
        last = self._health_warning_at.get(kind)
        if last is not None and 0 <= now - last < _HEALTH_WARNING_INTERVAL_S:
            return
        self._health_warning_at[kind] = now
        _LOGGER.warning(_HEALTH_MESSAGES[kind])
        self._queue("service_failure")

    def publish(
        self,
        *,
        records: int = 0,
        active_blocks: int | None = None,
        lag_bytes: int | None = None,
        enforcing: bool | None = None,
        log_stopped: bool | None = None,
        up: bool = True,
        force: bool = False,
    ) -> None:
        """Publish a bounded textfile at most once per interval during polling."""
        self._metrics["records_processed_total"] += records
        if log_stopped:
            self._warn_health("signed_log_stopped")
        samples = {
            "active_blocks": active_blocks,
            "access_log_lag_bytes": lag_bytes,
            "enforcing": enforcing,
            "signed_log_stopped": log_stopped,
        }
        for name, value in samples.items():
            if value is not None:
                self._metrics[name] = int(value)
        now = self._clock()
        if (
            not force
            and self._published_at is not None
            and 0 <= now - self._published_at < _PUBLISH_INTERVAL_S
        ):
            return
        self._published_at = now
        snapshot = {
            "up": int(up),
            "metrics_timestamp_seconds": max(0, int(now)),
            **self._metrics,
        }
        content = "".join(
            f"# TYPE lurewall_{name} {'counter' if name.endswith('_total') else 'gauge'}\n"
            f"lurewall_{name} {value}\n"
            for name, value in snapshot.items()
        )
        if self._agent_counts:
            content += "# TYPE lurewall_agent_claims_total counter\n"
            for (status, claim, method), count in sorted(self._agent_counts.items()):
                content += (
                    f'lurewall_agent_claims_total{{verdict="{status}",claim="{claim}",'
                    f'method="{method}"}} {count}\n'
                )
        try:
            _publish_file(self._directory, content)
        except OSError:
            if not self._publish_warning:
                _LOGGER.warning("Could not publish Lurewall metrics")
            self._publish_warning = True
        else:
            self._publish_warning = False


class _ObservedSink:
    def __init__(self, target: Sink, telemetry: Telemetry) -> None:
        self._target = target
        self._telemetry = telemetry

    def append(
        self,
        type: str,
        source: str | None = None,
        detail: dict | None = None,
        *,
        rollup_key: str | None = None,
    ) -> object:
        result = self._target.append(type, source, detail, rollup_key=rollup_key)
        self._telemetry._event(type, detail)
        return result


def _parse_endpoint(value: str) -> SplitResult:
    if len(value) > 2048 or any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("invalid webhook URL")
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username is not None or url.fragment:
        raise ValueError("webhook URL must use HTTPS")
    if url.port == 0:
        raise ValueError("invalid webhook port")
    return url


def _post(endpoint: SplitResult, event: Alert) -> bool:
    target = endpoint.path or "/"
    if endpoint.query:
        target += "?" + endpoint.query
    connection = HTTPSConnection(
        endpoint.hostname,
        port=endpoint.port,
        timeout=_WEBHOOK_TIMEOUT_S,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "POST",
            target,
            body=json.dumps({"event": event, "service": "lurewall"}).encode("ascii"),
            headers={"Content-Type": "application/json"},
        )
        return 200 <= connection.getresponse().status < 300
    finally:
        connection.close()


def _marker_exists(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_size:
        raise OSError("unexpected alert marker")
    return True


def _deliver(directory: Path, endpoint: SplitResult, sender: Sender) -> bool:
    _check_directory(directory)
    # Only the notifier uses this lock. The detection process never waits for a
    # slow webhook. Markers arriving during delivery use the pending slot.
    fd = os.open(
        directory / ".notify.lock",
        os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        0o600,
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("unexpected notifier lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        ok = True
        for event in _ALERTS:
            inflight = directory / f"{event}.sending"
            if not _marker_exists(inflight):
                pending = directory / f"{event}.pending"
                if not _marker_exists(pending):
                    continue
                os.replace(pending, inflight)
            try:
                delivered = sender(endpoint, event)
            except (OSError, HTTPException, ValueError):
                delivered = False
            if delivered:
                inflight.unlink()
            else:
                ok = False
        return ok
    finally:
        os.close(fd)


def notify(directory: Path, *, service_failure: bool = False, sender: Sender = _post) -> int:
    """Send queued alerts with an explicit HTTPS destination, reporting failures safely."""
    value = os.environ.get(WEBHOOK_ENV)
    if not value:
        return 0
    integrity_stop = (
        os.environ.get("MONITOR_EXIT_CODE") == "exited"
        and os.environ.get("MONITOR_EXIT_STATUS") == "3"
    )
    if service_failure:
        # The detector already records its own integrity stop. The sweeper and
        # other monitored units do not have the detector's telemetry path.
        recorded = integrity_stop and os.environ.get("MONITOR_UNIT") == "lurewall.service"
        event = "integrity_stop" if integrity_stop else "service_failure"
        if not recorded and not record_alert(directory, event):
            return 1
    try:
        endpoint = _parse_endpoint(value)
    except ValueError:
        _LOGGER.warning("Lurewall webhook configuration requires a valid HTTPS URL")
        return 1
    try:
        ok = _deliver(directory, endpoint, sender)
    except OSError:
        _LOGGER.warning("Could not read or update the Lurewall alert spool")
        return 1
    if not ok:
        _LOGGER.warning("Lurewall webhook delivery failed; queued alerts will be retried")
    return 0 if ok else 1
