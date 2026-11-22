# SPDX-License-Identifier: AGPL-3.0-only
"""Test telemetry using local files and injected webhook responses."""

import fcntl
import json
import os
import ssl
import stat
from types import SimpleNamespace

import pytest

from conftest import FakeClock
from lurewall import observability

WEBHOOK = "https://notify.example.test/receipt?key=fixture-secret"


class Sink:
    def __init__(self):
        self.entries = []

    def append(self, kind, source, detail, *, rollup_key=None):
        self.entries.append((kind, source, detail, rollup_key))
        return self.entries[-1]


def metrics(directory):
    content = (directory / observability.METRICS_FILE).read_text()
    return dict(line.split() for line in content.splitlines() if not line.startswith("#"))


def test_metrics_are_bounded_aggregate_and_go_down_on_clean_stop(tmp_path):
    clock = FakeClock(1_700_000_000)
    telemetry = observability.Telemetry(tmp_path, clock=clock)
    target = Sink()
    sink = telemetry.sink(target)
    detail = {"applied": True, "unexpected": "should not leave signed log"}
    result = sink.append("block", "2001:db8:1::/64", detail, rollup_key="kept")
    assert result == target.entries[-1] == ("block", "2001:db8:1::/64", detail, "kept")
    sink.append("block", None, {"applied": False})
    sink.append("block_applied", None)
    sink.append("block_restored", None)
    sink.append("would_block", None)
    sink.append("enforcement_failed", None)
    sink.append("access_log_unavailable", None)
    sink.append("parse_failure", None)
    sink.append("parse_failure_rollup", None, {"count": 12})
    telemetry.publish(records=6, active_blocks=2, lag_bytes=17, enforcing=True, log_stopped=True)
    expected = {
        "lurewall_agent_verified_total": "0",
        "lurewall_agent_impersonation_total": "0",
        "lurewall_agent_indeterminate_total": "0",
        "lurewall_up": "1",
        "lurewall_metrics_timestamp_seconds": str(clock.now),
        "lurewall_records_processed_total": "6",
        "lurewall_blocks_applied_total": "2",
        "lurewall_would_block_total": "1",
        "lurewall_enforcement_failures_total": "1",
        "lurewall_access_log_unavailable_total": "1",
        "lurewall_access_log_parse_failures_total": "13",
        "lurewall_active_blocks": "2",
        "lurewall_access_log_lag_bytes": "17",
        "lurewall_enforcing": "1",
        "lurewall_signed_log_stopped": "1",
    }
    assert metrics(tmp_path) == expected
    path = tmp_path / observability.METRICS_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert "2001:db8" not in path.read_text()
    assert "unexpected" not in path.read_text()
    assert (tmp_path / "block_applied.pending").read_bytes() == b""

    clock.advance(1)
    telemetry.publish(records=3)
    assert metrics(tmp_path) == expected
    telemetry.publish(up=False, force=True)
    assert metrics(tmp_path) == {
        **expected,
        "lurewall_up": "0",
        "lurewall_metrics_timestamp_seconds": str(clock.now),
        "lurewall_records_processed_total": "9",
    }


def test_metrics_and_alert_io_errors_do_not_block_signed_events(tmp_path, caplog):
    path = tmp_path / "missing"
    telemetry = observability.Telemetry(path)
    target = Sink()
    sink = telemetry.sink(target)
    for _ in range(3):
        sink.append("block_applied", None)
        telemetry.publish(force=True)
    assert len(target.entries) == 3
    assert caplog.messages.count("Could not queue a Lurewall alert") == 1
    assert caplog.messages.count("Could not publish Lurewall metrics") == 1


def test_degraded_running_service_queues_health_alert_and_limits_journal(tmp_path, caplog):
    clock = FakeClock(10)
    telemetry = observability.Telemetry(tmp_path, clock=clock)
    sink = telemetry.sink(Sink())
    for _ in range(10):
        sink.append("enforcement_failed", None, {"issue": "private fixture"})
        sink.append("access_log_unavailable", None)
        sink.append("parse_failure", None)
        telemetry.publish(log_stopped=True)
    service_health = dict(observability._HEALTH_MESSAGES)
    service_health.pop("agent_config_invalid")
    assert caplog.messages == list(service_health.values())
    assert "private fixture" not in caplog.text
    assert (tmp_path / "service_failure.pending").read_bytes() == b""
    clock.advance(60)
    sink.append("enforcement_failed", None)
    assert caplog.messages[-1] == observability._HEALTH_MESSAGES["enforcement_failed"]
    assert len(caplog.messages) == 5


def test_failed_atomic_metrics_write_preserves_previous_snapshot(tmp_path, monkeypatch):
    telemetry = observability.Telemetry(tmp_path)
    telemetry.publish(records=1)
    path = tmp_path / observability.METRICS_FILE
    before = path.read_bytes()

    def broken_replace(_old, _new):
        raise OSError("simulated failure")

    monkeypatch.setattr(os, "replace", broken_replace)
    telemetry.publish(records=1, force=True)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_notifier_is_disabled_without_explicit_webhook(tmp_path, monkeypatch):
    monkeypatch.delenv(observability.WEBHOOK_ENV, raising=False)
    assert observability.record_alert(tmp_path, "integrity_stop")

    def unexpected(*_args):
        pytest.fail("disabled alerts must not send a webhook")

    assert observability.notify(tmp_path, service_failure=True, sender=unexpected) == 0
    assert {path.name for path in tmp_path.iterdir()} == {"integrity_stop.pending"}


@pytest.mark.parametrize(
    "url",
    [
        "http://notify.example.test/fixture-secret",
        "https://fixture-secret@notify.example.test/",
        "https://notify.example.test/#fixture-secret",
        "https://notify.example.test:fixture-secret/",
        "https://notify.example.test/\r\nfixture-secret",
    ],
)
def test_invalid_webhook_reports_failure_without_exposing_url(tmp_path, monkeypatch, caplog, url):
    monkeypatch.setenv(observability.WEBHOOK_ENV, url)

    def unexpected(*_args):
        pytest.fail("invalid alert URLs must not open a connection")

    assert observability.notify(tmp_path, sender=unexpected) == 1
    assert caplog.messages == ["Lurewall webhook configuration requires a valid HTTPS URL"]
    assert "fixture-secret" not in caplog.text


def test_delivery_failures_are_retried_and_concurrent_marks_survive(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv(observability.WEBHOOK_ENV, WEBHOOK)
    for _ in range(10):
        assert observability.record_alert(tmp_path, "block_applied")
    assert len(list(tmp_path.glob("*.pending"))) == 1
    attempts = []

    def send(_endpoint, event):
        attempts.append(event)
        if len(attempts) == 1:
            # A new event arrives after the first was taken for delivery.
            assert observability.record_alert(tmp_path, event)
            raise OSError("fixture-secret")
        return True

    assert observability.notify(tmp_path, sender=send) == 1
    assert "fixture-secret" not in caplog.text
    assert {path.name for path in tmp_path.iterdir()} == {
        ".notify.lock",
        "block_applied.pending",
        "block_applied.sending",
    }
    assert observability.notify(tmp_path, sender=send) == 0
    assert observability.notify(tmp_path, sender=send) == 0
    assert attempts == ["block_applied"] * 3
    assert [path.name for path in tmp_path.iterdir()] == [".notify.lock"]


def test_overlapping_notifier_leaves_marker_for_the_active_worker(tmp_path, monkeypatch):
    monkeypatch.setenv(observability.WEBHOOK_ENV, WEBHOOK)
    assert observability.record_alert(tmp_path, "block_applied")

    def unexpected(*_args):
        pytest.fail("only one notifier can drain the spool at a time")

    with (tmp_path / ".notify.lock").open("xb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        assert observability.notify(tmp_path, sender=unexpected) == 0
    assert (tmp_path / "block_applied.pending").exists()


@pytest.mark.parametrize(
    ("unit", "status"),
    [("lurewall.service", "3"), ("lurewall-sweeper.service", "3"), ("lurewall.service", "1")],
)
def test_failure_unit_reports_only_the_relevant_event(tmp_path, monkeypatch, unit, status):
    monkeypatch.setenv(observability.WEBHOOK_ENV, WEBHOOK)
    monkeypatch.setenv("MONITOR_EXIT_CODE", "exited")
    monkeypatch.setenv("MONITOR_EXIT_STATUS", status)
    monkeypatch.setenv("MONITOR_UNIT", unit)
    if status == "3" and unit == "lurewall.service":
        assert observability.record_alert(tmp_path, "integrity_stop")
    events = []

    def send(_endpoint, event):
        events.append(event)
        return True

    assert observability.notify(tmp_path, service_failure=True, sender=send) == 0
    assert events == ["integrity_stop" if status == "3" else "service_failure"]


@pytest.mark.parametrize(("http_status", "delivered"), [(204, True), (302, False), (503, False)])
def test_webhook_verifies_tls_and_never_follows_redirects(monkeypatch, http_status, delivered):
    calls = []

    class Connection:
        def __init__(self, host, *, port, timeout, context):
            assert host == "notify.example.test"
            assert port is None
            assert timeout == 5
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            calls.append("connect")

        def request(self, method, path, *, body, headers):
            assert method == "POST"
            assert path == "/receipt?key=fixture-secret"
            assert json.loads(body) == {"event": "block_applied", "service": "lurewall"}
            assert headers == {"Content-Type": "application/json"}
            calls.append("post")

        def getresponse(self):
            return SimpleNamespace(status=http_status)

        def close(self):
            calls.append("close")

    monkeypatch.setattr(observability, "HTTPSConnection", Connection)
    assert observability._post(observability._parse_endpoint(WEBHOOK), "block_applied") == delivered
    assert calls == ["connect", "post", "close"]
