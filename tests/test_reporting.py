# SPDX-License-Identifier: AGPL-3.0-only
import json
import re
from pathlib import Path

import pytest

from lurewall import cli
from lurewall.observability import METRICS_FILE, Telemetry

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "192.0.2.34"
READER = "2001:db8:42::/64"


def args(log, signer):
    return ["--event-log", str(log.path), "--pubkey", signer.public_key_hex]


def test_report_window_rollups_redaction_and_verification(
    make_log, signer, clock, monkeypatch, capsys
):
    log = make_log()
    log.append("canary_hit", ISSUER, {"counted": True})
    clock.advance(3_600_000)
    for _ in range(3):
        log.append("attack_signal", ISSUER, {"signal": "path:*/.git"}, rollup_key="path:*/.git")
        log.append("would_block", ISSUER, {"reason": "dry_run"}, rollup_key="dry_run")
        log.append("canary_hit", ISSUER, {"signal": "research"}, rollup_key="security_txt.quiet")
    log.append("canary_hit", READER, {"counted": True})
    log.append("block", READER, {"applied": False})
    log.append("block_applied", READER, {})
    hidden_path = "/internal/hidden-reference"
    relay = {
        "issued_to": ISSUER,
        "path": hidden_path,
        "signal": hidden_path,
        "reason": "<img src=x>",
    }
    log.append("canary_relayed", READER, relay)
    log.append("canary_relayed", READER, {**relay, "issued_to": READER})
    log.append("canary_relayed", READER, {**relay, "issued_to": "2001:db8::%<script>"})
    log.append("canary_relayed", "192.0.2.101", {**relay, "stale": True})
    log.append("cross_site", "192.0.2.101", relay)
    log.append("attack_signal", ISSUER, {"signal": f"path:{hidden_path}"})
    log.close()
    monkeypatch.setattr("time.time_ns", lambda: clock.now * 1_000_000)
    arguments = ["report", *args(log, signer), "--since", "10m"]
    for extra in ([], ["--html"]):
        assert cli.main([*arguments, *extra]) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "1 distinct source took bait" in out
        assert "3 would-block decisions. 1 block successfully applied" in out
        assert "3 research-only hits" in out
        assert "1 candidate source pair" in out and f"{ISSUER} → {READER}" in out
        assert "Signed canary_relayed #" in out and "legacy record" in out
        assert "*/.git — 3" in out and "Other path rules — 1" in out
        assert "192.0.2.101" not in out and hidden_path not in out
        assert "<script" not in out and "<img" not in out
        assert out.startswith("<!doctype html>") == bool(extra)
    log.path.write_bytes(log.path.read_bytes().replace(b"would_block", b"would_shock", 1))
    assert cli.main([*arguments, "--html"]) == cli.EXIT_FAIL
    failed = capsys.readouterr()
    assert not failed.out and "RESULT: FAIL" in failed.err


@pytest.mark.parametrize("address", [ISSUER, "2001:db8:42::1234"])
def test_explain_possible_switch_from_either_endpoint(make_log, signer, address, capsys):
    log = make_log()
    log.append("canary_relayed", READER, {"issued_to": ISSUER, "reason": "/secret-copied-link"})
    log.close()
    assert cli.main(["explain-decision", address, *args(log, signer)]) == cli.EXIT_OK
    output = capsys.readouterr().out
    record = json.loads(output.splitlines()[-1])
    assert record["detail"]["issued_to"] == ISSUER and record["detail"]["requested_by"] == READER
    assert "Possible IP switch" in record["detail"]["observation"]
    assert "/secret-copied-link" not in output


def test_report_empty_window_and_invalid_duration(make_log, signer, capsys):
    log = make_log()
    log.close()
    assert cli.main(["report", *args(log, signer)]) == cli.EXIT_OK
    assert "No signed events" in capsys.readouterr().out
    assert cli.main(["report", "--since=bad", *args(log, signer)]) == cli.EXIT_USAGE


def test_grafana_dashboard_queries_shipped_textfile_metrics(tmp_path):
    dashboard = json.loads((ROOT / "deploy/grafana/lurewall.json").read_text())
    Telemetry(tmp_path).publish(force=True)
    metrics = {
        line.split()[0]
        for line in (tmp_path / METRICS_FILE).read_text().splitlines()
        if line and not line.startswith("#")
    }
    assert dashboard["__inputs"][0]["pluginId"] == "prometheus"
    queried = set()
    for panel in dashboard["panels"]:
        assert panel["datasource"]["uid"] == "${DS_PROMETHEUS}"
        for target in panel["targets"]:
            queried.update(re.findall(r"\blurewall_[a-z_]+", target["expr"]))
    assert queried == metrics
