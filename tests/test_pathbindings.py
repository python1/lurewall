# SPDX-License-Identifier: AGPL-3.0-only
"""Natural issuance receipts survive a detector restart, bounded and validated."""

from __future__ import annotations

import json
import stat

import pytest

import sig
from conftest import FakeClock
from lurewall import engine as engine_mod
from lurewall import pathbindings
from lurewall.collector import SignalCollector
from lurewall.engine import Engine, receipts_path
from lurewall.engineconfig import EngineConfig
from lurewall.pathbindings import Issuance, IssuedPaths

T0 = 1_800_000_000_000
DAY = 86_400_000
PATH = "/garden/copper-lantern/"
SOURCE = "192.0.2.10"


def receipt(issued=T0, until=T0 + 3 * DAY, source=SOURCE):
    return Issuance(source, "footer_comment.quiet", issued, until, "a" * 32, "b" * 64)


def start(tmp_path, clock, sink=None):
    sink = sink or sig.ListSink()
    paths = IssuedPaths(100)
    collector = SignalCollector(sig.classifier(), sink)
    running = Engine(
        EngineConfig(),
        sink,
        collector.tracker,
        state_path=tmp_path / "engine.json",
        issued_paths=paths,
        clock=clock,
    )
    return running, paths, sink


def test_receipts_survive_a_restart_in_a_private_file_beside_v02_state(tmp_path):
    clock = FakeClock(T0)
    running, paths, _ = start(tmp_path, clock)
    assert paths.record(PATH, receipt())
    paths.record("/garden/walnut-meadow/", receipt(source=None))
    running.close()

    saved = receipts_path(tmp_path / "engine.json")
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    # engine.json is untouched by receipts, so a v0.2 executable still reads it.
    assert not (tmp_path / "engine.json").exists()

    clock.advance(DAY)
    _, restored, sink = start(tmp_path, clock)
    assert restored.lookup(PATH, clock.now) == receipt()
    assert restored.lookup("/garden/walnut-meadow/", clock.now).source is None
    assert not sink.of("engine_state_invalid")


def test_expired_receipts_are_not_restored(tmp_path):
    clock = FakeClock(T0)
    running, paths, _ = start(tmp_path, clock)
    paths.record(PATH, receipt())
    running.close()
    clock.advance(4 * DAY)
    _, restored, _ = start(tmp_path, clock)
    assert restored.lookup(PATH, clock.now) is None


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b'{"version": 2, "receipts": []}',
        json.dumps(
            {
                "version": 1,
                "receipts": [
                    ["/Bad Path", None, "footer_comment.quiet", T0, T0 + DAY, "a" * 32, "b" * 64]
                ],
            }
        ).encode(),
        json.dumps(
            {
                "version": 1,
                "receipts": [
                    [PATH, "192.0.2.0/24", "footer_comment.quiet", T0, T0 + DAY, "a" * 32, "b" * 64]
                ],
            }
        ).encode(),
        json.dumps(
            {
                "version": 1,
                "receipts": [
                    [PATH, SOURCE, "footer_comment.quiet", T0, T0 + 8 * DAY, "a" * 32, "b" * 64]
                ],
            }
        ).encode(),
        json.dumps(
            {
                "version": 1,
                "receipts": [[PATH, SOURCE, "unknown.placement", T0, T0 + DAY, "a" * 32, "b" * 64]],
            }
        ).encode(),
    ],
)
def test_a_damaged_receipts_file_is_reported_and_ignored(tmp_path, content):
    receipts_path(tmp_path / "engine.json").write_bytes(content)
    _, restored, sink = start(tmp_path, FakeClock(T0))
    assert [event[2] for event in sink.of("engine_state_invalid")] == [
        {"reason": "malformed", "file": "receipts"}
    ]
    assert restored.lookup(PATH, T0) is None


def test_saved_receipts_are_bounded_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(pathbindings, "PERSIST_LIMIT", 3)
    paths = IssuedPaths(100)
    for n in range(5):
        paths.record(f"/garden/copper-lantern{n}/", receipt(issued=T0 + n))
    rows = json.loads(paths.dumps(T0 + 10))["receipts"]
    assert [row[0] for row in rows] == [f"/garden/copper-lantern{n}/" for n in (4, 3, 2)]

    monkeypatch.setattr(pathbindings, "PERSIST_LIMIT", 10_000)
    monkeypatch.setattr(pathbindings, "MAX_STATE_BYTES", 600)
    data = paths.dumps(T0 + 10)
    assert len(data) <= 600
    assert json.loads(data)["receipts"][0][0] == "/garden/copper-lantern4/"


def test_engine_state_shape_is_unchanged_for_rollback(tmp_path):
    clock = FakeClock(T0)
    running, paths, _ = start(tmp_path, clock)
    paths.record(PATH, receipt())
    running._dirty = True  # force an engine.json write next to the receipts
    running.close()
    state = json.loads((tmp_path / "engine.json").read_text())
    assert set(state) == {"version", "hits", "blocks", "history", "alert_raised"}
    engine_mod.parse_state((tmp_path / "engine.json").read_bytes())
