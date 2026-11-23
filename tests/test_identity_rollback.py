# SPDX-License-Identifier: AGPL-3.0-only
"""Run the released reader in a separate interpreter over the exact saved cursor."""

import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from lurewall import _eureka, signing
from lurewall.accesslog import CAPTURE_FIELDS
from lurewall.eventlog import EventLog
from lurewall.identitylab import log_fields
from lurewall.logreader import LogReader
from lurewall.verify import verify_log

ROOT = Path(__file__).resolve().parents[1]
V03 = "454127f949fa026975d723104a4818420e4d4373"


def test_v04_drain_then_v03_resume(tmp_path):
    old = tmp_path / "released"
    archive = subprocess.check_output(  # noqa: S603
        ["git", "archive", "--format=zip", V03, "src/lurewall"],  # noqa: S607
        cwd=ROOT,
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        source.extractall(old)
    access, cursor, events, key, checkpoint = (
        tmp_path / name for name in ("access", "cursor", "events", "key", "anchor")
    )
    signer = signing.EurekaSigner.generate(key)
    fields = log_fields(1800000000)
    access.write_bytes(json.dumps(fields).encode() + b"\n")
    log = EventLog(events, signer, checkpoint_path=checkpoint)
    reader = LogReader(access, cursor, log, require_peer_log=True)
    batch = reader.poll()
    assert len(batch) == 1 and batch[0].capture
    log.append("agent_identity", batch[0].ip, {"request_id": batch[0].request_id, "counted": False})
    reader.commit()
    reader.close()
    log.checkpoint()
    log.close()
    prefix = events.read_bytes()
    offset = access.stat().st_size
    assert json.loads(cursor.read_bytes())["offset"] == offset
    for name in ("v", *CAPTURE_FIELDS):
        fields.pop(name)
    fields["request_id"] = "cd" * 16
    with access.open("ab") as stream:
        stream.write(json.dumps(fields).encode() + b"\n")
    released = """
from pathlib import Path
from lurewall import accesslog, signing
from lurewall.eventlog import EventLog
from lurewall.logreader import LogReader
from lurewall.verify import verify_log
assert Path(accesslog.__file__).resolve().is_relative_to(Path('released').resolve())
key = signing.EurekaSigner.load('key')
log = EventLog('events',key)
reader = LogReader('access','cursor',log,require_peer_log=True)
batch = reader.poll()
assert len(batch)==1 and batch[0].request_id=='cd'*16
assert batch[0].offset==int(__import__('sys').argv[1])
log.append('rollback_resume',batch[0].ip,{'request_id':batch[0].request_id})
reader.commit()
reader.close()
log.close()
assert verify_log('events',key.public_key_hex,[Path('anchor')]).ok
"""
    subprocess.run(  # noqa: S603
        [sys.executable, "-c", released, str(offset)],
        cwd=tmp_path,
        check=True,
        env={
            **os.environ,
            "PYTHONPATH": str(old / "src"),
            _eureka.CRYPTO_PATH_ENV_VAR: str(_eureka.crypto_path()),
        },
    )
    report = verify_log(events, signer.public_key_hex, [checkpoint])
    assert report.ok and report.last_matched_anchor_seq
    assert events.read_bytes().startswith(prefix) and len(events.read_bytes()) > len(prefix)
    assert json.loads(cursor.read_bytes())["offset"] == access.stat().st_size
