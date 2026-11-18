# SPDX-License-Identifier: AGPL-3.0-only
"""The checkpoint job on test machine A: pull the lab's signed checkpoint and keep it.

Run on a schedule on test machine A (launchd, see deploy/launchd/). Each run:

1. fetches the checkpoint from the lab site over plain HTTP (a private address
   only, size capped);
2. checks its signature against the published public key, and refuses it
   otherwise;
3. stores it as ``checkpoints/<seq>.json`` in a local git repository, refusing
   to replace a stored checkpoint with a different one for the same sequence
   number (that would mean two histories) and flagging one that goes backwards;
4. stamps it with OpenTimestamps if the ``ots`` client is given, and tries to
   upgrade earlier stamps;
5. commits, and pushes only when asked.

The checkpoints hold a sequence number, a hash, a time and a signature: nothing
about any visitor. ``lurewall verify --anchors <repo>/checkpoints`` reads them.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from lurewall import entry as entry_mod
from lurewall import labclient
from lurewall.canonical import canonical_bytes
from lurewall.entry import EntryError

MAX_CHECKPOINT_BYTES = 64 * 1024
DIRECTORY = "checkpoints"

Runner = Callable[[list[str], Path], int]


@dataclass(frozen=True)
class PullResult:
    status: str  # stored | unchanged | conflict | went_back | fetch_failed | bad_checkpoint
    seq: int | None = None
    stamped: bool = False
    committed: bool = False
    pushed: bool = False

    @property
    def ok(self) -> bool:
        return self.status in ("stored", "unchanged")


def parse_url(text: str) -> tuple[labclient.Target, str]:
    parts = urlsplit(text)
    if parts.query or parts.fragment or not parts.path.startswith("/"):
        raise labclient.TargetError("the checkpoint URL is http://<lab address>/<path>")
    target = labclient.parse_target(f"{parts.scheme}://{parts.netloc}")
    return target, parts.path


def _subprocess_runner(argv: list[str], cwd: Path) -> int:
    try:
        return subprocess.run(  # noqa: S603 - argv is built here from fixed words and paths
            argv, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=False
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return -1


def _stored(directory: Path) -> dict[int, bytes]:
    found = {}
    for path in directory.glob("*.json"):
        if path.stem.isdigit():
            found[int(path.stem)] = path.read_bytes()
    return found


def pull(
    url: str,
    public_key_hex: str,
    repo: Path,
    *,
    ots: str | None = None,
    push: bool = False,
    sender: labclient.Sender = labclient.socket_sender,
    run: Runner = _subprocess_runner,
    git: str | None = None,
) -> PullResult:
    target, path = parse_url(url)
    response = sender(target, labclient.build_request(target, path))
    if response.status != 200 or len(response.body) > MAX_CHECKPOINT_BYTES:
        return PullResult("fetch_failed")
    try:
        checkpoint = entry_mod.check_checkpoint(json.loads(response.body), public_key_hex)
    except (ValueError, RecursionError, EntryError):
        return PullResult("bad_checkpoint")
    seq = checkpoint["seq"]
    data = canonical_bytes(checkpoint) + b"\n"

    directory = repo / DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    stored = _stored(directory)
    if seq in stored:
        return PullResult("unchanged" if stored[seq] == data else "conflict", seq)
    status = "went_back" if stored and seq < max(stored) else "stored"
    file = directory / f"{seq:012d}.json"
    file.write_bytes(data)

    stamped = False
    if ots is not None:
        stamped = run([ots, "stamp", str(file)], repo) == 0
        for pending in sorted(directory.glob("*.ots")):
            run([ots, "upgrade", str(pending)], repo)  # done when the Bitcoin proof is ready

    committed = pushed = False
    git = git or shutil.which("git")
    if git and (repo / ".git").exists():
        run([git, "add", "--", DIRECTORY], repo)
        committed = run([git, "commit", "-q", "-m", f"checkpoint {seq}"], repo) == 0
        if committed and push:
            pushed = run([git, "push", "-q"], repo) == 0
    return PullResult(status, seq, stamped, committed, pushed)
