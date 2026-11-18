# SPDX-License-Identifier: AGPL-3.0-only
"""The checkpoint job on test machine A: pull the lab's signed checkpoint and keep it.

Run on a schedule on test machine A (launchd, see deploy/launchd/). Each run:

1. fetches the checkpoint from the lab site over plain HTTP (a private address
   only, size capped);
2. checks its signature against the published public key, and refuses it
   otherwise;
3. stores it as ``checkpoints/<seq>.json`` in a local git repository, retaining
   the first checkpoint for each sequence and flagging conflicting heads or
   sequence numbers that go backwards;
4. stamps it with OpenTimestamps if the ``ots`` client is given, and tries to
   upgrade earlier stamps;
5. commits, and pushes only when asked.

An unchanged checkpoint can still need publication work. The receipt and
proof files and the Git index tell the job which steps still need to run.

The checkpoints hold a sequence number, a hash, a time and a signature: nothing
about any visitor. ``lurewall verify --anchors <repo>/checkpoints`` reads them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
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
_GIT_DIFF_BATCH = 128

Runner = Callable[[list[str], Path], int]


@dataclass(frozen=True)
class PullResult:
    status: str
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


def _stored(directory: Path) -> dict[int, Path]:
    found = {}
    for path in directory.glob("*.json"):
        if path.stem.isascii() and path.stem.isdigit() and _regular_file(path):
            found[int(path.stem)] = path
    return found


def _regular_file(path: Path) -> bool:
    return not path.is_symlink() and path.is_file()


def _has_proof(path: Path) -> bool:
    return _regular_file(path) and path.stat().st_size > 0


def _store(file: Path, data: bytes) -> bool:
    """Publish a complete receipt without overwriting another writer's receipt."""
    with tempfile.NamedTemporaryFile(dir=file.parent, prefix=".receipt-") as pending:
        pending.write(data)
        pending.flush()
        os.fsync(pending.fileno())
        try:
            os.link(pending.name, file)
        except FileExistsError:
            return False
    return True


def _stamp(file: Path, proof: Path, repo: Path, ots: str, run: Runner) -> bool:
    if _has_proof(proof):
        return True
    with tempfile.TemporaryDirectory(dir=file.parent, prefix=".stamp-") as directory:
        receipt = Path(directory) / file.name
        shutil.copyfile(file, receipt)
        staged = receipt.with_suffix(".json.ots")
        if run([ots, "stamp", str(receipt)], repo) != 0 or not _has_proof(staged):
            return False
        if not _has_proof(proof):
            os.replace(staged, proof)
    return True


def _commit(repo: Path, seq: int, files: list[Path], git: str, run: Runner) -> str:
    paths = [str(path.relative_to(repo)) for path in files]
    with tempfile.NamedTemporaryFile(prefix="lurewall-paths-") as pathspec:
        for path in paths:
            pathspec.write(os.fsencode(path) + b"\0")
        pathspec.flush()
        scope = [f"--pathspec-from-file={pathspec.name}", "--pathspec-file-nul"]
        if run([git, "add", *scope], repo) != 0:
            return "stage_failed"
        for first in range(0, len(paths), _GIT_DIFF_BATCH):
            batch = paths[first : first + _GIT_DIFF_BATCH]
            pending = run([git, "diff", "--cached", "--quiet", "--", *batch], repo)
            if pending == 1:
                command = [git, "commit", "--only", "-q", "-m", f"checkpoint {seq}", *scope]
                return "committed" if run(command, repo) == 0 else "commit_failed"
            if pending != 0:
                return "stage_failed"
    return "nothing_to_commit"


def _publish(
    status: str,
    seq: int,
    file: Path,
    stored: dict[int, Path],
    repo: Path,
    *,
    ots: str | None,
    push: bool,
    run: Runner,
    git: str | None,
) -> PullResult:
    stamped = False
    if ots is not None:
        stamped = _stamp(file, file.with_suffix(".json.ots"), repo, ots, run)
        for pending in sorted(file.parent.glob("*.ots")):
            if _has_proof(pending):
                run([ots, "upgrade", str(pending)], repo)
        if not stamped:
            status = "stamp_failed"

    git = git or shutil.which("git")
    if not git or not (repo / ".git").exists():
        return PullResult("push_failed" if push else status, seq, stamped)

    receipts = sorted(stored.values())
    proofs = [receipt.with_suffix(".json.ots") for receipt in receipts]
    managed = receipts + [proof for proof in proofs if _has_proof(proof)]
    commit = _commit(repo, seq, managed, git, run)
    if commit in ("stage_failed", "commit_failed"):
        return PullResult(commit, seq, stamped)
    pushed = push and run([git, "push", "-q"], repo) == 0
    if push and not pushed:
        status = "push_failed"
    return PullResult(status, seq, stamped, commit == "committed", pushed)


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

    repo = repo.absolute()
    directory = repo / DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    stored = _stored(directory)
    went_back = seq < max(stored, default=seq)
    file = stored.get(seq, directory / f"{seq:012d}.json")
    if seq in stored or not _store(file, data):
        if not _regular_file(file):
            return PullResult("conflict", seq)
        saved_data = file.read_bytes()
        if saved_data != data:
            try:
                saved = entry_mod.check_checkpoint(json.loads(saved_data), public_key_hex)
            except (ValueError, RecursionError):
                return PullResult("conflict", seq)
            if saved["seq"] != seq or saved["head_hash"] != checkpoint["head_hash"]:
                return PullResult("conflict", seq)
        status = "unchanged"
    else:
        status = "stored"
    if went_back:
        return PullResult("went_back", seq)
    stored[seq] = file
    return _publish(status, seq, file, stored, repo, ots=ots, push=push, run=run, git=git)
