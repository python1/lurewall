# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a signed log: the chain, the signatures and the anchored checkpoints.

What a pass means: every entry is in canonical form, is signed by the given
key, and follows the entry before it; and every anchored checkpoint matches
the entry it names. What it cannot mean: that entries after the last anchor
are original. Whoever holds the signing key can rewrite or remove those, and
no check made from the log alone can tell.

This module checks checkpoint signatures and their agreement with the log. It
does not check OpenTimestamps proofs; that belongs to the anchoring job.

Nothing here prints log content. A bad line is reported by position, a fixed
reason word and its hash, because log text is attacker-controlled.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from lurewall import entry as entry_mod
from lurewall.canonical import ZERO_HASH, sha256_hex
from lurewall.entry import MAX_LINE_BYTES, EntryError

MAX_ANCHOR_FILE_BYTES = 1024 * 1024
MAX_ANCHOR_FILES = 100_000
_ANCHOR_SUFFIXES = frozenset({".json", ".jsonl"})


@dataclass(frozen=True)
class BadEntry:
    line: int  # 1-based line number
    offset: int  # byte offset of the start of the line
    expected_seq: int
    reason: str
    line_sha256: str


@dataclass(frozen=True)
class AnchorProblem:
    reason: str
    seq: int | None = None
    file: str | None = None


@dataclass
class Report:
    entries: int = 0  # entries verified, from the start of the log
    head_hash: str = ZERO_HASH
    bad_entry: BadEntry | None = None
    anchors_given: bool = False
    anchors_valid: int = 0  # distinct checkpoints with a valid signature
    anchors_matched: int = 0
    last_matched_anchor_seq: int | None = None
    highest_anchor_seq: int | None = None
    truncated_missing: int = 0  # entries an anchor proves existed but the log lacks
    anchor_problems: list[AnchorProblem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.bad_entry is None and not self.anchor_problems

    def to_dict(self) -> dict:
        return {"ok": self.ok, **asdict(self)}


def _safe_name(path: Path) -> str:
    return ascii(str(path))[1:-1][:200]


def _anchor_files(paths: list[Path], problems: list[AnchorProblem]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            found = sorted(
                item
                for item in path.rglob("*")
                if item.suffix in _ANCHOR_SUFFIXES
                and ".git" not in item.relative_to(path).parts
                and item.is_file()
            )
            files.extend(found)
        elif path.is_file():
            files.append(path)
        else:
            problems.append(AnchorProblem("anchor_path_missing", file=_safe_name(path)))
    if len(files) > MAX_ANCHOR_FILES:
        problems.append(AnchorProblem("too_many_anchor_files"))
        return []
    return files


def _objects_in(raw: bytes) -> list[object]:
    """One JSON document, or one per line. Raises ValueError if neither."""
    try:
        whole = json.loads(raw)
    except (ValueError, RecursionError):
        objects: list[object] = []
        for line in raw.splitlines():
            if line.strip():
                try:
                    objects.append(json.loads(line))
                except RecursionError as exc:
                    raise ValueError("nested too deeply") from exc
        return objects
    return whole if isinstance(whole, list) else [whole]


def load_anchors(
    paths: list[Path], public_key_hex: str
) -> tuple[dict[int, str], list[AnchorProblem]]:
    """Read checkpoints from files or directories. Returns {seq: head_hash} and problems.

    An anchor that cannot be read, or is not signed by the key, is a problem,
    not something to skip: the anchors are the reference the log is held to.
    """
    problems: list[AnchorProblem] = []
    anchors: dict[int, str] = {}
    for file in _anchor_files(paths, problems):
        name = _safe_name(file)
        try:
            with open(file, "rb") as handle:
                raw = handle.read(MAX_ANCHOR_FILE_BYTES + 1)
        except OSError:
            problems.append(AnchorProblem("anchor_unreadable", file=name))
            continue
        if len(raw) > MAX_ANCHOR_FILE_BYTES:
            problems.append(AnchorProblem("anchor_file_too_large", file=name))
            continue
        try:
            objects = _objects_in(raw)
        except ValueError:
            problems.append(AnchorProblem("anchor_not_json", file=name))
            continue
        for obj in objects:
            try:
                checkpoint = entry_mod.check_checkpoint(obj, public_key_hex)
            except EntryError as exc:
                problems.append(AnchorProblem(f"anchor_{exc.code}", file=name))
                continue
            seq, head = checkpoint["seq"], checkpoint["head_hash"]
            if anchors.setdefault(seq, head) != head:
                # Two validly signed checkpoints disagree about one entry.
                problems.append(AnchorProblem("anchor_conflict", seq=seq, file=name))
    return anchors, problems


def verify_log(
    log_path: str | Path, public_key_hex: str, anchor_paths: list[Path] | None = None
) -> Report:
    report = Report()
    anchors: dict[int, str] = {}
    if anchor_paths:
        report.anchors_given = True
        anchors, report.anchor_problems = load_anchors(list(anchor_paths), public_key_hex)
        report.anchors_valid = len(anchors)
        report.highest_anchor_seq = max(anchors, default=None)

    anchored_hashes: dict[int, str] = {}
    offset = 0
    with open(log_path, "rb") as handle:
        while True:
            raw = handle.readline(MAX_LINE_BYTES + 2)
            if not raw:
                break
            expected = report.entries + 1
            reason = None
            if not raw.endswith(b"\n"):
                reason = "line_too_long" if len(raw) > MAX_LINE_BYTES else "unterminated_line"
            else:
                try:
                    item = entry_mod.check_entry_line(raw[:-1], public_key_hex)
                except EntryError as exc:
                    reason = exc.code
                else:
                    if item.seq != expected:
                        reason = "bad_seq"
                    elif item.prev_hash != report.head_hash:
                        reason = "bad_prev_hash"
            if reason is not None:
                report.bad_entry = BadEntry(
                    line=expected,
                    offset=offset,
                    expected_seq=expected,
                    reason=reason,
                    line_sha256=sha256_hex(raw.rstrip(b"\n")),
                )
                break
            report.entries = expected
            report.head_hash = item.hash
            if expected in anchors:
                anchored_hashes[expected] = item.hash
            offset += len(raw)

    for seq in sorted(anchors):
        if seq in anchored_hashes:
            if anchored_hashes[seq] == anchors[seq]:
                report.anchors_matched += 1
                report.last_matched_anchor_seq = seq
            else:
                report.anchor_problems.append(AnchorProblem("anchor_mismatch", seq=seq))
        elif report.bad_entry is not None:
            report.anchor_problems.append(AnchorProblem("anchor_unchecked", seq=seq))
        else:
            report.anchor_problems.append(AnchorProblem("log_truncated", seq=seq))
            report.truncated_missing = max(report.truncated_missing, seq - report.entries)
    return report


_REASONS = {
    "line_too_long": "the line is longer than any entry can be",
    "unterminated_line": "the last line has no newline (a cut-off write, or a truncated file)",
    "not_canonical_json": "the line is not canonical JSON (edited, or not written by Lurewall)",
    "bad_fields": "the entry's fields are missing, extra or of the wrong type",
    "bad_signature": "the signature does not match the entry under this key",
    "bad_seq": "the sequence number is not the next one (entries removed, added or reordered)",
    "bad_prev_hash": "the entry does not follow the one before it (an earlier line was changed)",
    "anchor_mismatch": "the log's entry differs from the anchored checkpoint: "
    "the log was rewritten at or before it",
    "anchor_unchecked": "the checkpoint could not be compared: the log is invalid before it",
    "log_truncated": "the checkpoint names an entry the log no longer has",
    "anchor_conflict": "two signed checkpoints give different hashes for one entry",
    "anchor_bad_signature": "the checkpoint is not signed by this key",
    "anchor_bad_fields": "the checkpoint's fields are missing, extra or of the wrong type",
    "anchor_not_json": "the file is not JSON",
    "anchor_unreadable": "the file could not be read",
    "anchor_file_too_large": "the file is too large to be a checkpoint",
    "anchor_path_missing": "no such file or directory",
    "too_many_anchor_files": "too many anchor files",
}


def format_report(report: Report) -> str:
    lines = [f"log: {report.entries} entries verified from the start"]
    if report.entries:
        lines.append(f"head: seq {report.entries} hash {report.head_hash}")
    bad = report.bad_entry
    if bad is not None:
        lines.append(
            f"FIRST BAD ENTRY: line {bad.line} (byte offset {bad.offset}), "
            f"expected seq {bad.expected_seq}: {bad.reason}"
        )
        lines.append(f"  {_REASONS.get(bad.reason, bad.reason)}")
        lines.append(f"  sha256 of that line: {bad.line_sha256}")
        lines.append(f"  nothing from line {bad.line} on is verified")

    if not report.anchors_given:
        lines.append(
            "anchors: none given. Without anchored checkpoints, removed entries at the "
            "end of the log, or a log rewritten by the key holder, cannot be detected."
        )
    else:
        lines.append(
            f"anchors: {report.anchors_valid} signed checkpoints, "
            f"{report.anchors_matched} match the log"
        )
        for problem in report.anchor_problems:
            where = f"seq {problem.seq}" if problem.seq is not None else "anchor"
            if problem.file is not None:
                where += f" ({problem.file})"
            lines.append(
                f"ANCHOR PROBLEM: {where}: {problem.reason}: "
                f"{_REASONS.get(problem.reason, problem.reason)}"
            )
        if report.truncated_missing:
            lines.append(
                f"TRUNCATED: the log ends at seq {report.entries}, but an anchored checkpoint "
                f"covers seq {report.highest_anchor_seq}: at least {report.truncated_missing} "
                "entries are missing from the end"
            )
        last = report.last_matched_anchor_seq
        if last is None:
            lines.append("last anchor that matches the log: none. No entry is covered.")
        else:
            lines.append(f"last anchor that matches the log: seq {last}")
            if bad is None and report.entries > last:
                lines.append(
                    f"entries {last + 1} to {report.entries} come after the last anchor: they "
                    "are signed and chained, but the key holder could have rewritten or "
                    "removed entries there without detection"
                )
    lines.append("RESULT: OK" if report.ok else "RESULT: FAIL")
    return "\n".join(lines)
