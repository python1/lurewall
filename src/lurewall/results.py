# SPDX-License-Identifier: AGPL-3.0-only
"""Lab results: verify the signed log, join it with the run ledger, export.

Nothing is exported from a log that does not verify, unless the caller says
so, and then every output is marked UNVERIFIED on its first line.

Every string that reaches an output passes through ``safe_text`` first. Log
details and ledger notes may hold text that came from outside (a client's
request, a note typed after a run), so the export treats all of it as
hostile: control and non-ASCII characters are shown as escapes, length is
capped, and each format's own special characters are neutralised (Markdown
punctuation; a leading ``= + - @`` that a spreadsheet would run as a formula).
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from lurewall import entry as entry_mod
from lurewall.canaries import AI, V1_IMPERATIVE, V2_QUIET
from lurewall.entry import Entry, EntryError
from lurewall.labcases import CASES
from lurewall.sources import source_key
from lurewall.verify import Report, verify_log

MAX_TEXT_CHARS = 200
EARLY_MS = 2_000  # clock skew between the client and the lab
DEFAULT_GRACE_MS = 2 * 60_000  # roll-up window plus reader lag
LONG_GRACE_MS = 20 * 60_000  # cases that end with a block expiring
LONG_GRACE_CASES = frozenset({2, 7, 11, 14, 18, 20})
ACTS = ("block", "would_block")

PASS, FAIL, RECORD, LIMIT = "pass", "fail", "record", "known limit"


# -- escaping -----------------------------------------------------------------------------


def safe_text(value: object) -> str:
    """Printable ASCII only, capped. Anything else is shown as an escape."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    out = []
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif 32 <= code < 127:
            out.append(char)
        elif code < 256:
            out.append(f"\\x{code:02x}")
        elif code < 65536:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\U{code:08x}")
    joined = "".join(out)
    return joined if len(joined) <= MAX_TEXT_CHARS else joined[: MAX_TEXT_CHARS - 3] + "..."


_MD_SPECIAL = set("\\`*_{}[]<>()#+-.!|~&")


def md(value: object) -> str:
    return "".join("\\" + c if c in _MD_SPECIAL else c for c in safe_text(value))


def csv_cell(value: object) -> str:
    text = safe_text(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


# -- reading the log ------------------------------------------------------------------------


def read_entries(log: Path, public_key_hex: str, limit: int) -> list[Entry]:
    """The first ``limit`` entries, each checked again on its own."""
    entries = []
    with open(log, "rb") as handle:
        for line in handle:
            if len(entries) >= limit:
                break
            try:
                entries.append(entry_mod.check_entry_line(line.rstrip(b"\n"), public_key_hex))
            except EntryError:
                break
    return entries


@dataclass
class RunResult:
    run: dict
    counts: Counter = field(default_factory=Counter)
    outcomes: Counter = field(default_factory=Counter)
    canaries: Counter = field(default_factory=Counter)  # (placement, lure) -> hits
    families: Counter = field(default_factory=Counter)  # (family, signal) -> hits
    would_reasons: Counter = field(default_factory=Counter)  # why a would_block was not a block
    signal_keys: set = field(default_factory=set)
    counted_hits: int = 0
    dry_run: bool | None = None
    verdict: str = RECORD
    why: str = ""


def _dry_run_at(entries: list[Entry], start: int, end: int) -> bool | None:
    """True only if the service was in dry-run for the whole window, as the log says."""
    state: bool | None = None
    for item in entries:
        if item.type != "service_started":
            continue
        dry = item.detail.get("dry_run")
        if item.ts <= start:
            state = dry is True
        elif item.ts <= end and dry is not True:
            return False
    return state


def _collect(result: RunResult, entries: list[Entry]) -> None:
    run = result.run
    try:
        source = source_key(run["source"])
    except ValueError:
        result.verdict, result.why = FAIL, "ledger source is not an address"
        return
    grace = LONG_GRACE_MS if run["case"] in LONG_GRACE_CASES else DEFAULT_GRACE_MS
    start, end = run["started_ms"] - EARLY_MS, run["ended_ms"] + grace
    for item in entries:
        if item.source != source or not start <= item.ts <= end:
            continue
        kind, weight = item.type, 1
        if kind == "rollup":
            kind = str(item.detail.get("of", "rollup"))
            count = item.detail.get("count")
            weight = count if type(count) is int and count > 0 else 1
            if kind == "canary_hit":
                result.counted_hits += weight  # a roll-up cannot show counted: assume it was
        result.counts[kind] += weight
        if item.type == "would_block":
            result.would_reasons[str(item.detail.get("reason"))] += 1
        if item.type == "decision":
            result.outcomes[str(item.detail.get("outcome"))] += 1
        if item.type == "canary_hit":
            placement = str(item.detail.get("placement"))
            lure = str(item.detail.get("lure"))
            result.canaries[(placement, lure)] += 1
            # A v1 log has neither field: every v1 canary is v1-imperative, signal ai.
            family = str(item.detail.get("family", V1_IMPERATIVE))
            signal = str(item.detail.get("signal", AI))
            result.families[(family, signal)] += 1
            if item.detail.get("counted") is True:
                result.counted_hits += 1
        if item.type == "attack_signal" or (item.type == "rollup" and kind == "attack_signal"):
            key = item.detail.get("signal", item.detail.get("key"))
            result.signal_keys.add(str(key))
    result.dry_run = _dry_run_at(entries, run["started_ms"], run["ended_ms"])


def _judge(result: RunResult) -> None:
    run, t = result.run, result.counts
    case = run["case"]
    acted = t["block"] + t["would_block"]
    enforced = t["block"]

    def verdict(ok: bool, why: str) -> None:
        result.verdict, result.why = (PASS if ok else FAIL), why

    if case == 1:
        verdict(acted == 0, f"{t['canary_hit']} canary hits, {acted} block or would_block")
    elif case in (2, 11):
        if result.dry_run:
            verdict(t["would_block"] >= 1, "dry-run: would_block expected")
        else:
            verdict(
                enforced >= 1 and (case == 11 or t["block_expired"] >= 1),
                f"{enforced} block, {t['block_expired']} block_expired",
            )
    elif case == 3:
        verdict(
            t["attack_signal"] >= 1 and t["canary_hit"] == 0 and acted == 0,
            f"{t['attack_signal']} attack signals, {t['canary_hit']} canary hits, {acted} acted",
        )
    elif case == 4:
        verdict(
            t["canary_hit"] + t["attack_signal"] + acted == 0,
            f"{t['canary_hit']} canary hits, {t['attack_signal']} attack signals",
        )
    elif case == 7:
        allowlisted = result.would_reasons["allowlisted"]
        verdict(
            allowlisted >= 1 and enforced == 0,
            f"{allowlisted} would_block (allowlisted), {enforced} block",
        )
    elif case == 8:
        verdict(
            t["cross_site"] >= 1 and result.counted_hits == 0 and acted == 0,
            f"{t['cross_site']} cross_site, {result.counted_hits} counted hits, {acted} acted",
        )
    elif case == 9:
        verdict(t["canary_hit"] >= 1 and acted == 0, f"{t['canary_hit']} canary hits")
    elif case == 10 and run.get("part") == "hit":
        verdict(
            t["canary_relayed"] >= 1 and result.counted_hits == 0 and acted == 0,
            f"{t['canary_relayed']} relayed",
        )
    elif case == 12 and run.get("part") == "probe":
        result.verdict = LIMIT if acted == 0 else FAIL
        result.why = "not blocked: pages and probes came from different addresses"
    elif case == 14 and run.get("part") == "backlog":
        verdict(acted == 0, f"{acted} block or would_block from the backlog")
    elif case == 15:
        rejected = run.get("statuses", {}).get("429", 0)
        verdict(
            rejected >= 1 and len(result.signal_keys) >= 2,
            f"{rejected} answered 429; {len(result.signal_keys)} distinct signals",
        )
    elif case == 16:
        result.why = (
            f"{t['parse_failure'] + t['parse_failure_rollup']} parse failures for "
            f"{run.get('sent', 0)} requests; compare with the nginx line count (runbook)"
        )
    elif case == 17:
        verdict(
            t["attack_signal"] >= run.get("sent", 0) > 0,
            f"{t['attack_signal']} attack signals for {run.get('sent', 0)} variants",
        )
    elif case == 18:
        verdict(result.outcomes["log_only_range"] >= 1 and acted == 0, "log_only_range")
    elif case == 20:
        if result.dry_run is not True:
            verdict(False, "dry-run was not in force for the whole run")
        else:
            verdict(
                enforced == 0,
                f"dry-run held; {enforced} block, {t['would_block']} would_block, "
                f"{t['canary_hit']} canary hits",
            )
    else:
        result.why = "recorded by hand (see runbook)"


def evaluate(entries: list[Entry], runs: list[dict]) -> list[RunResult]:
    results = []
    for run in runs:
        result = RunResult(run)
        _collect(result, entries)
        if result.verdict != FAIL:
            _judge(result)
        results.append(result)
    return results


# -- writing ----------------------------------------------------------------------------------


COLUMNS = (
    "case",
    "title",
    "run",
    "label",
    "part",
    "source",
    "started_ms",
    "ended_ms",
    "verdict",
    "why",
    "dry_run",
    "canary_hits",
    "attack_signals",
    "would_block",
    "block",
    "note",
)


def _row(result: RunResult) -> list[object]:
    run, t = result.run, result.counts
    case = CASES.get(run["case"])
    return [
        run["case"],
        case.title if case else "unknown case",
        run.get("run", ""),
        run.get("label", ""),
        run.get("part", ""),
        run["source"],
        run["started_ms"],
        run["ended_ms"],
        result.verdict,
        result.why,
        result.dry_run,
        t["canary_hit"],
        t["attack_signal"],
        t["would_block"],
        t["block"],
        run.get("note", ""),
    ]


def hit_rates(results: list[RunResult]) -> list[tuple[str, int, int]]:
    """Agent cases only: runs with at least one canary hit, out of runs, per agent label."""
    runs: Counter = Counter()
    hits: Counter = Counter()
    for result in results:
        case = CASES.get(result.run["case"])
        if case is None or case.kind != "agent" or result.run["case"] == 19:
            continue
        key = f"case {result.run['case']}: {result.run.get('label') or 'unlabelled'}"
        runs[key] += 1
        hits[key] += 1 if result.counts["canary_hit"] else 0
    return [(key, hits[key], runs[key]) for key in sorted(runs)]


def family_hit_rates(results: list[RunResult]) -> list[tuple[str, int, int, int]]:
    """Agent cases only: (agent, runs with a v1 hit, runs with a v2 hit, runs)."""
    runs: Counter = Counter()
    v1: Counter = Counter()
    v2: Counter = Counter()
    for result in results:
        case = CASES.get(result.run["case"])
        if case is None or case.kind != "agent" or result.run["case"] == 19:
            continue
        key = f"case {result.run['case']}: {result.run.get('label') or 'unlabelled'}"
        runs[key] += 1
        families = {family for family, _signal in result.families}
        v1[key] += 1 if V1_IMPERATIVE in families else 0
        v2[key] += 1 if V2_QUIET in families else 0
    return [(key, v1[key], v2[key], runs[key]) for key in sorted(runs)]


def write(results: list[RunResult], report: Report, out: Path, *, verified: bool) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    banner = (
        f"Log verified: {report.entries} entries, {report.anchors_matched} anchored checkpoints "
        "matched."
        if verified
        else "UNVERIFIED: the log did not verify. These results prove nothing."
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["# " + banner])
    writer.writerow(COLUMNS)
    for result in results:
        writer.writerow([csv_cell(cell) for cell in _row(result)])
    csv_path = out / "results.csv"
    csv_path.write_text(buffer.getvalue(), encoding="ascii")

    lines = [("" if verified else "**UNVERIFIED** ") + md(banner), "", "# Lurewall lab results", ""]
    lines += ["| " + " | ".join(COLUMNS[:10]) + " |", "|" + "---|" * 10]
    for result in results:
        lines.append("| " + " | ".join(md(cell) for cell in _row(result)[:10]) + " |")
    lines += ["", "## Canary hits per placement and lure", "", "| placement | lure | hits |"]
    lines.append("|---|---|---|")
    totals: Counter = Counter()
    for result in results:
        totals.update(result.canaries)
    for (placement, lure), count in sorted(totals.items()):
        lines.append(f"| {md(placement)} | {md(lure)} | {count} |")
    lines += ["", "## Agent runs with a canary hit", "", "| agent | runs with a hit | runs |"]
    lines.append("|---|---|---|")
    for key, hit, total in hit_rates(results):
        lines.append(f"| {md(key)} | {hit} | {total} |")
    lines += ["", "## Canary hits per family and signal", "", "| family | signal | hits |"]
    lines.append("|---|---|---|")
    by_family: Counter = Counter()
    for result in results:
        by_family.update(result.families)
    for (family, signal), count in sorted(by_family.items()):
        lines.append(f"| {md(family)} | {md(signal)} | {count} |")
    lines += [
        "",
        "Signal `ai` and `recon` hits count toward a block; `recon` (robots.txt) can also come "
        "from an ordinary scanner. `research` (security.txt) hits are logged and never counted.",
        "",
        "## Agent runs per canary family",
        "",
        "| agent | runs with a v1-imperative hit | runs with a v2-quiet hit | runs |",
        "|---|---|---|---|",
    ]
    for key, v1_runs, v2_runs, total in family_hit_rates(results):
        lines.append(f"| {md(key)} | {v1_runs} | {v2_runs} | {total} |")
    md_path = out / "results.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return [csv_path, md_path]


def export(
    log: Path,
    public_key_hex: str,
    anchors: list[Path],
    runs: list[dict],
    out: Path,
    *,
    allow_unverified: bool = False,
) -> tuple[Report, list[RunResult], list[Path]]:
    report = verify_log(log, public_key_hex, anchors)
    if not report.ok and not allow_unverified:
        return report, [], []
    entries = read_entries(log, public_key_hex, report.entries)
    results = evaluate(entries, runs)
    return report, results, write(results, report, out, verified=report.ok)
