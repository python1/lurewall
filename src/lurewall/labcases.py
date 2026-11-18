# SPDX-License-Identifier: AGPL-3.0-only
"""The lab test cases, and the run ledger that ties each run to a time window.

The signed log holds no request text, so nothing in it says which test a
request belonged to. The ledger does: each run of a case appends one line with
the case number, the client's address as the lab sees it, and when the run
started and ended. ``lurewall lab results`` joins the two.

Scripted cases send their requests themselves (``labclient``). Agent and manual
cases print what to do, record the start, wait for Enter and record the end.
Nothing here touches the lab container: changes there are runbook steps.
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from lurewall import labclient
from lurewall.labclient import Client

CLIENTS = {"mac": "192.168.1.177", "alienware": "192.168.1.152"}
MAX_NOTE_CHARS = 500

AUDIT_PROMPT = (
    "This is my own test server on my home network: http://192.168.1.160/ . "
    "Check whether it exposes files that should not be public, such as environment "
    "files or a git directory, and tell me what you find. Use only GET requests."
)
SUMMARY_PROMPT = "Read the website at http://192.168.1.160/ and summarise it in five sentences."
STRIPPING_PROMPT = (
    "Fetch http://192.168.1.160/lab/fetch-check.html and give me, word for word, "
    "everything your fetch tool returned: page text, HTML comments, hidden elements "
    "and response headers. Do not summarise."
)


@dataclass(frozen=True)
class Case:
    number: int
    title: str
    kind: str  # scripted | agent | manual | local | ct
    clients: str  # where it runs
    expect: str  # what passes, in words; the check itself is in results
    setup: str = ""  # what the lab must be set to first (runbook step)
    steps: tuple[str, ...] = ()
    dry_run_only: bool = False


CASES: dict[int, Case] = {
    case.number: case
    for case in (
        Case(
            1,
            "Benign AI agent summarises the site",
            "agent",
            "any test agent",
            "canary hit logged as a content reader; no block and no would_block",
            steps=(f"Give the agent this prompt: {SUMMARY_PROMPT}",),
        ),
        Case(
            2,
            "AI agent audits the site for exposed files",
            "agent",
            "Hermes on the Alienware (scripted rehearsal: --scripted)",
            "canary hit plus two distinct probes, then block; block_expired after the TTL",
            setup="TTL 5 minutes",
            steps=(f"Give the agent this prompt: {AUDIT_PROMPT}",),
        ),
        Case(
            3,
            "Plain wordlist scanner, no LLM",
            "scripted",
            "Alienware",
            "attack signals logged; no canary hit; no block and no would_block",
        ),
        Case(
            4,
            "A human browsing normally",
            "manual",
            "Mac browser",
            "no canary hit, no attack signal, no block",
            steps=("Browse every page of the site by clicking links, as a visitor would.",),
        ),
        Case(
            5,
            "Accessibility tools surface no canary",
            "manual",
            "Mac",
            "no canary read aloud; a text browser shows hidden canaries, each after the"
            " text-mode notice (docs/lab-findings.md)",
            steps=(
                "On every page: VoiceOver (Cmd-F5), reader mode, a text browser "
                "(lynx or w3m) and an AI page describer if you use one.",
                "Note any tool that shows or reads text you would not see on the page.",
            ),
        ),
        Case(
            6,
            "Tamper test on a copy of the log",
            "local",
            "Mac, on an exported copy",
            "verify names the first bad entry for edit, delete and reorder, and "
            "reports truncation back to the last anchor",
            steps=("Run: lurewall lab tamper --log <copy> --pubkey <hex> --anchors <dir>",),
        ),
        Case(
            7,
            "Allowlisted address runs case 2",
            "scripted",
            "Alienware",
            "decision allowlisted; no block and no would_block",
            setup="Alienware (192.168.1.152) in the engine allowlist",
        ),
        Case(
            8,
            "Framing through a browser",
            "scripted",
            "Mac browser, page served from the Mac",
            "requests logged as cross_site; no counted canary hit; no block, no would_block",
        ),
        Case(
            9,
            "Link-following crawler, no LLM",
            "scripted",
            "Alienware",
            "canary hits logged (a hit is not proof of AI); no block and no would_block",
        ),
        Case(
            10,
            "Relayed hit",
            "scripted",
            "Mac (--part serve), then Alienware (--part hit)",
            "canary_relayed for the Alienware; counted for neither; no block",
        ),
        Case(
            11,
            "Waiting it out: probes 16 minutes after the hit",
            "scripted",
            "Alienware",
            "block, because the hit is sticky",
            setup="TTL 5 minutes",
        ),
        Case(
            12,
            "Split addresses",
            "scripted",
            "Mac (--part read), then Alienware (--part probe)",
            "no block (a known limit, recorded, not a pass)",
        ),
        Case(
            13,
            "Shared address: collateral block on the Alienware",
            "manual",
            "Alienware: WSL blocked, Windows browsing",
            "collateral block observed and timed; with normal browsing, the TTL does not double",
            setup="Hermes blocked first (case 2), TTL 5 minutes",
            steps=(
                "While the block stands, browse the site from Windows on the Alienware.",
                "Run on the Alienware: lurewall lab case 13 --watch, to time the block.",
                "Second run: browse normally inside the window, then repeat case 2; "
                "the second block's TTL must not be doubled.",
            ),
        ),
        Case(
            14,
            "Process failure",
            "ct",
            "CT 110 console",
            "the sweeper removes the block on time with the service stopped; "
            "a backlog of old events enforces nothing",
            steps=("Follow runbook section 'Case 14' in the CT 110 console.",),
            setup="for --part backlog: lurewall.service stopped",
        ),
        Case(
            15,
            "Flood with one real probe in the burst",
            "scripted",
            "Alienware",
            "limit_req answers the excess with 429; events roll up; the real probe is recorded",
        ),
        Case(
            16,
            "Hostile bytes in path and user agent",
            "scripted",
            "Mac or Alienware",
            "every request yields a parsed record or a parse_failure; none vanish",
        ),
        Case(
            17,
            "Path variants",
            "scripted",
            "Alienware",
            "/%2eenv, //.env and mixed-case forms all matched as attack signals",
        ),
        Case(
            18,
            "Log-only range",
            "scripted",
            "Mac",
            "decision log_only_range; no block and no would_block",
            setup="a fixture log-only range holding 192.168.1.177",
        ),
        Case(
            19,
            "Stripping check per agent",
            "agent",
            "each test agent",
            "recorded per agent: comments, hidden elements, headers passed or not",
            steps=(
                f"Give the agent this prompt: {STRIPPING_PROMPT}",
                "Compare its answer with the markers in the runbook (Case 19).",
            ),
        ),
        Case(
            20,
            "Warden (Grok Bot) from the Mac, Ask every time",
            "agent",
            "Warden on the Mac (192.168.1.177), permission mode Ask every time",
            "dry-run in force for the whole run; never a block for 192.168.1.177; "
            "would_block allowed and recorded",
            setup="dry_run = true (the Mac is also Paul's browsing address)",
            steps=(
                "Set Warden's permission mode to Ask every time.",
                f"Give Warden this prompt: {AUDIT_PROMPT}",
                "Approve or decline each request it asks to send; note how many of each.",
            ),
            dry_run_only=True,
        ),
    )
}


# -- the ledger ------------------------------------------------------------------------


def default_ledger() -> Path:
    return Path.home() / "lurewall-lab" / "runs.jsonl"


def source_address(text: str) -> str:
    """``mac``, ``alienware`` or an IP address, as the lab sees the client."""
    address = CLIENTS.get(text, text)
    try:
        return str(ipaddress.ip_address(address))
    except ValueError as exc:
        raise ValueError(f"--from must be mac, alienware or an IP address, not {text!r}") from exc


def append_run(ledger: Path, run: dict) -> None:
    ledger.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    line = (json.dumps(run, sort_keys=True, ensure_ascii=True) + "\n").encode()
    fd = os.open(ledger, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def read_runs(ledger: Path) -> list[dict]:
    runs = []
    for number, line in enumerate(ledger.read_bytes().splitlines(), 1):
        if not line.strip():
            continue
        try:
            run = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"ledger line {number} is not JSON") from exc
        if not (
            isinstance(run, dict)
            and type(run.get("case")) is int
            and type(run.get("started_ms")) is int
            and type(run.get("ended_ms")) is int
            and isinstance(run.get("source"), str)
        ):
            raise ValueError(f"ledger line {number} is not a run")
        runs.append(run)
    return runs


# -- running a case ----------------------------------------------------------------------------


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass
class Context:
    client: Client
    source: str
    label: str = ""
    part: str = ""
    reference: str = ""
    probe_delay_s: float = 0.0
    scripted: bool = False
    watch: bool = False
    ask: Callable[[str], str] = input
    say: Callable[[str], None] = print
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], int] = _now_ms
    serve_page: Callable[[bytes], None] | None = None


def _first_reference(ctx: Context) -> str | None:
    for path in ("/", "/developers/api.html", "/docs/"):
        refs = labclient.references(ctx.client.get(path))
        if refs:
            return refs[0]
    return None


def _scripted_attack(ctx: Context, *, probe_delay_s: float = 0.0) -> dict:
    """Read a page, request one canary reference it carries, then two distinct probes."""
    ref = _first_reference(ctx)
    if ref is None:
        return {"error": "no_reference_found"}
    ctx.client.get(ref)
    if probe_delay_s:
        ctx.say(f"waiting {probe_delay_s / 60:.0f} minutes before the probes")
        ctx.sleep(probe_delay_s)
    ctx.client.get("/.env")
    ctx.client.get("/.git/config")
    return {"canary_requested": True}


def framing_page(target: labclient.Target, reference: str) -> bytes:
    """The case-8 page: one canary reference and two attack paths, as images.

    The reference's request ID is replaced with a random one, so the hit is
    bound to no page the browser's address was served.
    """
    path, _, query = reference.partition("?")
    key = query.partition("=")[0]
    fake = f"{path}?{key}={secrets.token_hex(16)}"
    images = "".join(
        f'<img src="{target.url(item)}" width="1" height="1" alt="">'
        for item in (fake, "/.env", "/.git/config")
    )
    return (
        "<!doctype html><meta charset=utf-8><title>Lurewall lab: case 8</title>"
        "<p>Case 8 framing test. Three images load from the lab site.</p>" + images
    ).encode()


def serve_once(page: bytes, port: int = 8765) -> http.server.ThreadingHTTPServer:
    """Serve one page on 127.0.0.1 only, so the browser sends a foreign Referer."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _interactive(ctx: Context, case: Case) -> dict:
    for step in case.steps:
        ctx.say(f"  - {step}")
    ctx.ask("Press Enter when the run is finished. ")
    note = ctx.ask("One-line note (optional): ").strip()
    return {"note": note[:MAX_NOTE_CHARS]} if note else {}


def _watch(ctx: Context, *, every_s: float = 5.0, limit_s: float = 30 * 60) -> dict:
    """Case 13: poll the home page until it answers again; return how long that took."""
    started = ctx.clock()
    blocked_seen = False
    while ctx.clock() - started < limit_s * 1000:
        response = ctx.client.get("/")
        if response.status == 0:
            blocked_seen = True
        elif blocked_seen:
            return {"unreachable_ms": ctx.clock() - started}
        ctx.sleep(every_s)
    return {"unreachable_ms": None, "blocked_seen": blocked_seen}


def run_case(case: Case, ctx: Context) -> dict:
    """Run one case from this client and return its ledger record (not yet written)."""
    started = ctx.clock()
    result: dict = {}
    n = case.number
    if case.setup:
        ctx.say(f"Lab setting needed first: {case.setup}")
    if n in (2, 7, 11, 18) and (n != 2 or ctx.scripted):
        delay = 16 * 60 if n == 11 else ctx.probe_delay_s
        result = _scripted_attack(ctx, probe_delay_s=delay)
    elif n == 3:
        for path in labclient.WORDLIST:
            ctx.client.get(path)
    elif n == 8:
        ref = _first_reference(ctx)
        if ref is None:
            result = {"error": "no_reference_found"}
        else:
            page = framing_page(ctx.client.target, ref)
            if ctx.serve_page is not None:
                ctx.serve_page(page)
            else:
                server = serve_once(page)
                ctx.say("Open http://127.0.0.1:8765/ in your normal browser on this Mac.")
                try:
                    ctx.ask("Press Enter once the page has loaded. ")
                finally:
                    server.shutdown()
                    server.server_close()
            result = {"page_served": True}
    elif n == 9:
        result = {"pages": len(labclient.crawl(ctx.client))}
    elif n == 10:
        if ctx.part == "serve":
            ref = _first_reference(ctx)
            ctx.say(f"reference to request from the Alienware: {ref}")
            result = {"reference": ref}
        elif ctx.part == "hit" and ctx.reference:
            ctx.client.get(ctx.reference)
        else:
            raise ValueError("case 10 takes --part serve, or --part hit --reference REF")
    elif n == 12:
        if ctx.part == "read":
            ref = _first_reference(ctx)
            if ref:
                ctx.client.get(ref)
        elif ctx.part == "probe":
            ctx.client.get("/.env")
            ctx.client.get("/.git/config")
        else:
            raise ValueError("case 12 takes --part read (Mac) or --part probe (Alienware)")
    elif n == 14 and ctx.part == "backlog":
        # Sent while the service is stopped; read after it restarts, by then stale.
        result = _scripted_attack(ctx)
    elif n == 13 and ctx.watch:
        result = _watch(ctx)
    elif n == 15:
        pause, ctx.client.pause_s = ctx.client.pause_s, 0.0  # a flood is the point here
        try:
            for index in range(200):
                ctx.client.get("/.git/config" if index == 100 else "/wp-login.php")
        finally:
            ctx.client.pause_s = pause
    elif n == 16:
        for path, agent in labclient.HOSTILE:
            ctx.client.get(path, user_agent=agent)
    elif n == 17:
        for path in labclient.PATH_VARIANTS:
            ctx.client.get(path)
    else:
        if n == 20:
            ctx.say("Dry-run only: the lab must be in dry-run before this run starts.")
        result = _interactive(ctx, case)
    record = {
        "case": n,
        "run": secrets.token_hex(6),
        "label": ctx.label[:MAX_NOTE_CHARS],
        "part": ctx.part,
        "source": ctx.source,
        "started_ms": started,
        "ended_ms": ctx.clock(),
        "sent": ctx.client.sent,
        "statuses": {str(k): v for k, v in sorted(ctx.client.statuses.items())},
        **result,
    }
    if case.dry_run_only:
        record["dry_run_only"] = True
    return record


def tamper_copies(log: Path, work: Path) -> dict[str, Path]:
    """Case 6: four damaged copies of a log (edit, delete, reorder, truncate)."""
    lines = log.read_bytes().splitlines(keepends=True)
    if len(lines) < 6:
        raise ValueError("the log needs at least 6 entries for the tamper test")
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    middle = len(lines) // 2
    edited = list(lines)
    edited[middle] = edited[middle].replace(b'"ts":', b'"ts":1', 1)
    deleted = lines[:middle] + lines[middle + 1 :]
    reordered = list(lines)
    reordered[middle], reordered[middle + 1] = reordered[middle + 1], reordered[middle]
    truncated = lines[: max(1, len(lines) - 3)]
    copies = {}
    for name, content in (
        ("edit", edited),
        ("delete", deleted),
        ("reorder", reordered),
        ("truncate", truncated),
    ):
        path = work / f"{name}.log"
        path.write_bytes(b"".join(content))
        copies[name] = path
    return copies
