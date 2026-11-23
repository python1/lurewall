# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only summaries of verified records. A relay is evidence of path reuse."""

from __future__ import annotations

import html
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from lurewall import sigconfig, verify
from lurewall.entry import Entry


def window_ms(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]{0,5})([mhd])", value)
    if not match:
        raise ValueError("window must be a positive duration such as 10m, 24h or 7d")
    return int(match[1]) * {"m": 60_000, "h": 3_600_000, "d": 86_400_000}[match[2]]


def _source(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None
    if network.version == 4 and value == str(network.network_address):
        return value
    if network.version == 6 and network.prefixlen == 64 and value == network.compressed:
        return value
    return None


@dataclass(frozen=True)
class PossibleSwitch:
    issuer: str
    requester: str
    seq: int
    ts: int
    timed_issuance: bool

    def description(self) -> str:
        evidence = "The signed record identifies the issuer and requester."
        if not self.timed_issuance:
            evidence += " The legacy record does not establish issuance age."
        return (
            f"Possible IP switch {self.issuer} → {self.requester}. A path issued to the first "
            f"source was used by the second. Signed canary_relayed #{self.seq} "
            f"at {format_time(self.ts)}. {evidence} "
            "A shared URL, cache or crawler can produce the same evidence."
        )


def possible_switch(item: Entry) -> PossibleSwitch | None:
    # Rollups omit issued_to and can merge different issuers on older installations.
    if item.type != "canary_relayed" or item.detail.get("stale"):
        return None
    issuer = _source(item.detail.get("issued_to"))
    requester = _source(item.source)
    if not issuer or not requester or issuer == requester:
        return None
    timed = all(type(item.detail.get(key)) is int for key in ("issued_at_ms", "expires_at_ms"))
    return PossibleSwitch(issuer, requester, item.seq, item.ts, timed)


def probe_rules(config: sigconfig.SignalConfig | None) -> set[str]:
    # Only print site-configured rule labels. Unknown/retired rules have one generic label.
    if config is None:
        return {"*/.env", "*/.git", "*/.svn"}  # shipped operator defaults
    return {
        *config.exact,
        *config.tree,
        *(f"*/{segment}" for segment in config.segment),
        *(f"*{suffix}" for suffix in config.suffix),
    }


def format_time(ms: int) -> str:
    try:
        return datetime.fromtimestamp(ms / 1_000, UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return "unknown time"


def quantity(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


@dataclass
class Summary:
    start: int
    end: int
    rules: set[str]
    records: int = 0
    bait_sources: set[str] = field(default_factory=set)
    would_block: int = 0
    blocks: int = 0
    research: int = 0
    probes: Counter[str] = field(default_factory=Counter)
    switches: dict[tuple[str, str], PossibleSwitch] = field(default_factory=dict)
    identities: Counter[tuple[str, str, str]] = field(default_factory=Counter)
    incomplete: bool = False

    def visit(self, item: Entry) -> None:
        detail = item.detail
        kind = item.type
        count = 1
        key = detail.get("signal")
        if kind == "rollup":
            first, last = detail.get("first_ts"), detail.get("last_ts")
            count = detail.get("count")
            if any(type(n) is not int for n in (first, last, count)) or count < 1:
                return
            if last < self.start or first > self.end:
                return
            if first < self.start or last > self.end:
                self.incomplete = True  # exact timestamps of individual repeats are unavailable
                return
            kind, key = detail.get("of"), detail.get("key")
        elif not self.start <= item.ts <= self.end:
            return
        self.records += 1
        if detail.get("oversize") is True:
            self.incomplete = True
            return
        if kind == "agent_identity":
            parts = (
                key.split("|")
                if item.type == "rollup" and isinstance(key, str)
                else [detail.get(k) for k in ("verdict", "claim", "reason")]
            )
            if len(parts) == 3 and all(isinstance(part, str) for part in parts):
                self.identities[tuple(parts)] += count
        elif kind == "canary_hit":
            source = _source(item.source)
            if (
                key == "research"
                or detail.get("canary") == "security_txt.quiet"
                or (item.type == "rollup" and key == "security_txt.quiet")
            ):
                self.research += count
            elif source and detail.get("counted") is True:
                self.bait_sources.add(source)
            elif item.type == "rollup" and source not in self.bait_sources:
                # These legacy rows do not say whether a hit qualified or was stale.
                self.incomplete = True
        elif kind == "would_block":
            self.would_block += count
        elif kind == "block_applied" or (kind == "block" and detail.get("applied") is True):
            self.blocks += count
        elif kind == "attack_signal" and isinstance(key, str) and key.startswith("path:"):
            rule = key.removeprefix("path:")
            self.probes[rule if rule in self.rules else "Other path rules"] += count
        elif kind == "canary_relayed":
            switch = possible_switch(item)
            if switch:
                self.switches[switch.issuer, switch.requester] = switch
            elif item.type == "rollup":
                self.incomplete = True
        elif kind in ("writer_stopped", "writer_resumed"):
            self.incomplete = True

    def sections(self, verified: verify.Report) -> list[tuple[str, list[str]]]:
        coverage = [f"{format_time(self.start)} to {format_time(self.end)}."]
        if verified.last_matched_anchor_seq is None:
            coverage.append("Signatures and chain verified. No independent checkpoint supplied.")
        else:
            coverage.append(
                f"Signatures and chain verified. Matched checkpoint "
                f"#{verified.last_matched_anchor_seq}."
            )
        if not self.records:
            coverage.append(
                "No signed events in this window. Run lurewall doctor to check ingestion."
            )
        if self.incomplete:
            coverage.append(
                "Some events could not be attributed within this window. Counts are lower bounds."
            )
        activity = [
            f"{quantity(len(self.bait_sources), 'distinct source')} took bait "
            "(counted hits, IPv6 grouped by /64).",
            f"{quantity(self.would_block, 'would-block decision')}. "
            f"{quantity(self.blocks, 'block')} successfully applied.",
            f"{quantity(self.research, 'research-only hit')}.",
        ]
        links = [
            f"{quantity(len(self.switches), 'candidate source pair')}. "
            "Identity is unconfirmed. Links have no enforcement effect."
        ]
        # One direct observation per pair, most recent first. All counts above cover the window.
        recent = sorted(self.switches.values(), key=lambda switch: switch.seq, reverse=True)
        links.extend(switch.description() for switch in recent[:20])
        if len(recent) > 20:
            links.append("Showing the 20 most recent pairs. Narrow the window for more detail.")
        probes = [f"{label} — {count}" for label, count in self.probes.most_common(10)]
        return [
            ("Evidence window", coverage),
            ("Activity", activity),
            *(
                (
                    heading,
                    [
                        f"{claim} ({reason}) — {count}"
                        for (status, claim, reason), count in self.identities.most_common()
                        if status == wanted
                    ]
                    or ["None recorded."],
                )
                for wanted, heading in (
                    ("verified", "Verified agents"),
                    ("impersonation", "Impersonation attempts"),
                    ("indeterminate", "Indeterminate claims"),
                )
            ),
            ("Possible IP switches", links),
            ("Top probed paths (matched rules)", probes or ["No path-rule matches recorded."]),
        ]


def render(summary: Summary, verified: verify.Report, *, as_html: bool) -> str:
    if not verified.ok:
        raise ValueError("signed history could not be verified")
    sections = summary.sections(verified)
    if not as_html:
        return "\n\n".join(
            ["Lurewall report", *("\n".join([name, *lines]) for name, lines in sections)]
        )
    blocks = []
    for name, lines in sections:
        items = "".join(f"<li>{html.escape(line)}</li>" for line in lines)
        blocks.append(f"<section><h2>{html.escape(name)}</h2><ul>{items}</ul></section>")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Lurewall report</title><style>"
        "body{font:1rem/1.5 system-ui,sans-serif;max-width:58rem;margin:3rem auto;"
        "padding:0 1rem;color:#192735}h2{border-top:1px solid #9aa7b0;padding-top:1rem}"
        "li{margin:.4rem 0}ul{padding-left:1.3rem}</style></head><body><main>"
        "<h1>Lurewall report</h1>" + "".join(blocks) + "</main></body></html>"
    )
