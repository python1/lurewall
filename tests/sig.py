# SPDX-License-Identifier: AGPL-3.0-only
"""Helpers for the signal tests. Addresses are from the documentation ranges."""

from __future__ import annotations

import random
from dataclasses import replace
from pathlib import Path

import nginx_emu
from lurewall import accesslog, canaries, labsite, sigconfig
from lurewall.signals import Classifier

REPO = Path(__file__).resolve().parents[1]
LAB_CONFIG = REPO / "deploy" / "signals" / "lab-site.toml"
NOW = nginx_emu.NOW_MS
HOST = "lab.lurewall.test"
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"


def shipped_config() -> sigconfig.SignalConfig:
    """The lab config exactly as shipped: plain HTTP, reached by address."""
    return sigconfig.load(LAB_CONFIG)


def lab_config() -> sigconfig.SignalConfig:
    """The shipped rules on an HTTPS site with a name, where fetch metadata applies."""
    return replace(shipped_config(), https=True, hosts=frozenset({HOST}))


def canary_set(seed: int = 1):
    return canaries.generate(labsite.site_routes(), rng=random.Random(seed), now_ms=1)


def classifier(seed: int = 1, *, shipped: bool = False) -> Classifier:
    config = shipped_config() if shipped else lab_config()
    canary_set_ = canary_set(seed)
    return Classifier(
        config, canary_set_, labsite.site_routes(), labsite.quiet_carriers(canary_set_)
    )


def rec(
    uri: str | bytes = "/",
    *,
    ip: str = "192.0.2.10",
    method: str = "GET",
    status: int = 200,
    ua: str | bytes = BROWSER_UA,
    lang: str = "en-GB",
    referer: str | bytes = "",
    sfs: str = "",
    ts_ms: int = NOW,
    now_ms: int | None = None,
) -> accesslog.Record:
    """A record that went through the real line builder and the real parser."""

    def raw(value: str | bytes) -> bytes:
        return value if isinstance(value, bytes) else value.encode("utf-8", "surrogatepass")

    line = nginx_emu.line(
        ts_ms=ts_ms,
        ip=ip,
        method=raw(method),
        uri=raw(uri),
        status=status,
        ua=raw(ua),
        lang=raw(lang),
        referer=raw(referer),
        sec_fetch_site=raw(sfs),
    )
    parsed = accesslog.parse_line(
        line.rstrip(b"\n"), 0, now_ms=NOW if now_ms is None else now_ms, max_age_ms=300_000
    )
    assert isinstance(parsed, accesslog.Record), parsed
    return parsed


def keys(signals) -> list[str]:
    return sorted(signal.key for signal in signals)


class ListSink:
    """Collects events the way the signed log would be asked to write them."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str | None, dict, str | None]] = []

    def append(self, type, source=None, detail=None, *, rollup_key=None):
        self.events.append((type, source, detail or {}, rollup_key))

    def of(self, type: str) -> list[tuple[str, str | None, dict, str | None]]:
        return [event for event in self.events if event[0] == type]
