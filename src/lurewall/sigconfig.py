# SPDX-License-Identifier: AGPL-3.0-only
"""The per-site signals config: what counts as an attack on this site.

The file is plain TOML so a reviewer can read exactly what counts. It is set
per site, and it is checked against the site before it is used:

- no decoy path may match an attack-path rule, in any spelling, and the
  request a canary plants must produce no attack signal at all;
- no path the site really serves may match an attack-path rule.

``check_against_site`` enforces both, and a classifier cannot be built without
passing it. The config holds no secrets and nothing about any visitor.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_RULES = 2000

INJECTION_FAMILIES = ("sqli", "traversal", "xss", "jndi", "command", "file")

# Verbs that can be listed as abuse. GET, HEAD, POST and OPTIONS are what
# browsers send on their own, so they can never be configured as an attack.
_BROWSER_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})

# The block threshold is two distinct attack signals. Config may raise it; it
# can never lower it, so no file can make one signal, or speed, enough.
MIN_DISTINCT_ATTACK_SIGNALS = 2

_PATH_RE = re.compile(r"(?:/[a-z0-9._~-]{1,64}){1,8}", re.ASCII)
_SEGMENT_RE = re.compile(r"[a-z0-9._~-]{1,64}", re.ASCII)
_HOST_RE = re.compile(r"[a-z0-9]([a-z0-9.:-]{0,251}[a-z0-9])?", re.ASCII)
_METHOD_RE = re.compile(r"[A-Z]{3,16}", re.ASCII)
_PREFIX_RE = re.compile(r"/(?:[a-z0-9._~-]{1,64}/){1,8}", re.ASCII)
_EXTENSION_RE = re.compile(r"[a-z0-9]{1,8}", re.ASCII)
# "~", ".swp", ".old": short, and never a whole path or a dot alone.
_SUFFIX_RE = re.compile(r"~|\.[a-z0-9]{1,8}~?", re.ASCII)


class SignalConfigError(ValueError):
    """The signals config is malformed, or does not fit the site."""


@dataclass(frozen=True)
class SignalConfig:
    hosts: frozenset[str]  # names and addresses the site is reached by
    # Browsers send Sec-Fetch-Site only to secure origins. On a plain-HTTP site
    # a real browser never sends it, so the header is ignored there.
    https: bool
    asset_prefixes: tuple[str, ...]
    asset_extensions: frozenset[str]
    exact: frozenset[str]  # the normalized path equals this
    tree: tuple[str, ...]  # the path is this, or sits under it
    segment: frozenset[str]  # any one path segment equals this
    suffix: tuple[str, ...]  # the last segment ends with this (editor and backup leftovers)
    injection_families: frozenset[str]
    abuse_methods: frozenset[str]
    window_ms: int
    distinct_attack_signals: int
    max_sources: int


def _table(parent: dict, name: str, allowed: set[str]) -> dict:
    value = parent.get(name, {})
    if type(value) is not dict:
        raise SignalConfigError(f"[{name}] must be a table")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SignalConfigError(f"[{name}] has unknown keys: {', '.join(unknown)}")
    return value


def _strings(table: dict, where: str, key: str, pattern: re.Pattern[str]) -> list[str]:
    value = table.get(key, [])
    if type(value) is not list or any(type(item) is not str for item in value):
        raise SignalConfigError(f"{where}.{key} must be a list of strings")
    if len(value) > MAX_RULES:
        raise SignalConfigError(f"{where}.{key} has more than {MAX_RULES} entries")
    for item in value:
        if pattern.fullmatch(item) is None:
            raise SignalConfigError(f"{where}.{key}: {item!r} is not in the allowed form")
    if len(set(value)) != len(value):
        raise SignalConfigError(f"{where}.{key} lists an entry twice")
    return value


def _integer(table: dict, where: str, key: str, default: int, low: int, high: int) -> int:
    value = table.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise SignalConfigError(f"{where}.{key} must be a whole number from {low} to {high}")
    return value


def _path_rules(table: dict, key: str) -> list[str]:
    rules = _strings(table, "attack_paths", key, _PATH_RE)
    for rule in rules:
        if any(segment in (".", "..") for segment in rule.split("/")):
            raise SignalConfigError(f"attack_paths.{key}: {rule!r} holds a dot segment")
    return rules


def parse(raw: bytes | str) -> SignalConfig:
    """Parse and validate config text. Raises SignalConfigError."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_CONFIG_BYTES:
            raise SignalConfigError("signals config is too large")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SignalConfigError("signals config is not UTF-8") from exc
    try:
        doc = tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise SignalConfigError(f"signals config is not valid TOML: {exc}") from exc

    top = {"version", "site", "attack_paths", "injection", "methods", "thresholds"}
    unknown = sorted(set(doc) - top)
    if unknown:
        raise SignalConfigError(f"unknown top-level keys: {', '.join(unknown)}")
    if type(doc.get("version")) is not int or doc["version"] != CONFIG_VERSION:
        raise SignalConfigError(f"version must be {CONFIG_VERSION}")

    site = _table(doc, "site", {"hosts", "https", "asset_prefixes", "asset_extensions"})
    https = site.get("https", True)
    if type(https) is not bool:
        raise SignalConfigError("site.https must be true or false")
    hosts = _strings(site, "site", "hosts", _HOST_RE)
    if not hosts:
        raise SignalConfigError(
            "site.hosts is empty: without the site's own names, a Referer from "
            "another host cannot be told apart"
        )

    paths = _table(doc, "attack_paths", {"exact", "tree", "segment", "suffix"})
    exact = _path_rules(paths, "exact")
    tree = _path_rules(paths, "tree")
    segment = _strings(paths, "attack_paths", "segment", _SEGMENT_RE)
    suffix = _strings(paths, "attack_paths", "suffix", _SUFFIX_RE)
    if any(item in (".", "..") for item in segment):
        raise SignalConfigError("attack_paths.segment may not hold a dot segment")

    injection = _table(doc, "injection", {"families"})
    families = injection.get("families", list(INJECTION_FAMILIES))
    if type(families) is not list or any(item not in INJECTION_FAMILIES for item in families):
        raise SignalConfigError(
            f"injection.families must be a list drawn from: {', '.join(INJECTION_FAMILIES)}"
        )

    methods = _table(doc, "methods", {"abuse"})
    abuse = _strings(methods, "methods", "abuse", _METHOD_RE)
    browser = sorted(_BROWSER_METHODS.intersection(abuse))
    if browser:
        raise SignalConfigError(
            f"methods.abuse may not list {', '.join(browser)}: browsers send those themselves"
        )

    limits = _table(doc, "thresholds", {"window_minutes", "distinct_attack_signals", "max_sources"})
    return SignalConfig(
        hosts=frozenset(hosts),
        https=https,
        asset_prefixes=tuple(_strings(site, "site", "asset_prefixes", _PREFIX_RE)),
        asset_extensions=frozenset(_strings(site, "site", "asset_extensions", _EXTENSION_RE)),
        exact=frozenset(exact),
        tree=tuple(sorted(tree)),
        segment=frozenset(segment),
        suffix=tuple(sorted(suffix)),
        injection_families=frozenset(families),
        abuse_methods=frozenset(abuse),
        window_ms=_integer(limits, "thresholds", "window_minutes", 15, 1, 24 * 60) * 60_000,
        distinct_attack_signals=_integer(
            limits,
            "thresholds",
            "distinct_attack_signals",
            MIN_DISTINCT_ATTACK_SIGNALS,
            MIN_DISTINCT_ATTACK_SIGNALS,
            16,
        ),
        max_sources=_integer(limits, "thresholds", "max_sources", 10_000, 1, 1_000_000),
    )


def load(path: str | Path) -> SignalConfig:
    path = Path(path)
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise SignalConfigError(f"cannot read signals config {path}: {exc.strerror}") from exc
    return parse(raw)


def check_against_site(config: SignalConfig, canary_set, real_paths: Iterable[str]) -> None:
    """Fail unless the config fits this site and this installation's canaries.

    A decoy must never count as an attack path, and neither may a path the
    site really serves. Every spelling the matcher looks at is tried: the path
    as planted, its lowercase form, and its percent-encoded and doubled-slash
    variants. The request a canary plants must also produce no attack signal
    of any kind.
    """
    # Imported here: signals builds on this module.
    from lurewall import signals
    from lurewall.canaries import collision_key

    problems: list[str] = []
    for canary in canary_set.canaries:
        for spelling in _spellings(canary.path):
            rules = signals.match_attack_paths(config, spelling)
            if rules:
                problems.append(f"decoy {canary.id} matches attack path rule {rules[0]}")
                break
        planted = canary.reference("0" * 32)
        found = signals.attack_signals_for(config, "GET", planted, decoy=False)
        if found:
            problems.append(f"the request planted by {canary.id} would raise {found[0].key}")
        decoy = collision_key(canary.path)
        for rule in sorted(config.exact.union(config.tree)):
            if rule == decoy or rule.startswith(decoy + "/"):
                problems.append(f"attack path rule {rule} sits on decoy {canary.id}")
        for spelling in _quiet_spellings(canary):
            rules = signals.match_attack_paths(config, spelling)
            if rules:
                problems.append(f"decoy {canary.id} matches attack path rule {rules[0]}")
                break
    for route in sorted(set(real_paths)):
        if collision_key(route) == "/":
            continue
        for spelling in (route, collision_key(route), _encoded(route).replace("%", "%25")):
            rules = signals.match_attack_paths(config, spelling)
            if rules:
                problems.append(f"real site path {route} matches attack path rule {rules[0]}")
                break
    if problems:
        raise SignalConfigError(
            "signals config does not fit the site: " + "; ".join(dict.fromkeys(problems))
        )


def _quiet_spellings(canary) -> list[str]:
    """A quiet decoy also counts without its trailing slash and in upper case."""
    if not canary.quiet:
        return []
    bare = canary.path.rstrip("/")
    return [bare, bare.upper(), canary.path.upper()]


def _encoded(path: str) -> str:
    return "".join(char if char == "/" else f"%{ord(char):02x}" for char in path)


def _spellings(path: str) -> list[str]:
    once = _encoded(path)
    twice = once.replace("%", "%25")
    return [path, path.lower(), path.upper(), once, twice, path.replace("/", "//"), path + "/"]
