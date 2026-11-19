# SPDX-License-Identifier: AGPL-3.0-only
"""The decision engine's config: thresholds, TTLs, the allowlist, log-only ranges.

Plain TOML with a closed schema. Dry-run is on unless the file says
``dry_run = false`` in so many words.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_RANGES = 20_000
MAX_TRUSTED_PROXIES = 64
MAX_TCP_PORTS = 64

ADAPTERS = ("log-only", "nftables")
_NFT_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._-]{1,64}){1,8}", re.ASCII)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class EngineConfigError(ValueError):
    """The engine config is malformed."""


@dataclass(frozen=True)
class EngineConfig:
    dry_run: bool = True
    sticky_ms: int = 7 * 24 * 3_600_000
    id_ttl_ms: int = 24 * 3_600_000
    ttl_ms: int = 24 * 3_600_000
    max_ttl_ms: int = 7 * 24 * 3_600_000
    cap: int = 1000
    allowlist: tuple[Network, ...] = ()
    log_only: tuple[Network, ...] = ()
    max_hit_sources: int = 10_000
    max_issued_ids: int = 100_000
    max_ids_per_source: int = 256
    # What enforces a block once dry-run is off. "log-only" blocks nothing.
    adapter: str = "log-only"
    nft_path: str = "/usr/sbin/nft"
    tcp_ports: tuple[int, ...] = ()
    trusted_proxies: tuple[Network, ...] = ()

    @property
    def enforcing(self) -> bool:
        return not self.dry_run and self.adapter == "nftables"

    def __post_init__(self) -> None:
        # Held here as well as in the parser, so a config built in code is
        # held to the same rules as one read from a file.
        if type(self.dry_run) is not bool:
            raise EngineConfigError("dry_run must be true or false")
        for name in (
            "sticky_ms",
            "id_ttl_ms",
            "ttl_ms",
            "max_ttl_ms",
            "cap",
            "max_hit_sources",
            "max_issued_ids",
            "max_ids_per_source",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise EngineConfigError(f"{name} must be a positive whole number")
        if self.adapter not in ADAPTERS:
            raise EngineConfigError(f"adapter must be one of: {', '.join(ADAPTERS)}")
        if type(self.nft_path) is not str or _NFT_PATH_RE.fullmatch(self.nft_path) is None:
            raise EngineConfigError("nft_path must be an absolute path to the nft binary")
        if self.max_ttl_ms < self.ttl_ms:
            raise EngineConfigError("the longest TTL cannot be shorter than the first TTL")
        if (
            type(self.tcp_ports) is not tuple
            or len(self.tcp_ports) > MAX_TCP_PORTS
            or any(type(port) is not int or not 1 <= port <= 65535 for port in self.tcp_ports)
            or len(self.tcp_ports) != len(set(self.tcp_ports))
        ):
            raise EngineConfigError(
                f"enforcement.tcp_ports must contain at most {MAX_TCP_PORTS} distinct "
                "whole-number TCP ports from 1 to 65535"
            )
        if (
            type(self.trusted_proxies) is not tuple
            or len(self.trusted_proxies) > MAX_TRUSTED_PROXIES
            or any(
                not isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                or network.network_address.is_unspecified
                or network.network_address.is_multicast
                or (
                    isinstance(network.network_address, ipaddress.IPv6Address)
                    and network.network_address.ipv4_mapped is not None
                )
                for network in self.trusted_proxies
            )
            or len(self.trusted_proxies) != len(set(self.trusted_proxies))
        ):
            raise EngineConfigError(
                f"sources.trusted_proxies must contain at most {MAX_TRUSTED_PROXIES} "
                "distinct explicit proxy addresses or CIDR ranges without default, "
                "unspecified, multicast, or IPv4-mapped ranges"
            )
        if self.trusted_proxies and self.enforcing:
            raise EngineConfigError(
                "trusted proxies require dry-run or the log-only adapter because local "
                "nftables cannot block a client behind a terminating proxy"
            )


def _table(parent: dict, name: str, allowed: set[str]) -> dict:
    value = parent.get(name, {})
    if type(value) is not dict:
        raise EngineConfigError(f"[{name}] must be a table")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise EngineConfigError(f"[{name}] has unknown keys: {', '.join(unknown)}")
    return value


def _integer(table: dict, where: str, key: str, default: int, low: int, high: int) -> int:
    value = table.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise EngineConfigError(f"{where}.{key} must be a whole number from {low} to {high}")
    return value


def parse_networks(values: object, where: str) -> tuple[Network, ...]:
    if type(values) is not list or any(type(item) is not str for item in values):
        raise EngineConfigError(f"{where} must be a list of addresses or CIDR ranges")
    if len(values) > MAX_RANGES:
        raise EngineConfigError(f"{where} has more than {MAX_RANGES} entries")
    found = []
    for item in values:
        try:
            found.append(ipaddress.ip_network(item, strict=True))
        except ValueError as exc:
            raise EngineConfigError(f"{where}: {item!r} is not an address or CIDR range") from exc
    return tuple(found)


def parse(raw: bytes | str) -> EngineConfig:
    if isinstance(raw, bytes):
        if len(raw) > MAX_CONFIG_BYTES:
            raise EngineConfigError("engine config is too large")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EngineConfigError("engine config is not UTF-8") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise EngineConfigError("engine config is too large")
    try:
        doc = tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise EngineConfigError(f"engine config is not valid TOML: {exc}") from exc
    unknown = sorted(
        set(doc) - {"version", "dry_run", "canary", "block", "sources", "limits", "enforcement"}
    )
    if unknown:
        raise EngineConfigError(f"unknown top-level keys: {', '.join(unknown)}")
    if type(doc.get("version")) is not int or doc["version"] != CONFIG_VERSION:
        raise EngineConfigError(f"version must be {CONFIG_VERSION}")
    dry_run = doc.get("dry_run", True)
    if type(dry_run) is not bool:
        raise EngineConfigError("dry_run must be true or false")

    canary = _table(doc, "canary", {"sticky_days", "id_ttl_hours"})
    block = _table(doc, "block", {"ttl_minutes", "max_ttl_minutes", "cap"})
    sources = _table(doc, "sources", {"allowlist", "log_only_ranges", "trusted_proxies"})
    limits = _table(doc, "limits", {"max_hit_sources", "max_issued_ids", "max_ids_per_source"})
    enforcement = _table(doc, "enforcement", {"adapter", "nft_path", "tcp_ports"})
    ports = enforcement.get("tcp_ports", [])
    if type(ports) is not list:
        raise EngineConfigError("enforcement.tcp_ports must be a list of TCP ports")
    week = 7 * 24 * 60
    return EngineConfig(
        dry_run=dry_run,
        sticky_ms=_integer(canary, "canary", "sticky_days", 7, 1, 90) * 24 * 3_600_000,
        id_ttl_ms=_integer(canary, "canary", "id_ttl_hours", 24, 1, 24 * 90) * 3_600_000,
        ttl_ms=_integer(block, "block", "ttl_minutes", 24 * 60, 1, week) * 60_000,
        max_ttl_ms=_integer(block, "block", "max_ttl_minutes", week, 1, 4 * week) * 60_000,
        cap=_integer(block, "block", "cap", 1000, 1, 10_000),
        allowlist=parse_networks(sources.get("allowlist", []), "sources.allowlist"),
        log_only=parse_networks(sources.get("log_only_ranges", []), "sources.log_only_ranges"),
        max_hit_sources=_integer(limits, "limits", "max_hit_sources", 10_000, 1, 1_000_000),
        max_issued_ids=_integer(limits, "limits", "max_issued_ids", 100_000, 1, 10_000_000),
        max_ids_per_source=_integer(limits, "limits", "max_ids_per_source", 256, 1, 100_000),
        adapter=enforcement.get("adapter", "log-only"),
        nft_path=enforcement.get("nft_path", "/usr/sbin/nft"),
        tcp_ports=tuple(ports),
        trusted_proxies=parse_networks(
            sources.get("trusted_proxies", []), "sources.trusted_proxies"
        ),
    )


def load(path: str | Path) -> EngineConfig:
    path = Path(path)
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise EngineConfigError(f"cannot read engine config {path}: {exc.strerror}") from exc
    return parse(raw)
