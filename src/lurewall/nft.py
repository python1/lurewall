# SPDX-License-Identifier: AGPL-3.0-only
"""The nftables adapter: timed set entries on the lab container.

A block is one element in a named set that a drop rule matches on. Each
element carries its expiry twice:

- as nftables' own element **timeout**, so the kernel removes it even if
  Lurewall is stopped;
- as an absolute time in the element's **comment**, so the sweeper and the
  startup reconcile can tell what an entry is and when it is due, with no
  help from Lurewall's saved state.

Sets live in memory and are lost on reboot; reconcile puts unexpired blocks
back with the time they have left.

Only two things ever reach the ``nft`` command line: fixed words from this
file, and addresses that have been through ``ipaddress`` and written back
out. No text from a request or from nft's own output is ever passed to it.
This adapter is for the isolated prototype and direct traffic only. Behind
Cloudflare the origin sees Cloudflare's addresses, and must not use it.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field

FAMILY = "inet"
TABLE = "lurewall"
SET4 = "blocked4"
SET6 = "blocked6"
CHAIN = "input"
DEFAULT_NFT = "/usr/sbin/nft"

_COMMENT_RE = re.compile(r"lurewall:exp=(\d{1,16})", re.ASCII)
# No entry may claim to expire further ahead than this: the longest TTL the
# engine config allows is four weeks.
MAX_AHEAD_MS = 29 * 24 * 3_600_000
_NFT_TIMEOUT_S = 10

# The whole ruleset this adapter owns. Re-running it is safe: the chain is
# flushed and refilled, the sets and their elements are left alone.
RULESET = f"""\
add table {FAMILY} {TABLE}
add set {FAMILY} {TABLE} {SET4} {{ type ipv4_addr; flags timeout; }}
add set {FAMILY} {TABLE} {SET6} {{ type ipv6_addr; flags interval, timeout; }}
add chain {FAMILY} {TABLE} {CHAIN} {{ type filter hook input priority -10; policy accept; }}
flush chain {FAMILY} {TABLE} {CHAIN}
add rule {FAMILY} {TABLE} {CHAIN} ip saddr @{SET4} counter drop
add rule {FAMILY} {TABLE} {CHAIN} ip6 saddr @{SET6} counter drop
"""


class NftError(RuntimeError):
    """nft could not be run, failed, or printed something unexpected."""


# Takes nft's arguments and optional standard input; returns standard output.
Runner = Callable[[list[str], str | None], str]


def system_runner(nft_path: str = DEFAULT_NFT) -> Runner:
    """Run the real ``nft``. Needs CAP_NET_ADMIN."""

    def run(args: list[str], stdin: str | None) -> str:
        try:
            done = subprocess.run(  # noqa: S603 - fixed binary, arguments built in this module
                [nft_path, *args],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=_NFT_TIMEOUT_S,
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise NftError(f"nft could not be run: {type(exc).__name__}") from exc
        if done.returncode != 0:
            # nft's message is not passed on: it can quote what it was given.
            raise NftError(f"nft exited with status {done.returncode}")
        return done.stdout

    return run


@dataclass(frozen=True)
class LiveEntry:
    """One element as the kernel holds it."""

    set_name: str
    element: str  # canonical text, safe to hand back to nft
    source: str | None  # the source key it blocks, or None if it is not one
    expiry_ms: int | None  # from the comment; None if absent or malformed
    kernel_expires_s: int | None  # seconds the kernel says are left


@dataclass
class ReconcileReport:
    kept: int = 0
    removed: list[tuple[str, str]] = field(default_factory=list)  # (element, reason)
    restored: list[str] = field(default_factory=list)


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def element_for(source: str) -> tuple[str, str]:
    """(set name, element text) for a source key. Raises ValueError for anything else."""
    if type(source) is not str:
        raise ValueError("source must be a string")
    network = ipaddress.ip_network(source, strict=True)
    address = network.network_address
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("refusing to block a loopback, unspecified or multicast address")
    if network.version == 4:
        if network.prefixlen != 32 or source != str(address):
            raise ValueError("an IPv4 source must be a single address")
        return SET4, str(address)
    if network.prefixlen != 64 or source != network.compressed:
        raise ValueError("an IPv6 source must be a /64")
    return SET6, network.compressed


def _parse_value(value: object, version: int) -> tuple[str, str | None]:
    """(element text, source key or None) for one value from nft's JSON."""
    try:
        if type(value) is str:
            address = ipaddress.ip_address(value)
            if address.version != version or "%" in value:
                raise ValueError("family")
            return address.compressed, (address.compressed if version == 4 else None)
        if type(value) is dict and set(value) == {"prefix"}:
            prefix = value["prefix"]
            if type(prefix) is not dict or set(prefix) != {"addr", "len"}:
                raise ValueError("prefix")
            address, length = prefix["addr"], prefix["len"]
            if type(address) is not str or "%" in address or type(length) is not int:
                raise ValueError("prefix")
            network = ipaddress.ip_network(f"{address}/{length}", strict=True)
            if network.version != version:
                raise ValueError("family")
            is_source = version == 6 and network.prefixlen == 64
            return network.compressed, (network.compressed if is_source else None)
        if type(value) is dict and set(value) == {"range"}:
            bounds = value["range"]
            if type(bounds) is not list or len(bounds) != 2:
                raise ValueError("range")
            if any(type(item) is not str or "%" in item for item in bounds):
                raise ValueError("range")
            low, high = (ipaddress.ip_address(item) for item in bounds)
            if low.version != version or high.version != version or low > high:
                raise ValueError("range")
            return f"{low.compressed}-{high.compressed}", None
    except (ValueError, TypeError) as exc:
        raise NftError("nft listed an element in an unexpected form") from exc
    raise NftError("nft listed an element in an unexpected form")


def _listing_items(output: str, kind: str) -> list[dict]:
    try:
        doc = json.loads(output)
        items = doc["nftables"]
        if type(items) is not list:
            raise ValueError("nftables")
        for item in items:
            if type(item) is not dict or len(item) != 1:
                raise ValueError("listing entry")
            ((name, body),) = item.items()
            if name not in ("metainfo", kind) or type(body) is not dict:
                raise ValueError("listing entry")
        return items
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise NftError("nft printed a listing in an unexpected form") from exc


def parse_set(output: str, set_name: str) -> list[LiveEntry]:
    """Read ``nft -j list set`` output. Raises NftError on anything unexpected."""
    if set_name not in (SET4, SET6):
        raise NftError("unexpected set name")
    version = 4 if set_name == SET4 else 6
    try:
        sets = [item["set"] for item in _listing_items(output, "set") if "set" in item]
        (found,) = sets
        if (
            found.get("name") != set_name
            or found.get("table") != TABLE
            or found.get("family") != FAMILY
        ):
            raise ValueError("wrong set")
        elements = found.get("elem", [])
        if type(elements) is not list:
            raise ValueError("elem")
    except ValueError as exc:
        raise NftError("nft printed a set listing in an unexpected form") from exc

    entries = []
    for item in elements:
        meta: dict = {}
        value = item
        if type(item) is dict and set(item) == {"elem"} and type(item["elem"]) is dict:
            meta = item["elem"]
            value = meta.get("val")
        element, source = _parse_value(value, version)
        comment = meta.get("comment")
        match = _COMMENT_RE.fullmatch(comment) if type(comment) is str else None
        expires = meta.get("expires")
        entries.append(
            LiveEntry(
                set_name=set_name,
                element=element,
                source=source,
                expiry_ms=int(match.group(1)) if match else None,
                kernel_expires_s=expires if type(expires) is int else None,
            )
        )
    return entries


class NftAdapter:
    """Adds, removes and lists blocks in nftables. Does nothing at all in dry-run."""

    def __init__(
        self,
        runner: Runner | None = None,
        *,
        clock: Callable[[], int] = _now_ms,
        dry_run: bool = True,
        tcp_ports: tuple[int, ...] = (),
    ) -> None:
        if any(type(port) is not int or not 1 <= port <= 65535 for port in tcp_ports):
            raise ValueError("nftables TCP ports must be integers from 1 to 65535")
        self._run = runner if runner is not None else system_runner()
        self._clock = clock
        self.dry_run = dry_run
        self._ready = False
        self._ruleset = RULESET
        if tcp_ports:
            ports = ", ".join(str(port) for port in sorted(set(tcp_ports)))
            scope = f" tcp dport {{ {ports} }} counter drop"
            self._ruleset = RULESET.replace(" counter drop", scope)

    # -- plumbing --------------------------------------------------------------------

    def _script(self, lines: list[str]) -> None:
        if lines:
            self._run(["-f", "-"], "\n".join(lines) + "\n")

    def ensure(self) -> None:
        """Create the table, sets, chain and drop rules if they are missing."""
        if self.dry_run or self._ready:
            return
        self._run(["-f", "-"], self._ruleset)
        self._ready = True

    def installed(self) -> bool:
        """Whether the Lurewall table exists at all."""
        items = _listing_items(self._run(["-j", "list", "tables"], None), "table")
        tables = [item["table"] for item in items if "table" in item]
        if any(
            type(table.get("family")) is not str or type(table.get("name")) is not str
            for table in tables
        ):
            raise NftError("nft printed a table listing in an unexpected form")
        return any(table["family"] == FAMILY and table["name"] == TABLE for table in tables)

    def _add_line(self, set_name: str, element: str, expiry_ms: int, now: int) -> str:
        seconds = max(1, -(-(expiry_ms - now) // 1000))  # round up: never shorter than asked
        return (
            f"add element {FAMILY} {TABLE} {set_name} "
            f'{{ {element} timeout {seconds}s comment "lurewall:exp={expiry_ms}" }}'
        )

    @staticmethod
    def _delete_line(set_name: str, element: str) -> str:
        return f"delete element {FAMILY} {TABLE} {set_name} {{ {element} }}"

    @staticmethod
    def _check_expiry(expiry_ms: int, now: int) -> None:
        if type(expiry_ms) is not int or expiry_ms - now > MAX_AHEAD_MS:
            raise ValueError("a block must carry an expiry time no more than 29 days ahead")

    # -- the adapter interface ---------------------------------------------------------

    def list(self) -> list[LiveEntry]:
        """Every element in both sets, as the kernel holds them now."""
        if self.dry_run:
            return []
        entries = []
        for set_name in (SET4, SET6):
            output = self._run(["-j", "list", "set", FAMILY, TABLE, set_name], None)
            entries += parse_set(output, set_name)
        return entries

    def block(self, source: str, expiry_ms: int) -> None:
        """Block ``source`` until ``expiry_ms``. Replaces any entry already there."""
        set_name, element = element_for(source)
        now = self._clock()
        self._check_expiry(expiry_ms, now)
        if self.dry_run or expiry_ms <= now:
            return
        self.ensure()
        lines = [
            self._delete_line(entry.set_name, entry.element)
            for entry in self.list()
            if entry.set_name == set_name and entry.element == element
        ]
        lines.append(self._add_line(set_name, element, expiry_ms, now))
        self._script(lines)

    def unblock(self, source: str) -> None:
        """Remove the block on ``source`` if there is one."""
        set_name, element = element_for(source)
        if self.dry_run:
            return
        self.ensure()
        self._script(
            [
                self._delete_line(entry.set_name, entry.element)
                for entry in self.list()
                if entry.set_name == set_name and entry.element == element
            ]
        )

    def reconcile(self, wanted: dict[str, int]) -> ReconcileReport:
        """Make the live sets match ``wanted`` (source -> absolute expiry).

        Removes entries that are expired, unknown, or do not carry the expiry
        the state file has for them, and puts back unexpired blocks that are
        missing (sets are lost on reboot) with the time they have left. One
        atomic nft transaction.
        """
        report = ReconcileReport()
        if self.dry_run:
            return report
        now = self._clock()
        targets = {}
        for source, expiry_ms in wanted.items():
            self._check_expiry(expiry_ms, now)
            if expiry_ms > now:
                targets[source] = (*element_for(source), expiry_ms)
        if self._ready and not self.installed():
            self._ready = False
        # Refresh the managed chain in the same transaction as element changes.
        # A malformed listing below still prevents any changes to a live table.
        lines = self._ruleset.splitlines() if self._ready else []
        self.ensure()
        in_place = set()
        for entry in self.list():
            target = targets.get(entry.source) if entry.source is not None else None
            if entry.source is None:
                reason = "unknown_shape"
            elif target is None:
                reason = "expired" if entry.source in wanted else "unknown"
            elif entry.expiry_ms is None:
                reason = "no_expiry"
            elif entry.expiry_ms != target[2]:
                reason = "expiry_mismatch"
            else:
                report.kept += 1
                in_place.add(entry.source)
                continue
            report.removed.append((entry.element, reason))
            lines.append(self._delete_line(entry.set_name, entry.element))
        for source, (set_name, element, expiry_ms) in sorted(targets.items()):
            if source not in in_place:
                report.restored.append(source)
                lines.append(self._add_line(set_name, element, expiry_ms, now))
        self._script(lines)
        return report

    def sweep(self) -> list[tuple[str, str]]:
        """Remove every entry that is past due or cannot show when it is due.

        Reads only the live entries, so it works with Lurewall stopped and
        its state lost. Returns (element, reason) for each removal.
        """
        if self.dry_run or not self.installed():
            return []
        now = self._clock()
        removed = []
        lines = []
        for entry in self.list():
            if entry.source is None:
                reason = "unknown_shape"
            elif entry.expiry_ms is None:
                reason = "no_expiry"
            elif entry.expiry_ms <= now:
                reason = "expired"
            elif entry.expiry_ms - now > MAX_AHEAD_MS:
                reason = "bad_expiry"
            else:
                continue
            removed.append((entry.element, reason))
            lines.append(self._delete_line(entry.set_name, entry.element))
        self._script(lines)
        return removed
