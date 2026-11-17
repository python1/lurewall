# SPDX-License-Identifier: AGPL-3.0-only
"""A stand-in for the ``nft`` command, for unit tests.

It understands exactly the commands the adapter sends and prints JSON in the
form nft 1.0 prints. It is not nftables: what the real one accepts and prints
is checked by the tests that run against a real ``nft`` in CI.
"""

from __future__ import annotations

import copy
import json
import re

from lurewall.nft import CHAIN, FAMILY, SET4, SET6, TABLE, NftError

_PREFIX = rf"{FAMILY} {TABLE}"
_ADD_ELEMENT = re.compile(
    rf"add element {_PREFIX} (\w+) \{{ (\S+)(?: timeout (\d+)s)?(?: comment \"([^\"]*)\")? \}}"
)
_DELETE_ELEMENT = re.compile(rf"delete element {_PREFIX} (\w+) \{{ (\S+) \}}")


class FakeNft:
    def __init__(self, clock) -> None:
        self.clock = clock
        self.installed = False
        self.sets: dict[str, dict[str, dict]] = {}
        self.rules: list[str] = []
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail = False
        self.freeze_timeouts = False  # as if the kernel's own expiry never fired

    # -- helpers for tests -----------------------------------------------------------

    def reboot(self) -> None:
        """Sets live in memory: a reboot loses the table and everything in it."""
        self.installed = False
        self.sets = {}
        self.rules = []

    def changes(self) -> list[str]:
        """Every script that was run, as text."""
        return [stdin for args, stdin in self.calls if args == ["-f", "-"]]

    def elements(self) -> dict[str, dict]:
        self._expire()
        return {element: meta for items in self.sets.values() for element, meta in items.items()}

    # -- the command ---------------------------------------------------------------------

    def _expire(self) -> None:
        if self.freeze_timeouts:
            return
        now = self.clock()
        for items in self.sets.values():
            for element in [
                element
                for element, meta in items.items()
                if meta["timeout"] is not None and meta["added"] + meta["timeout"] * 1000 <= now
            ]:
                del items[element]

    def __call__(self, args: list[str], stdin: str | None) -> str:
        self.calls.append((list(args), stdin))
        if self.fail:
            raise NftError("nft exited with status 1")
        self._expire()
        if args == ["-j", "list", "tables"]:
            tables = [{"table": {"family": FAMILY, "name": TABLE, "handle": 1}}]
            return json.dumps({"nftables": [{"metainfo": {}}, *(tables if self.installed else [])]})
        if args[:3] == ["-j", "list", "set"] and args[3:5] == [FAMILY, TABLE] and len(args) == 6:
            if not self.installed or args[5] not in self.sets:
                raise NftError("nft exited with status 1")
            return self._list(args[5])
        if args == ["-f", "-"] and stdin is not None:
            self._apply(stdin)
            return ""
        raise AssertionError(f"the adapter ran an unexpected nft command: {args}")

    def _list(self, name: str) -> str:
        now = self.clock()
        elements = []
        for element, meta in self.sets[name].items():
            if "/" in element:
                addr, _, length = element.partition("/")
                value: object = {"prefix": {"addr": addr, "len": int(length)}}
            elif "-" in element:
                value = {"range": element.split("-")}
            else:
                value = element
            if meta["timeout"] is None and meta["comment"] is None:
                elements.append(value)
                continue
            entry: dict = {"val": value}
            if meta["timeout"] is not None:
                left = meta["timeout"] - (now - meta["added"]) // 1000
                entry |= {"timeout": meta["timeout"], "expires": max(1, left)}
            if meta["comment"] is not None:
                entry["comment"] = meta["comment"]
            elements.append({"elem": entry})
        body = {"family": FAMILY, "name": name, "table": TABLE, "handle": 2, "flags": ["timeout"]}
        if elements:
            body["elem"] = elements
        return json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}, {"set": body}]})

    def _apply(self, script: str) -> None:
        # One transaction: all of it lands, or none of it.
        installed, sets, rules = self.installed, copy.deepcopy(self.sets), list(self.rules)
        for line in script.splitlines():
            if not line.strip():
                continue
            if line == f"add table {_PREFIX}":
                installed = True
            elif line.startswith(f"add set {_PREFIX} "):
                sets.setdefault(line.split()[4], {})
            elif line.startswith(f"add chain {_PREFIX} {CHAIN} "):
                pass
            elif line == f"flush chain {_PREFIX} {CHAIN}":
                rules = []
            elif line.startswith(f"add rule {_PREFIX} {CHAIN} "):
                rules.append(line.split(f"{CHAIN} ", 1)[1])
            elif match := _ADD_ELEMENT.fullmatch(line):
                name, element, timeout, comment = match.groups()
                if not installed or name not in sets:
                    raise NftError("nft exited with status 1")
                # Like nft: adding an element that is there changes nothing.
                sets[name].setdefault(
                    element,
                    {
                        "timeout": int(timeout) if timeout else None,
                        "comment": comment,
                        "added": self.clock(),
                    },
                )
            elif match := _DELETE_ELEMENT.fullmatch(line):
                name, element = match.groups()
                if name not in sets or element not in sets[name]:
                    raise NftError("nft exited with status 1")
                del sets[name][element]
            else:
                raise AssertionError(f"the adapter sent a line the fake does not know: {line!r}")
        self.installed, self.sets, self.rules = installed, sets, rules


__all__ = ["SET4", "SET6", "FakeNft"]
