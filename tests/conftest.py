# SPDX-License-Identifier: AGPL-3.0-only
"""Shared test helpers. Every key here is generated in memory at run time."""

from __future__ import annotations

import pytest

from lurewall import signing
from lurewall.canonical import canonical_bytes
from lurewall.eventlog import EventLog

# Strings an attacker can put in a user agent or a path. Every one must survive
# as data: one entry, one line, read back unchanged.
HOSTILE_STRINGS = [
    "",
    'quote " and backslash \\ and slash /',
    "newline\nin the middle",
    "carriage\r\nreturn",
    "tab\tand NUL \x00 and escape \x1b[31m and DEL \x7f",
    "invalid UTF-8 decoded with replacement: ��",
    "lone surrogates from surrogateescape: \udc80\udcff \ud800",
    "unicode line separators     and NEL \x85",
    "non-BMP \U0001f600 and RTL override ‮",
    '{"seq":1,"type":"block","detail":{}}',
    '"}\n{"detail":{},"prev_hash":"' + "0" * 64 + '","seq":2,"sig":"AAAA","type":"unblock"}',
    "${jndi:ldap://x/a} ' OR 1=1 -- <script>alert(1)</script> ../../etc/passwd",
    "%s%s%s%n {0} {__class__} $(reboot) `id`",
    "NaN Infinity -Infinity 1e999",
    "A" * 9000,
]


class FakeClock:
    def __init__(self, now: int = 1_800_000_000_000) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now

    def advance(self, ms: int) -> None:
        self.now += ms


class FakeDisk:
    def __init__(self, free: int = 10**12) -> None:
        self.free = free

    def __call__(self, _path) -> int:
        return self.free


@pytest.fixture
def signer():
    return signing.EurekaSigner.ephemeral()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def disk():
    return FakeDisk()


@pytest.fixture
def make_log(tmp_path, signer, clock, disk):
    """Open an EventLog on a temp file with a fake clock and disk. Closes leftovers."""
    opened = []

    def _make(name="events.log", **kwargs):
        kwargs.setdefault("clock", clock)
        kwargs.setdefault("disk_free", disk)
        kwargs.setdefault("fsync", False)
        log = EventLog(tmp_path / name, kwargs.pop("signer", signer), **kwargs)
        opened.append(log)
        return log

    yield _make
    for log in opened:
        log.close()


def read_lines(path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


def signed_line(signer, seq, prev_hash, *, type="probe", source=None, detail=None, ts=1) -> bytes:
    """A correctly signed entry line, as the key holder could forge one."""
    body = {
        "seq": seq,
        "ts": ts,
        "type": type,
        "source": source,
        "detail": {} if detail is None else detail,
        "prev_hash": prev_hash,
    }
    sig = signer.sign(body, signing.DOMAIN_EVENT)
    return canonical_bytes({**body, "sig": sig}) + b"\n"
