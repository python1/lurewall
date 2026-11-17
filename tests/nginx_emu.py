# SPDX-License-Identifier: AGPL-3.0-only
"""Builds access-log lines the way nginx's ``escape=json`` is documented to.

nginx escapes the double quote and the backslash with a backslash, writes
characters below 32 as ``\\n``, ``\\r``, ``\\t``, ``\\b``, ``\\f`` or
``\\u00XX``, and leaves every other byte alone, including bytes above 126.
These helpers imitate that from the documentation and nginx's source. They
are not nginx: what a real nginx writes for invalid UTF-8 is settled by the
lab's hostile-bytes test, not here.

All addresses are from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32) and every request ID is made up.
"""

from __future__ import annotations

import hashlib

_SHORT = {0x08: b"\\b", 0x09: b"\\t", 0x0A: b"\\n", 0x0C: b"\\f", 0x0D: b"\\r"}

NOW_MS = 1_800_000_000_000


def escape_json(value: bytes) -> bytes:
    out = bytearray()
    for byte in value:
        if byte in (0x22, 0x5C):
            out += b"\\" + bytes([byte])
        elif byte < 0x20:
            out += _SHORT.get(byte, b"\\u%04X" % byte)
        else:
            out.append(byte)
    return bytes(out)


def request_id(seed: object) -> str:
    return hashlib.sha256(repr(seed).encode()).hexdigest()[:32]


def line(
    *,
    ts_ms: int = NOW_MS,
    ip: str = "192.0.2.10",
    method: bytes = b"GET",
    uri: bytes = b"/",
    status: int = 200,
    ua: bytes = b"Mozilla/5.0",
    lang: bytes = b"en-GB",
    referer: bytes = b"",
    sec_fetch_site: bytes = b"",
    rid: str | None = None,
    request: bytes | None = None,
) -> bytes:
    """One log line, newline included, with client-controlled values given as raw bytes."""
    if request is None:
        request = method + b" " + uri + b" HTTP/1.1"
    if rid is None:
        rid = request_id((ts_ms, ip, uri, ua))
    fields = [
        (b"ts", b"%d.%03d" % divmod(ts_ms, 1000)),
        (b"ip", ip.encode()),
        (b"method", escape_json(method)),
        (b"request", escape_json(request)),
        (b"uri", escape_json(uri)),
        (b"status", b"%d" % status),
        (b"ua", escape_json(ua)),
        (b"lang", escape_json(lang)),
        (b"referer", escape_json(referer)),
        (b"sec_fetch_site", escape_json(sec_fetch_site)),
        (b"request_id", rid.encode()),
    ]
    return b"{" + b",".join(b'"' + k + b'":"' + v + b'"' for k, v in fields) + b"}\n"


# Raw bytes a client can put in a user agent or a path, with what the reader
# must hand on after decoding with replacement. None of these may cost a line.
HOSTILE_VALUES: list[tuple[str, bytes, str]] = [
    ("plain", b"curl/8.5.0", "curl/8.5.0"),
    ("quote", b'say "hi"', 'say "hi"'),
    ("backslash", b"C:\\path\\n", "C:\\path\\n"),
    ("backslash_quote", b'\\"', '\\"'),
    ("trailing_backslash", b"ends with \\", "ends with \\"),
    ("newline", b"line1\nline2\r\nline3", "line1\nline2\r\nline3"),
    ("controls", bytes(range(1, 32)), "".join(map(chr, range(1, 32)))),
    ("nul", b"a\x00b", "a\x00b"),
    ("del", b"a\x7fb", "a\x7fb"),
    (
        "valid_utf8",
        "caf\u00e9 \u65e5\u672c \U0001f600".encode(),
        "caf\u00e9 \u65e5\u672c \U0001f600",
    ),
    ("invalid_ff", b"a\xff\xfeb", "a\ufffd\ufffdb"),
    ("truncated_multibyte", b"a\xe2\x82", "a\ufffd"),
    ("overlong_slash", b"/\xc0\xaf/", "/\ufffd\ufffd/"),
    ("utf8_surrogate", b"\xed\xa0\x80", "\ufffd\ufffd\ufffd"),
    ("lone_continuation", b"\x80\x80", "\ufffd\ufffd"),
    ("latin1", b"caf\xe9", "caf\ufffd"),
    ("all_high_bytes", bytes(range(0x80, 0x100)), None),
    (
        ("json_breakout", b'","ip":"203.0.113.99","status":"200', None),
        b'","ip":"203.0.113.99","status":"200',
        '","ip":"203.0.113.99","status":"200',
    ),
    ("object_breakout", b'"}\n{"ts":"1.000","ip":"203.0.113.99"}', None),
    (
        "whole_fake_line",
        b"x\n" + line(ip="203.0.113.99", uri=b"/admin", status=200),
        None,
    ),
    ("escape_sequences", b"\\u0041\\n\\x41\\ud800", "\\u0041\\n\\x41\\ud800"),
    ("json_tokens", b"NaN Infinity null true {} [] 1e999", "NaN Infinity null true {} [] 1e999"),
    ("format_strings", b"%s%n{0}{__class__}${jndi:ldap://x}$(id)`id`", None),
    ("ansi", b"\x1b[2J\x1b]0;title\x07", "\x1b[2J\x1b]0;title\x07"),
    ("empty", b"", ""),
    ("long", b"A" * 8000, "A" * 8000),
    ("long_controls", b"\x01" * 2000, "\x01" * 2000),
]


def expected_text(raw: bytes, expected: str | None) -> str:
    return raw.decode("utf-8", errors="replace") if expected is None else expected


def build_fixture() -> bytes:
    """The checked-in fixture: hostile requests, ordinary ones and lines that are not records."""
    out = bytearray()
    ts = NOW_MS
    for index, (_name, raw, _expected) in enumerate(HOSTILE_VALUES):
        ts += 37
        out += line(ts_ms=ts, ip=f"198.51.100.{index + 1}", ua=raw, uri=b"/ua")
        ts += 37
        out += line(ts_ms=ts, ip=f"198.51.100.{index + 1}", uri=b"/p/" + raw, status=404)
        ts += 37
        out += line(
            ts_ms=ts, ip="2001:db8::" + format(index + 1, "x"), referer=raw, sec_fetch_site=raw,
            lang=raw, method=b"GET",
        )  # fmt: skip
    # A request nginx could not parse at all: empty method and URI, status 400.
    tls_hello = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"
    out += line(
        ts_ms=ts + 1, ip="203.0.113.7", method=b"", uri=b"", status=400, request=tls_hello,
        ua=b"", lang=b"",
    )  # fmt: skip
    out += line(ts_ms=ts + 2, ip="::ffff:203.0.113.8", uri=b"/.env", status=404)
    out += line(ts_ms=ts + 3, ip="203.0.113.9", uri=b"/", status=429)
    # Lines that are not records. Each must become a parse_failure, never vanish.
    out += b"\n"
    out += b"plain text, not JSON\n"
    out += b'{"ts":"1800000000.000"}\n'
    out += b"\xff\xfe\x00 binary junk \x00\n"
    out += line(ts_ms=ts + 4, ip="not-an-address")
    out += line(ts_ms=ts + 5).replace(b'"status":"200"', b'"status":"200","status":"403"')
    out += line(ts_ms=ts + 6, ip="203.0.113.10", uri=b"/after-the-junk")
    return bytes(out)


FIXTURE_FAILURES = 6
FIXTURE_RECORDS = 3 * len(HOSTILE_VALUES) + 4
