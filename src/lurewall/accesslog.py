# SPDX-License-Identifier: AGPL-3.0-only
"""Parse one line of nginx's ``lurewall_json`` access log.

Every field is attacker-influenced data: the user agent, the path, the
Referer and even the method are whatever the client sent. Nothing here treats
a field as a format string, a pattern or a command. A line either becomes a
``Record`` or a ``ParseFailure`` with a fixed reason word; it never raises and
is never skipped.

Bytes that are not valid UTF-8 are decoded with U+FFFD replacement characters
and the record says so, because nginx's ``escape=json`` passes bytes above 126
through as they arrived.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

from lurewall.canonical import sha256_hex

FIELDS = (
    "ts",
    "ip",
    "method",
    "request",
    "uri",
    "status",
    "ua",
    "lang",
    "referer",
    "sec_fetch_site",
    "request_id",
)
_FIELD_SET = frozenset(FIELDS)

# nginx can turn one request byte into six log bytes (\u00XX), and several
# fields can each hold a full header buffer. A longer line is not from nginx.
MAX_LINE_BYTES = 256 * 1024

_TS_RE = re.compile(r"(\d{1,11})\.(\d{3})", re.ASCII)
_STATUS_RE = re.compile(r"[1-5]\d{2}", re.ASCII)
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)


@dataclass(frozen=True)
class Record:
    """One request, as nginx logged it. String fields are untrusted data."""

    ts_ms: int
    ip: str  # normalized address text; the one field nginx, not the client, decides
    method: str
    request: str
    uri: str
    status: int
    ua: str
    lang: str
    referer: str
    sec_fetch_site: str
    request_id: str
    offset: int  # byte offset of the line in its file
    line_sha256: str
    invalid_utf8: bool  # bytes were replaced with U+FFFD while decoding
    stale: bool  # too old (or too far in the future) to enforce on


@dataclass(frozen=True)
class ParseFailure:
    """A line that is not a record. Holds no line content, only where and what."""

    offset: int
    line_sha256: str
    length: int
    reason: str


class _Duplicate(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _Duplicate(key)
        result[key] = value
    return result


def _reject_constant(_text: str) -> object:
    raise ValueError("constant")


def _normalize_ip(text: str) -> str | None:
    if "%" in text:  # no zone identifiers: they are not part of an address
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        # ::ffff:192.0.2.1 and 192.0.2.1 are one client, so one key.
        address = address.ipv4_mapped
    return address.compressed


def parse_line(raw: bytes, offset: int, *, now_ms: int, max_age_ms: int) -> Record | ParseFailure:
    """Turn one log line (no trailing newline) into a Record or a ParseFailure."""
    digest = sha256_hex(raw)

    def failure(reason: str) -> ParseFailure:
        return ParseFailure(offset=offset, line_sha256=digest, length=len(raw), reason=reason)

    if len(raw) > MAX_LINE_BYTES:
        return failure("line_too_long")
    try:
        text = raw.decode("utf-8")
        invalid_utf8 = False
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        invalid_utf8 = True
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except _Duplicate:
        return failure("duplicate_field")
    except (ValueError, RecursionError):
        return failure("not_json")
    if type(obj) is not dict:
        return failure("not_an_object")
    if obj.keys() != _FIELD_SET:
        return failure("unexpected_fields")
    if any(type(value) is not str for value in obj.values()):
        return failure("field_not_a_string")

    ts = _TS_RE.fullmatch(obj["ts"])
    if ts is None:
        return failure("bad_ts")
    ts_ms = int(ts.group(1)) * 1000 + int(ts.group(2))
    ip = _normalize_ip(obj["ip"])
    if ip is None:
        return failure("bad_ip")
    if _STATUS_RE.fullmatch(obj["status"]) is None:
        return failure("bad_status")
    if _REQUEST_ID_RE.fullmatch(obj["request_id"]) is None:
        return failure("bad_request_id")

    return Record(
        ts_ms=ts_ms,
        ip=ip,
        method=obj["method"],
        request=obj["request"],
        uri=obj["uri"],
        status=int(obj["status"]),
        ua=obj["ua"],
        lang=obj["lang"],
        referer=obj["referer"],
        sec_fetch_site=obj["sec_fetch_site"],
        request_id=obj["request_id"],
        offset=offset,
        line_sha256=digest,
        invalid_utf8=invalid_utf8,
        # Old events are logged, never enforced. A time far in the future is
        # just as untrustworthy, so it gets the same treatment.
        stale=abs(now_ms - ts_ms) > max_age_ms,
    )
