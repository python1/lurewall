# SPDX-License-Identifier: AGPL-3.0-only
"""The shape of one log entry and one checkpoint, and how each is checked.

An entry is one line: the canonical JSON of

    {"seq", "ts", "type", "source", "detail", "prev_hash", "sig"}

``sig`` signs the other six fields. ``prev_hash`` is the SHA-256 of the whole
previous line (signature included), and the first entry uses 64 zeros. So
editing, removing or reordering a line breaks the chain at that line.

A checkpoint is ``{"seq", "head_hash", "ts", "sig"}``: the hash of entry
``seq``, signed. It holds no addresses and no event content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from lurewall import signing
from lurewall.canonical import LogValueError, check_value, parse_canonical, sha256_hex

ENTRY_KEYS = frozenset({"seq", "ts", "type", "source", "detail", "prev_hash", "sig"})
CHECKPOINT_KEYS = frozenset({"seq", "head_hash", "ts", "sig"})

# The longest line any reader will load. The writer's own limit is lower.
MAX_LINE_BYTES = 1024 * 1024
MAX_SOURCE_CHARS = 256

_TYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_HASH_RE = re.compile(r"[0-9a-f]{64}")


class EntryError(ValueError):
    """A line that is not a valid entry. ``code`` is a fixed word, never log content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: int
    type: str
    source: str | None
    detail: dict
    prev_hash: str
    sig: str
    hash: str


def is_event_type(value: object) -> bool:
    return type(value) is str and _TYPE_RE.fullmatch(value) is not None


def is_hash(value: object) -> bool:
    return type(value) is str and _HASH_RE.fullmatch(value) is not None


def is_source(value: object) -> bool:
    return value is None or (type(value) is str and len(value) <= MAX_SOURCE_CHARS)


def _is_count(value: object) -> bool:
    return type(value) is int and value >= 0


def check_entry_line(line: bytes, public_key_hex: str) -> Entry:
    """Check one line on its own: form, fields and signature. Not its place in the chain."""
    if len(line) > MAX_LINE_BYTES:
        raise EntryError("line_too_long")
    try:
        obj = parse_canonical(line)
    except LogValueError as exc:
        raise EntryError("not_canonical_json") from exc
    if obj.keys() != ENTRY_KEYS:
        raise EntryError("bad_fields")
    if not (
        type(obj["seq"]) is int
        and obj["seq"] >= 1
        and _is_count(obj["ts"])
        and is_event_type(obj["type"])
        and is_source(obj["source"])
        and type(obj["detail"]) is dict
        and is_hash(obj["prev_hash"])
        and signing.is_signature(obj["sig"])
    ):
        raise EntryError("bad_fields")
    signed = {key: value for key, value in obj.items() if key != "sig"}
    if not signing.verify(public_key_hex, obj["sig"], signed, signing.DOMAIN_EVENT):
        raise EntryError("bad_signature")
    return Entry(hash=sha256_hex(line), **obj)


def make_checkpoint(signer: signing.Signer, seq: int, head_hash: str, ts: int) -> dict:
    body = {"seq": seq, "head_hash": head_hash, "ts": ts}
    return {**body, "sig": signer.sign(body, signing.DOMAIN_CHECKPOINT)}


def check_checkpoint(obj: Any, public_key_hex: str) -> dict:
    """Check a checkpoint object. Raises EntryError with a fixed code."""
    if type(obj) is not dict or obj.keys() != CHECKPOINT_KEYS:
        raise EntryError("bad_fields")
    try:
        check_value(obj)
    except LogValueError as exc:
        raise EntryError("bad_fields") from exc
    if not (
        type(obj["seq"]) is int
        and obj["seq"] >= 1
        and _is_count(obj["ts"])
        and is_hash(obj["head_hash"])
        and signing.is_signature(obj["sig"])
    ):
        raise EntryError("bad_fields")
    body = {key: value for key, value in obj.items() if key != "sig"}
    if not signing.verify(public_key_hex, obj["sig"], body, signing.DOMAIN_CHECKPOINT):
        raise EntryError("bad_signature")
    return obj
