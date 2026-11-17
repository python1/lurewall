# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical JSON for the signed log: what may be signed, and its exact bytes.

The bytes come from eureka's ``canonical_json_bytes`` (sorted keys, no
whitespace, ASCII-only escapes), so what Lurewall hashes is byte-for-byte what
eureka signs. That encoder accepts more than a hash chain can tolerate, so
every value is checked here first:

* **No floats at all.** eureka's encoder would write ``NaN`` and ``Infinity``,
  which are not JSON, and finite floats print differently across languages.
  Times and counts are integers.
* **String keys only.** The encoder turns ``1``, ``1.5`` and ``True`` into
  string keys, so ``{1: a, "1": b}`` would produce a duplicate key.
* **Exact built-in types only**, bounded integers and bounded nesting, so the
  same value always produces the same bytes in any implementation.

Strings may hold anything, including newlines, quotes, control characters and
lone surrogates left by bad UTF-8: all are escaped, so one entry is always one
line of printable ASCII.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from lurewall import _eureka

MAX_DEPTH = 8
MAX_INT = 2**63 - 1
MIN_INT = -(2**63)

ZERO_HASH = "0" * 64


class LogValueError(ValueError):
    """A value that must not be signed, or bytes that are not canonical."""


def check_value(value: Any, _depth: int = 0) -> None:
    """Raise LogValueError unless ``value`` is safe to canonicalize and sign."""
    kind = type(value)
    if value is None or kind is bool or kind is str:
        return
    if kind is int:
        if not MIN_INT <= value <= MAX_INT:
            raise LogValueError("integer outside the signed 64-bit range")
        return
    if kind is float:
        raise LogValueError("floats are not allowed in signed data (use integers)")
    if kind is dict:
        if _depth >= MAX_DEPTH:
            raise LogValueError("value nested too deeply")
        for key, item in value.items():
            if type(key) is not str:
                raise LogValueError("object keys must be strings")
            check_value(item, _depth + 1)
        return
    if kind is list:
        if _depth >= MAX_DEPTH:
            raise LogValueError("value nested too deeply")
        for item in value:
            check_value(item, _depth + 1)
        return
    raise LogValueError(f"type {kind.__name__} is not allowed in signed data")


def canonical_bytes(payload: dict) -> bytes:
    """The exact bytes that are signed and hashed for ``payload``."""
    if type(payload) is not dict:
        raise LogValueError("payload must be a JSON object")
    check_value(payload)
    return _eureka.canonical_json_bytes(payload)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_number(text: str) -> Any:
    raise LogValueError(f"number form not allowed: {text[:16]}")


def parse_canonical(line: bytes) -> dict:
    """Parse one line and require it to be exactly its own canonical form.

    Rejects anything a canonical writer could not have produced: non-ASCII
    bytes, floats, ``NaN``/``Infinity``, whitespace, unsorted or duplicate
    keys, alternative escapes. So a line has one meaning and one hash.
    """
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LogValueError("not ASCII") from exc
    try:
        value = json.loads(text, parse_float=_reject_number, parse_constant=_reject_number)
    except LogValueError:
        raise
    except (ValueError, RecursionError) as exc:
        raise LogValueError("not JSON") from exc
    if type(value) is not dict:
        raise LogValueError("not a JSON object")
    if canonical_bytes(value) != line:
        raise LogValueError("not in canonical form")
    return value
