# SPDX-License-Identifier: AGPL-3.0-only
"""What may be signed, and what counts as a canonical line."""

import enum
import json

import pytest

from conftest import HOSTILE_STRINGS
from lurewall import signing
from lurewall.canonical import (
    MAX_DEPTH,
    MAX_INT,
    MIN_INT,
    LogValueError,
    canonical_bytes,
    check_value,
    parse_canonical,
)


class Colour(enum.IntEnum):
    RED = 1


class Text(str):
    pass


FLOATS = [float("nan"), float("inf"), float("-inf"), 0.0, -0.0, 1.0, 1.5, 1e308]


@pytest.mark.parametrize("number", FLOATS)
def test_no_float_is_ever_signed_finite_or_not(number):
    for payload in (
        {"a": number},
        {"a": {"b": {"c": number}}},
        {"a": [1, [2, number]]},
        {"a": [{"b": number}]},
    ):
        with pytest.raises(LogValueError, match="floats"):
            canonical_bytes(payload)


@pytest.mark.parametrize("number", FLOATS)
def test_signer_refuses_floats_itself(signer, number):
    with pytest.raises(LogValueError):
        signer.sign({"a": number}, signing.DOMAIN_EVENT)


def test_eurekas_encoder_would_have_written_non_json_without_the_guard():
    """Why the guard exists: the reused encoder emits a bare NaN token."""
    from lurewall import _eureka

    assert _eureka.canonical_json_bytes({"a": float("nan")}) == b'{"a":NaN}'


@pytest.mark.parametrize("key", [1, 1.5, True, None, float("nan"), b"k", ("a",)])
def test_non_string_keys_are_refused(key):
    with pytest.raises(LogValueError):
        canonical_bytes({key: "v"})


@pytest.mark.parametrize(
    "value",
    [b"bytes", ("tuple",), {"set"}, Colour.RED, Text("s"), object(), 1j, bytearray(b"x")],
)
def test_only_exact_json_types_are_allowed(value):
    with pytest.raises(LogValueError):
        canonical_bytes({"a": value})


def test_integer_range_is_signed_64_bit():
    canonical_bytes({"a": MAX_INT, "b": MIN_INT})
    for value in (MAX_INT + 1, MIN_INT - 1, 10**100):
        with pytest.raises(LogValueError):
            canonical_bytes({"a": value})


def test_nesting_is_bounded():
    value: object = "leaf"
    for _ in range(MAX_DEPTH):
        value = [value]
    check_value(value)  # exactly at the limit
    value = [value]
    with pytest.raises(LogValueError, match="nested"):
        check_value(value)
    cyclic: list = []
    cyclic.append(cyclic)
    with pytest.raises(LogValueError, match="nested"):
        check_value(cyclic)


def test_payload_must_be_an_object():
    for payload in ([], "s", 1, None):
        with pytest.raises(LogValueError):
            canonical_bytes(payload)


def test_plain_values_pass():
    data = canonical_bytes({"b": [1, True, None, "x", {"y": -2}], "a": ""})
    assert data == b'{"a":"","b":[1,true,null,"x",{"y":-2}]}'


@pytest.mark.parametrize("text", HOSTILE_STRINGS)
def test_any_string_is_one_ascii_line_and_reads_back_unchanged(text):
    data = canonical_bytes({"ua": text, text: "as a key too"})
    assert b"\n" not in data and b"\r" not in data
    assert all(0x20 <= byte < 0x7F or byte == 0x7F for byte in data)
    back = parse_canonical(data)
    assert back["ua"] == text
    assert back[text] == "as a key too"


NOT_CANONICAL = [
    b"",
    b"{}\n",
    b" {}",
    b'{"a": 1}',
    b'{"a":1 }',
    b'{"b":1,"a":2}',  # keys not sorted
    b'{"a":1,"a":2}',  # duplicate key
    b'{"a":1,"a":1}',
    b'{"a":1.0}',
    b'{"a":1e3}',
    b'{"a":-0.0}',
    b'{"a":NaN}',
    b'{"a":Infinity}',
    b'{"a":-Infinity}',
    b'{"a":01}',
    b'{"a":+1}',
    b'{"a":-0}',
    b'{"a":"\\u00E9"}',  # upper-case escape
    b'{"a":"\\u0041"}',  # escaped where the canonical form is literal
    b'{"a":"\\/"}',
    b'{"a":"\xc3\xa9"}',  # raw UTF-8 where an escape is canonical
    b'{"a":"\xff\xfe"}',  # invalid UTF-8
    b'{"a":"line\nbreak"}',  # raw control character
    b'{"a":"tab\there"}',
    b'{"a":1}{"a":1}',
    b'{"a":1},',
    b"[]",
    b'"text"',
    b"1",
    b"null",
    b'{"a":9223372036854775808}',
    b'{"a":' + b"9" * 5000 + b"}",
    b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}",
    b"{" + b'"a":{' * 20 + b"}" * 20 + b"}",
    b"\xef\xbb\xbf{}",  # byte-order mark
    b"{'a':1}",
    b'{"a":1,}',
    b'{"a":True}',
    b'{"a":1}\x00',
]


@pytest.mark.parametrize("line", NOT_CANONICAL, ids=lambda b: repr(b[:24]))
def test_non_canonical_lines_are_refused(line):
    with pytest.raises(LogValueError):
        parse_canonical(line)


def test_canonical_line_parses_to_itself():
    line = b'{"a":[1,-2,true,false,null,"x"],"b":{"c":""}}'
    assert parse_canonical(line) == json.loads(line)
    assert canonical_bytes(parse_canonical(line)) == line


def test_signature_spelling_and_key_form_are_strict(signer):
    payload = {"a": 1}
    sig = signer.sign(payload, signing.DOMAIN_EVENT)
    key = signer.public_key_hex
    assert signing.verify(key, sig, payload, signing.DOMAIN_EVENT)

    # Same 64 bytes, different base64 spelling: unused trailing bits set.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet.index(sig[-3])
    respelled = sig[:-3] + alphabet[last ^ 1] + "=="
    assert respelled != sig
    assert not signing.verify(key, respelled, payload, signing.DOMAIN_EVENT)

    for bad_sig in (sig + "\n", " " + sig, sig[:-2], sig.rstrip("="), "", "!!!!", None, 5, b"x"):
        assert not signing.verify(key, bad_sig, payload, signing.DOMAIN_EVENT)
    for bad_key in (key.upper(), key[:-1], key + "0", " " + key, "zz" * 32, "", None, 5):
        assert not signing.verify(bad_key, sig, payload, signing.DOMAIN_EVENT)
    assert not signing.verify(key, sig, {"a": 2}, signing.DOMAIN_EVENT)


def test_signer_repr_shows_no_private_material(signer):
    private_hex = signer._crypto.get_private_key_hex()
    assert private_hex not in repr(signer)
    assert private_hex not in str(signer)
