# SPDX-License-Identifier: AGPL-3.0-only
"""One access-log line in, one Record or ParseFailure out. Nothing raises, nothing vanishes."""

import random
import re
from pathlib import Path

import pytest

import nginx_emu
from lurewall.accesslog import FIELDS, MAX_LINE_BYTES, ParseFailure, Record, parse_line
from lurewall.canonical import sha256_hex
from nginx_emu import HOSTILE_VALUES, NOW_MS, expected_text, line

REPO = Path(__file__).resolve().parents[1]
MAX_AGE = 300_000


def parse(raw: bytes, offset: int = 0, now: int = NOW_MS):
    assert raw.endswith(b"\n")
    return parse_line(raw[:-1], offset, now_ms=now, max_age_ms=MAX_AGE)


def test_parser_fields_match_the_shipped_nginx_format():
    conf = (REPO / "deploy" / "nginx" / "lurewall-log.conf").read_text()
    body = conf[conf.index("log_format lurewall_json") : conf.index("access_log ")]
    assert tuple(re.findall(r'"(\w+)":"\$', body)) == FIELDS
    assert "escape=json" in body
    for variable in ("$http_referer", "$http_sec_fetch_site", "$request_id", "$msec"):
        assert variable in body
    for never_logged in ("x_forwarded_for", "cookie", "authorization", "request_body"):
        assert never_logged not in conf


def test_ordinary_line():
    raw = line(
        ts_ms=NOW_MS - 1500,
        ip="192.0.2.44",
        uri=b"/index.html?v=1",
        status=200,
        ua=b"Mozilla/5.0 (X11)",
        lang=b"en-GB,en;q=0.9",
        referer=b"http://192.0.2.1/",
        sec_fetch_site=b"same-origin",
        rid="0123456789abcdef0123456789abcdef",
    )
    record = parse(raw, offset=777)
    assert record == Record(
        ts_ms=NOW_MS - 1500,
        ip="192.0.2.44",
        method="GET",
        request="GET /index.html?v=1 HTTP/1.1",
        uri="/index.html?v=1",
        status=200,
        ua="Mozilla/5.0 (X11)",
        lang="en-GB,en;q=0.9",
        referer="http://192.0.2.1/",
        sec_fetch_site="same-origin",
        request_id="0123456789abcdef0123456789abcdef",
        offset=777,
        line_sha256=sha256_hex(raw[:-1]),
        invalid_utf8=False,
        stale=False,
    )


@pytest.mark.parametrize(("name", "raw", "expected"), HOSTILE_VALUES, ids=lambda v: None)
def test_hostile_user_agent_and_path_are_parsed_as_data(name, raw, expected):
    text = expected_text(raw, expected)
    try:
        raw.decode("utf-8")
        invalid = False
    except UnicodeDecodeError:
        invalid = True
    for field in ("ua", "uri", "referer", "sec_fetch_site", "lang", "method"):
        built = line(ip="192.0.2.5", status=404, rid="ab" * 16, **{field: raw})
        assert built.count(b"\n") == 1, name  # the emulated nginx never writes a raw newline
        record = parse(built)
        assert isinstance(record, Record), (name, field)
        assert getattr(record, field) == text
        # The client's bytes changed nothing nginx decided.
        assert (record.ip, record.status, record.request_id) == ("192.0.2.5", 404, "ab" * 16)
        assert record.invalid_utf8 is invalid


def test_a_fake_log_line_in_the_user_agent_stays_inside_the_user_agent():
    fake = line(ip="203.0.113.99", uri=b"/admin", status=200)
    record = parse(line(ip="192.0.2.5", uri=b"/", ua=b"x\n" + fake))
    assert record.ip == "192.0.2.5" and record.uri == "/"
    assert record.ua == "x\n" + fake.decode()


def test_request_that_nginx_could_not_parse_is_still_a_record():
    garbage = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xff"
    record = parse(line(method=b"", uri=b"", status=400, request=garbage, ua=b"", lang=b""))
    assert isinstance(record, Record)
    assert (record.method, record.uri, record.status) == ("", "", 400)
    assert record.request == garbage.decode("utf-8", errors="replace") and record.invalid_utf8


GOOD = line()[:-1]


def swap(old: bytes, new: bytes) -> bytes:
    assert old in GOOD
    return GOOD.replace(old, new, 1)


FAILURES = [
    (b"", "not_json"),
    (b" ", "not_json"),
    (b"plain text", "not_json"),
    (GOOD[:-1], "not_json"),
    (GOOD + b"}", "not_json"),
    (GOOD + GOOD, "not_json"),
    (b"\xff\xfe\x00\x01", "not_json"),
    (b"\xef\xbb\xbf" + GOOD, "not_json"),
    (b"[" * 100_000, "not_json"),
    (b'{"a":' * 40_000, "not_json"),
    (b"NaN", "not_json"),
    (swap(b'"status":"200"', b'"status":NaN'), "not_json"),
    (swap(b'"ua":"Mozilla/5.0"', b'"ua":"raw\ttab"'), "not_json"),
    (b"[]", "not_an_object"),
    (b'"text"', "not_an_object"),
    (b"7", "not_an_object"),
    (b"null", "not_an_object"),
    (b"{}", "unexpected_fields"),
    (swap(b',"lang":"en-GB"', b""), "unexpected_fields"),
    (swap(b'"lang":', b'"extra":"1","lang":'), "unexpected_fields"),
    (swap(b'"ua":', b'"UA":'), "unexpected_fields"),
    (swap(b'"status":"200"', b'"status":"200","status":"200"'), "duplicate_field"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":"192.0.2.10","ip":"203.0.113.1"'), "duplicate_field"),
    (swap(b'"status":"200"', b'"status":200'), "field_not_a_string"),
    (swap(b'"ua":"Mozilla/5.0"', b'"ua":null'), "field_not_a_string"),
    (swap(b'"ua":"Mozilla/5.0"', b'"ua":{"a":"b"}'), "field_not_a_string"),
    (swap(b'"ua":"Mozilla/5.0"', b'"ua":["x"]'), "field_not_a_string"),
    (swap(b'"ts":"1800000000.000"', b'"ts":"1800000000"'), "bad_ts"),
    (swap(b'"ts":"1800000000.000"', b'"ts":"-1.000"'), "bad_ts"),
    (swap(b'"ts":"1800000000.000"', b'"ts":"1e9.000"'), "bad_ts"),
    (swap(b'"ts":"1800000000.000"', b'"ts":" 1800000000.000"'), "bad_ts"),
    (swap(b'"ts":"1800000000.000"', b'"ts":"1800000000.000\\n"'), "bad_ts"),
    (swap(b'"ts":"1800000000.000"', b'"ts":"999999999999.000"'), "bad_ts"),
    (swap(b'"ts":"1800000000.000"', '"ts":"\u0661\u0668.\u0660\u0660\u0660"'.encode()), "bad_ts"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":""'), "bad_ip"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":"unix:"'), "bad_ip"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":"192.0.2.10 "'), "bad_ip"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":"192.0.2.999"'), "bad_ip"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":"192.0.2.0/24"'), "bad_ip"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":"fe80::1%eth0"'), "bad_ip"),
    (swap(b'"ip":"192.0.2.10"', b'"ip":"example.com"'), "bad_ip"),
    (swap(b'"status":"200"', b'"status":"2000"'), "bad_status"),
    (swap(b'"status":"200"', b'"status":"099"'), "bad_status"),
    (swap(b'"status":"200"', b'"status":"-"'), "bad_status"),
    (swap(b'"status":"200"', b'"status":"200 OK"'), "bad_status"),
    (re.sub(rb'"request_id":"[0-9a-f]+"', b'"request_id":"ABCDEF"', GOOD), "bad_request_id"),
    (re.sub(rb'"request_id":"[0-9a-f]+"', b'"request_id":""', GOOD), "bad_request_id"),
    (re.sub(rb'"request_id":"([0-9a-f]+)"', rb'"request_id":"\1\\n"', GOOD), "bad_request_id"),
    (line(ua=b"A" * MAX_LINE_BYTES)[:-1], "line_too_long"),
]


@pytest.mark.parametrize(("raw", "reason"), FAILURES, ids=lambda v: None)
def test_every_bad_line_is_a_failure_with_a_fixed_reason(raw, reason):
    result = parse_line(raw, 4242, now_ms=NOW_MS, max_age_ms=MAX_AGE)
    assert result == ParseFailure(
        offset=4242, line_sha256=sha256_hex(raw), length=len(raw), reason=reason
    )


def test_a_failure_carries_no_line_content():
    marker = b"ATTACKER-TEXT-91c2"
    result = parse_line(b'{"ua":"' + marker + b'"}', 0, now_ms=NOW_MS, max_age_ms=MAX_AGE)
    assert isinstance(result, ParseFailure)
    assert marker.decode() not in repr(result)


def test_random_bytes_never_raise_and_never_vanish():
    rng = random.Random(20261116)  # noqa: S311 - a fixed seed for a repeatable fuzz, not a secret
    good = line()[:-1]
    for _ in range(3000):
        choice = rng.random()
        if choice < 0.3:
            raw = rng.randbytes(rng.randrange(0, 200))
        elif choice < 0.8:  # a real line with a few bytes damaged
            damaged = bytearray(good)
            for _ in range(rng.randrange(1, 4)):
                damaged[rng.randrange(len(damaged))] = rng.randrange(256)
            raw = bytes(damaged)
        else:  # a real line cut short or run together
            raw = good[: rng.randrange(len(good))] + rng.choice([b"", good, b"}", b'"'])
        raw = raw.replace(b"\n", b" ")
        result = parse_line(raw, 0, now_ms=NOW_MS, max_age_ms=MAX_AGE)
        assert isinstance(result, Record | ParseFailure)
        assert result.line_sha256 == sha256_hex(raw)


@pytest.mark.parametrize(
    ("logged", "normalized"),
    [
        ("192.0.2.1", "192.0.2.1"),
        ("::ffff:192.0.2.1", "192.0.2.1"),
        ("::FFFF:C000:0201", "192.0.2.1"),
        ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("2001:db8::0001", "2001:db8::1"),
        ("::1", "::1"),
    ],
)
def test_one_client_has_one_address_spelling(logged, normalized):
    assert parse(line(ip=logged)).ip == normalized


@pytest.mark.parametrize(
    ("age_ms", "stale"),
    [
        (0, False),
        (MAX_AGE, False),
        (MAX_AGE + 1, True),
        (86_400_000, True),
        (-MAX_AGE, False),
        (-MAX_AGE - 1, True),  # far in the future is no more trustworthy than old
    ],
)
def test_five_minute_staleness_rule(age_ms, stale):
    record = parse(line(ts_ms=NOW_MS - age_ms))
    assert isinstance(record, Record) and record.stale is stale


def test_checked_in_fixture_is_what_the_generator_builds():
    fixture = (REPO / "tests" / "fixtures" / "nginx_access.fixture").read_bytes()
    assert fixture == nginx_emu.build_fixture()
