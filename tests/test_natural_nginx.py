# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the shipped renderer, signed detector, report and rollback on private fixtures."""

import contextlib
import http.client
import json
import re
import socket
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lurewall import canaries, cli, labcases, naturalsite, service, signing
from test_lab_e2e import NGINX, REQUIRED, _free_port

ROOT = Path(__file__).resolve().parents[1]
HOST = "static.example.test"


def site(tmp_path):
    root = tmp_path / "public"
    root.mkdir()
    (root / "index.html").write_text("<html><body><footer>Library</footer></body></html>\n")
    wordlist = tmp_path / "words"
    wordlist.write_text(
        "velvet copper winter library village lantern meadow walnut\n"
        "thistle olive willow bronze morning coral timber notebook"
    )
    return root, wordlist


def build(tmp_path, root, wordlist, **opts):
    args = {
        "state": tmp_path / "legacy.json",
        "site_root": root,
        "out": tmp_path / "private",
        "host": HOST,
        "listen": "80",
        "wordlist": wordlist,
        "placements": "footer",
        "deploy_root": None,
        "checkpoint": None,
    }
    return naturalsite.build(**(args | opts))


def test_profile_uses_site_inventory_preserves_resources_and_legacy_state(tmp_path):
    root, wordlist = site(tmp_path)
    original = (root / "index.html").read_bytes()
    (root / "sitemap.xml").write_text(
        f"<urlset><url><loc>https://{HOST}/guides/early-harvest.html</loc></url></urlset>"
    )
    words, _, styles = naturalsite._inputs(root, HOST, wordlist)
    assert "harvest" in words and "/W/W-W.html" in styles
    conf = build(tmp_path, root, wordlist, placements="footer,robots,security")
    assert (root / "index.html").read_bytes() == original
    loc = (conf.parent / "lurewall-natural-locations.conf").read_text()
    assert "robots" not in loc and "security" not in loc
    assert not (root / "robots.txt").exists()
    legacy = tmp_path / "legacy.json"
    assert canaries.load_state(legacy).version == canaries.STATE_VERSION
    assert canaries.load_state(canaries.natural_state_path(legacy)).version == 3
    assert (conf.parent / "natural.js").stat().st_mode & 0o777 == 0o600


def test_robots_and_security_preserve_content_and_only_extend_valid_unsigned_files(tmp_path):
    root, _words = site(tmp_path)
    (root / "robots.txt").write_bytes(b"User-agent: *\r\nallow:  /\r\n")
    rules = naturalsite._carrier("robots", root)
    assert rules["before"].endswith("\r\ndisallow:  ") and rules["after"] == "\r\n"
    policy = root / ".well-known/security.txt"
    policy.parent.mkdir()
    valid = (
        "Contact: mailto:team@example.test\nExpires: "
        + (datetime.now(UTC) + timedelta(days=30)).isoformat(timespec="seconds")
        + "\n"
    )
    policy.write_text(valid)
    assert naturalsite._carrier("security", root)["before"].startswith(valid)
    for invalid in (
        "",
        "# only\n",
        "-----BEGIN PGP SIGNED MESSAGE-----\n" + valid,
        valid.replace("Expires", "Until"),
    ):
        policy.write_text(invalid)
        assert naturalsite._carrier("security", root) is None


def test_real_njs_pair_reuses_path_and_report_is_script_free(tmp_path, capsys):
    mod = Path("/usr/lib/nginx/modules/ngx_http_js_module.so")
    if not NGINX or not mod.is_file():
        if REQUIRED:
            pytest.fail("nginx and libnginx-mod-http-js required")
        pytest.skip("requires nginx with its njs HTTP module")
    root, words = site(tmp_path)
    (root / "robots.txt").write_text("User-agent: *\nDisallow: /unused/\n")
    port = _free_port()
    config = build(tmp_path, root, words, listen=f"127.0.0.1:{port}", placements="footer,robots")
    access = tmp_path / "access.log"
    server = config.read_text().replace("/var/log/lurewall/access.jsonl", str(access))
    server = server.replace(
        "    location / {", "    error_page 404 /missing.html;\n    location / {"
    )
    (root / "missing.html").write_text("Fixture missing page")
    temp_dirs = "".join(
        f"{kind}_temp_path {tmp_path}/{kind};\n"
        for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
    )
    nginx_config = tmp_path / "nginx.conf"
    nginx_config.write_text(
        f"load_module {mod};\ndaemon off; master_process off;\n"
        f"pid {tmp_path}/pid; error_log {tmp_path}/errors;\n"
        f"events {{ worker_connections 128; }}\nhttp {{ {temp_dirs}"
        f"include {config.parent}/lurewall-natural-format.conf;\n{server}\n}}"
    )
    paths = service.Paths(
        access_log=access,
        reader_state=tmp_path / "reader",
        event_log=tmp_path / "events",
        key=tmp_path / "keys/signer",
        canaries=tmp_path / "legacy.json",
        signals=ROOT / "deploy/signals/lab-site.toml",
        engine_config=ROOT / "deploy/engine/lab.toml",
        engine_state=tmp_path / "engine.json",
        checkpoint=tmp_path / "checkpoint",
    )
    paths.key.parent.mkdir()
    signer = signing.EurekaSigner.generate(paths.key)
    running = service.Service(paths, fsync=False)

    def get(path, source, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3, source_address=(source, 0))
        try:
            conn.request("GET", path, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    process = subprocess.Popen(  # noqa: S603
        [NGINX, "-e", "stderr", "-p", str(tmp_path), "-c", str(nginx_config)]
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail("nginx failed to start with the generated modules")
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.1):
                break
            time.sleep(0.05)
        source_a, source_b = "127.0.0.2", "127.0.0.3"
        status, headers, body = get("/", source_a)
        match = re.search(rb"<!-- (/[^ ?]+) -->", body)
        assert status == 200 and match, "natural carrier must contain an issued local path"
        ref = match[1].decode()
        assert get("/", source_a)[1]["ETag"] == headers["ETag"]
        assert get("/", source_a)[2] == body and "Last-Modified" in headers
        assert get("/", source_a, {"If-None-Match": headers["ETag"]})[0] == 304
        assert (
            get(ref, source_b)[::2]
            == get("/fixture-missing", source_b)[::2]
            == (404, b"Fixture missing page")
        )
        for route in labcases.SWITCH_PROBES:
            get(route, source_b)
        running.step()
        running.close()
        running = None
        data = [json.loads(line) for line in paths.event_log.read_text().splitlines()]
        assert any(
            event["type"] == "canary_relayed"
            and event["source"] == source_b
            and event["detail"]["issued_to"] == source_a
            for event in data
        )
        assert not {e["type"] for e in data} & {"block", "would_block", "block_applied"}
        assert (
            cli.main(
                [
                    "report",
                    "--html",
                    "--since",
                    "10m",
                    "--event-log",
                    str(paths.event_log),
                    "--pubkey",
                    signer.public_key_hex,
                ]
            )
            == 0
        )
        output = capsys.readouterr().out
        assert "Possible IP switch" in output and ref not in output and "<script" not in output
    finally:
        process.terminate()
        process.wait(timeout=10)
        if running is not None:
            running.close()
