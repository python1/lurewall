# SPDX-License-Identifier: AGPL-3.0-only
"""The lab harness against a real nginx and the real service, end to end.

A private nginx serves the built lab site on 127.0.0.1, with the shipped log
format and rate limit. Each case runs from its own loopback address (Linux
routes all of 127.0.0.0/8 to lo), so per-source state does not mix. The
service reads nginx's log after each case. At the end the checkpoint is pulled
through nginx, the results are exported, and every scripted case must come out
as the lab expects.

The engine runs with dry_run = false and the log-only adapter: decisions are
the real ones, and nothing touches a firewall. Runs in CI next to the nginx
integration tests; skipped without nginx unless LUREWALL_REQUIRE_NGINX=1.
"""

from __future__ import annotations

import contextlib
import functools
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from lurewall import anchorjob, canaries, labcases, labclient, labsite, results, service, signing

REPO = Path(__file__).resolve().parents[1]
NGINX = shutil.which("nginx") or next(
    (path for path in ("/usr/sbin/nginx", "/opt/homebrew/bin/nginx") if os.path.exists(path)), None
)
REQUIRED = os.environ.get("LUREWALL_REQUIRE_NGINX") == "1"

ENGINE = """version = 1
dry_run = false
[enforcement]
adapter = "log-only"
[block]
ttl_minutes = 1
[sources]
allowlist = ["127.0.0.7"]
log_only_ranges = ["127.0.0.18/32"]
"""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _loopback_aliases_work() -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.2", 0))
        except OSError:
            return False
    return True


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if NGINX is None:
        if REQUIRED:
            pytest.fail("LUREWALL_REQUIRE_NGINX=1 but nginx is not installed")
        pytest.skip("nginx is not installed")
    if not _loopback_aliases_work():
        if REQUIRED and sys.platform.startswith("linux"):
            pytest.fail("cannot send from 127.0.0.2 on this Linux host")
        pytest.skip("this host cannot send from loopback addresses other than 127.0.0.1")

    base = tmp_path_factory.mktemp("lab-e2e")
    port = _free_port()
    key = base / "keys" / "lurewall.key"
    key.parent.mkdir()
    signer = signing.EurekaSigner.generate(key)
    canary_set = canaries.generate(labsite.site_routes(), rng=random.Random(808))
    canaries.save_state(canary_set, base / "canaries.json")
    checkpoint = base / "checkpoint" / "checkpoint.json"
    checkpoint.parent.mkdir()
    site = labsite.build(
        canary_set, base / "site", listen=f"127.0.0.1:{port}", checkpoint_file=str(checkpoint)
    )
    log_conf = (REPO / "deploy" / "nginx" / "lurewall-log.conf").read_text()
    log_conf = log_conf.replace("/var/log/nginx/lurewall.json.log", str(base / "access.log"))
    conf = base / "nginx.conf"
    conf.write_text(
        "daemon off;\nmaster_process off;\nworker_processes 1;\n"
        f"pid {base}/nginx.pid;\nerror_log {base}/error.log info;\n"
        "events { worker_connections 256; }\n"
        "http {\n"
        "    types { text/html html; text/css css; text/plain txt; text/xml xml;"
        " image/svg+xml svg; }\n"
        "    default_type application/octet-stream;\n"
        + "".join(
            f"    {kind}_temp_path {base}/{kind}-temp;\n"
            for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        + f"{log_conf}\n    include {site.nginx_conf};\n}}\n"
    )
    (base / "access.log").touch()
    (base / "engine.toml").write_text(ENGINE)
    command = [NGINX, "-e", str(base / "error.log"), "-p", str(base), "-c", str(conf)]
    out = open(base / "nginx.out", "wb")  # noqa: SIM115 - closed below
    process = subprocess.Popen(command, stdout=out, stderr=subprocess.STDOUT)  # noqa: S603
    running = None
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                pytest.fail("nginx exited at startup: " + (base / "error.log").read_text())
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.2):
                break
            if time.monotonic() > deadline:
                pytest.fail("nginx did not start listening")
            time.sleep(0.05)
        paths = service.Paths(
            access_log=base / "access.log",
            reader_state=base / "reader.state",
            event_log=base / "events.log",
            key=key,
            canaries=base / "canaries.json",
            signals=REPO / "deploy" / "signals" / "lab-site.toml",
            engine_config=base / "engine.toml",
            engine_state=base / "engine.json",
            checkpoint=checkpoint,
        )
        running = service.Service(paths, fsync=False)
        yield {
            "base": base,
            "port": port,
            "service": running,
            "paths": paths,
            "signer": signer,
            "target": labclient.parse_target(f"http://127.0.0.1:{port}"),
        }
    finally:
        if running is not None:
            with contextlib.suppress(ValueError):
                running.close()
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)
        if process.poll() is None:
            process.kill()
            process.wait()
        out.close()


def drain(running) -> None:
    """Let nginx finish writing, then have the service read everything."""
    quiet = 0
    while quiet < 3:
        time.sleep(0.15)
        quiet = quiet + 1 if running.step() == 0 else 0


def run(lab, ledger, number, source, **kwargs):
    sender = functools.partial(labclient.socket_sender, bind=source)
    ctx = labcases.Context(
        client=labclient.Client(lab["target"], sender, pause_s=0.12),
        source=source,
        ask=lambda _prompt: "",
        say=lambda _text: None,
        **kwargs,
    )
    record = labcases.run_case(labcases.CASES[number], ctx)
    labcases.append_run(ledger, record)
    drain(lab["service"])
    return record


def test_the_scripted_cases_come_out_as_the_lab_expects(lab):
    ledger = lab["base"] / "runs.jsonl"
    target = lab["target"]

    # Case 2 first: its block must expire (TTL 1 minute) before the end.
    blocked_at = time.monotonic()
    run(lab, ledger, 2, "127.0.0.2", scripted=True)
    run(lab, ledger, 3, "127.0.0.3")
    run(lab, ledger, 7, "127.0.0.7")

    framed: list[bytes] = []

    def browser(page: bytes) -> None:
        # What a browser does with the case-8 page: fetch each image with the
        # page's origin as Referer.
        framed.append(page)
        client = labclient.Client(
            target, functools.partial(labclient.socket_sender, bind="127.0.0.8"), pause_s=0
        )
        for url in re.findall(rb'src="([^"]+)"', page):
            path = url.decode().split(str(lab["port"]), 1)[1]
            client.get(path, headers=[("Referer", "http://127.0.0.1:8765/")])

    run(lab, ledger, 8, "127.0.0.8", serve_page=browser)
    assert framed
    run(lab, ledger, 9, "127.0.0.9")
    served = run(lab, ledger, 10, "127.0.0.10", part="serve")
    assert served["reference"]
    run(lab, ledger, 10, "127.0.0.11", part="hit", reference=served["reference"])
    run(lab, ledger, 12, "127.0.0.12", part="read")
    run(lab, ledger, 12, "127.0.0.13", part="probe")
    flood = run(lab, ledger, 15, "127.0.0.15")
    assert flood["statuses"].get("429", 0) > 100  # the shipped limit_req, for real
    run(lab, ledger, 16, "127.0.0.16")
    run(lab, ledger, 17, "127.0.0.17")
    run(lab, ledger, 18, "127.0.0.18", scripted=True)

    # Wait out case 2's block, then let the engine expire it.
    while time.monotonic() - blocked_at < 65:
        time.sleep(1)
        lab["service"].step()
    drain(lab["service"])
    lab["service"].close()

    repo = lab["base"] / "anchors"
    pulled = anchorjob.pull(
        f"http://127.0.0.1:{lab['port']}{labsite.CHECKPOINT_ROUTE}",
        lab["signer"].public_key_hex,
        repo,
    )
    assert pulled.status == "stored"

    report, rows, written = results.export(
        lab["paths"].event_log,
        lab["signer"].public_key_hex,
        [repo / "checkpoints"],
        labcases.read_runs(ledger),
        lab["base"] / "results",
    )
    assert report.ok and report.anchors_matched == 1 and written
    verdicts = {(row.run["case"], row.run.get("part", "")): row for row in rows}
    expected = {
        (2, ""): results.PASS,
        (3, ""): results.PASS,
        (7, ""): results.PASS,
        (8, ""): results.PASS,
        (9, ""): results.PASS,
        (10, "serve"): results.RECORD,
        (10, "hit"): results.PASS,
        (12, "read"): results.RECORD,
        (12, "probe"): results.LIMIT,
        (15, ""): results.PASS,
        (16, ""): results.RECORD,
        (17, ""): results.PASS,
        (18, ""): results.PASS,
    }
    got = {key: (row.verdict, row.why) for key, row in verdicts.items()}
    assert {key: verdict for key, (verdict, _) in got.items()} == expected, got
    # Case 16: nothing vanished. Every hostile request reached the reader as a
    # record or a parse_failure.
    assert verdicts[(16, "")].counts["parse_failure"] == 0
    assert "0 parse failures for 8 requests" in verdicts[(16, "")].why
    hostile_lines = [
        line
        for line in (lab["base"] / "access.log").read_bytes().splitlines()
        if b'"ip":"127.0.0.16"' in line
    ]
    assert len(hostile_lines) == len(labclient.HOSTILE)
