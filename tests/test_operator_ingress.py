# SPDX-License-Identifier: AGPL-3.0-only
"""Ingress and rule scope for the operator deployment."""

import ipaddress
import json
import re
from pathlib import Path

import pytest

import nginx_emu
import sig
from fake_nft import FakeNft
from lurewall import accesslog, labsite
from lurewall.nft import NftAdapter
from lurewall.sources import source_key

REPO = Path(__file__).resolve().parents[1]
PEER = "192.0.2.10"
CLIENT = "198.51.100.20"
TRUSTED = (ipaddress.ip_network("192.0.2.0/28"), ipaddress.ip_network("2001:db8:2::/64"))


def parse(peer, forwarded, *, trusted=TRUSTED):
    fields = json.loads(nginx_emu.line(ip=peer))
    fields["forwarded_for"] = forwarded
    return accesslog.parse_line(
        json.dumps(fields).encode(),
        0,
        now_ms=nginx_emu.NOW_MS,
        max_age_ms=1000,
        require_peer_log=True,
        trusted_proxies=trusted,
    )


def test_operator_format_matches_parser_and_records_original_peer():
    text = (REPO / "deploy" / "nginx" / "operator-format.conf").read_text()
    assert tuple(re.findall(r'"(\w+)":"\$', text)) == accesslog.OPERATOR_FIELDS
    assert '"ip":"$realip_remote_addr"' in text
    assert '"forwarded_for":"$http_x_forwarded_for"' in text
    assert re.search(r"^\s*access_log\s", text, re.MULTILINE) is None


def test_untrusted_or_unconfigured_peers_cannot_choose_their_address():
    assert parse(CLIENT, PEER).ip == CLIENT
    assert parse(PEER, CLIENT, trusted=()).ip == PEER


def test_forwarding_stops_at_first_untrusted_hop_and_aggregates_ipv6():
    client = "2001:db8:9::42"
    parsed = parse(PEER, f"192.0.2.100, {client}, 2001:db8:2::2")
    assert parsed.ip == client
    assert source_key(parsed.ip) == "2001:db8:9::/64"


@pytest.mark.parametrize(
    "chain", ["-", "2001:db8:2::2", f"{CLIENT}, invalid", CLIENT + ",", CLIENT + " " * 4096]
)
def test_unusable_forwarding_falls_back_to_the_original_peer(chain):
    assert parse(PEER, chain).ip == PEER


def test_operator_requires_peer_format_and_legacy_reader_still_accepts_its_format():
    raw = nginx_emu.line().rstrip(b"\n")
    kwargs = {"now_ms": nginx_emu.NOW_MS, "max_age_ms": 1000}
    assert isinstance(accesslog.parse_line(raw, 0, **kwargs), accesslog.Record)
    failure = accesslog.parse_line(raw, 0, require_peer_log=True, **kwargs)
    assert failure.reason == "peer_log_required"


def test_operator_vhost_logs_only_for_explicit_host(tmp_path):
    out = tmp_path / "site"
    result = labsite.build(sig.canary_set(), out, server_name="canary.example.test")
    text = result.nginx_conf.read_text()
    assert "server_name canary.example.test;" in text
    assert "access_log /var/log/lurewall/access.jsonl lurewall_operator;" in text
    with pytest.raises(labsite.BuildError, match="exact DNS name"):
        labsite.build(sig.canary_set(), out, server_name="*.example.test")
    with pytest.raises(labsite.BuildError, match="listen address or port"):
        labsite.build(
            sig.canary_set(), out, server_name="canary.example.test", listen="80 default_server"
        )
    assert result.nginx_conf.read_text() == text


def test_operator_nftables_rules_scope_both_families_to_explicit_tcp_ports():
    fake = FakeNft(lambda: nginx_emu.NOW_MS)
    adapter = NftAdapter(fake, dry_run=False, tcp_ports=(443, 80))
    adapter.reconcile({})
    assert len(fake.rules) == 2
    assert all("tcp dport { 80, 443 } counter drop" in rule for rule in fake.rules)
