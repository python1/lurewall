# SPDX-License-Identifier: AGPL-3.0-only
import base64
import json
import secrets
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from lurewall import agentfeeds, agentfetch, cli, identitylab, webbotauth
from lurewall.accesslog import parse_line
from lurewall.identitylab import HOST, SIGNER, log_fields, observe, sign_fields

NOW = 1800000000
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def lab(tmp_path):
    obs, key, kid = identitylab.fixture(tmp_path, NOW)
    return obs, key, kid


def test_offline_lab(capsys):
    assert cli.main(["lab", "identity"]) == 0
    assert "Replay: indeterminate" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("authoritative", "address", "wanted"),
    [
        (False, "192.0.2.8", "indeterminate"),
        (True, "192.0.2.8", "impersonation"),
        (True, "2001:db8::1", "indeterminate"),
        (False, "198.51.100.1", "verified"),
    ],
)
def test_unsigned_range_policy(lab, authoritative, address, wanted):
    obs, _, _ = lab
    obs.settings.feeds["ranges"] = replace(
        obs.settings.feeds["ranges"], authoritative=authoritative
    )
    row = observe(obs, {**log_fields(NOW), "ip": address}, NOW)
    assert row["verdict"] == wanted and row["counted"] is False


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("bad", "bad_signature"),
        ("other", "foreign_signer"),
        ("unknown", "unknown_kid"),
        ("expired", "expired"),
        ("lossy", "ingress_unconfirmed"),
        ("missing", "replay_store_unavailable"),
        ("corrupt", "replay_store_unavailable"),
        ("mismatch", "key_mismatch"),
        ("nothing", "signature"),
    ],
)
def test_signature_outcomes(lab, change, reason):
    obs, key, kid = lab
    fields = log_fields(NOW)
    sign_fields(fields, NOW - 241 if change == "expired" else NOW, key, kid)
    fields["ua"] = "LabBot"
    if change == "bad":
        fields["signature"] = "lab=:" + base64.b64encode(bytes(64)).decode() + ":"
    if change == "other":
        fields["signature_agent"] = 'lab="https://foreign.example"'
    if change == "unknown":
        fields["signature_input"] = fields["signature_input"].replace(kid, secrets.token_hex(9))
    if change == "lossy":
        fields["authority"] = "proxy.example"
    if change == "missing":
        obs.replay.unlink()
    if change == "corrupt":
        obs.replay.write_bytes(b"broken")
    if change == "mismatch":
        obs.settings.feeds["lab"] = replace(obs.settings.feeds["lab"], thumbprint=True)
    row = observe(obs, fields, NOW)
    assert reason in (row["reason"], row.get("signature_result"))
    assert row["verdict"] == (
        {"bad": "impersonation", "expired": "impersonation", "nothing": "verified"}.get(
            change, "indeterminate"
        )
    )
    assert row["counted"] is False
    if change == "bad":
        fields["ip"] = "198.51.100.5"
        assert observe(obs, fields, NOW)["reason"] == "ip_range"


def test_snapshot_rotation_refresh_and_outage(tmp_path, lab):
    obs, key, _ = lab
    config = obs.config
    config.write_text(
        "\n".join(
            line
            for line in config.read_text().splitlines()
            if not line.startswith(("sha256", "pin_until"))
        )
    )
    obs.settings = agentfeeds.settings(config)
    cache = tmp_path / "cache"
    requests = tmp_path / "requests"
    cache.mkdir()
    requests.mkdir()
    obs.cache, obs.requests = cache, requests
    calls = []

    def download(feed):
        calls.append(feed.name)
        return (tmp_path / "pins" / (feed.name + ".json")).read_bytes(), 3600

    def run(at, fetch=download):
        return agentfetch.refresh(config, cache, requests, fetch=fetch, clock=lambda: at)

    assert run(NOW) == 0 and len(calls) == 2
    fields = log_fields(NOW)
    sign_fields(fields, NOW, key, secrets.token_hex(4))
    assert observe(obs, fields, NOW)["reason"] == "unknown_kid"
    assert (requests / "lab").is_file()
    import os

    os.utime(requests / "lab", (NOW + 1, NOW + 1))
    assert run(NOW + 30) == 0 and len(calls) == 2
    old = (cache / "lab.json").read_bytes()

    def unavailable(_):
        raise TimeoutError

    assert run(NOW + 61, unavailable) == 0 and (cache / "lab.json").read_bytes() == old
    assert run(NOW + 7 * 3600, unavailable) == 1
    fields["ts"] = f"{NOW + 7 * 3600}.010"
    assert observe(obs, fields, NOW + 7 * 3600)["reason"] == "key_unavailable"
    (tmp_path / "pins/lab.json").write_text('{"keys":[]}')
    assert run(NOW + 8 * 3600) == 0
    assert obs.snapshot(obs.settings.feeds["lab"], NOW + 8 * 3600)[0] == {}


def test_published_range_scope():
    cfg = agentfeeds.settings(ROOT / "deploy/operator/agents.example.toml")
    assert {f.name for f in cfg.feeds.values() if f.authoritative} == {
        "common-crawlers",
        "special-crawlers",
        "user-triggered-agents",
    }
    assert cfg.claims["Claude-User"] == cfg.claims["ClaudeBot"] == cfg.claims["Claude-SearchBot"]
    assert cfg.claims["MistralAI-Training"] == {}
    assert cfg.claims["Google-Agent"]["keys"] == "google-agent"
    for feed in cfg.feeds.values():
        assert feed.limit >= 256 * 1024


def test_mixed_dns_rejected_before_connect(lab, monkeypatch):
    import socket
    import ssl

    obs, _, _ = lab
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", ("::1", 443))])
    monkeypatch.setattr(ssl, "create_default_context", lambda: pytest.fail("unsafe destination"))
    with pytest.raises(ValueError, match="nonpublic"):
        agentfetch.download(obs.settings.feeds["lab"])


@pytest.mark.parametrize("alg", ["rsa", "ed"])
def test_published_key_validity_and_rsa_pss(lab, alg):
    obs, key, kid = lab
    f = log_fields(NOW)
    sign_fields(f, NOW, key, kid)
    feed = obs.settings.feeds["lab"]
    keys, _ = obs.snapshot(feed, NOW)
    keys[kid].update(nbf=NOW - 1, exp=NOW + 1)
    if alg == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()

        def enc(num):
            return (
                base64.urlsafe_b64encode(num.to_bytes((num.bit_length() + 7) // 8, "big"))
                .decode()
                .rstrip("=")
            )

        keys[kid].update(kty="RSA", n=enc(numbers.n), e=enc(numbers.e))
        params = f["signature_input"].split("=", 1)[1]
        base = (
            f'"@authority": {HOST}\n"signature-agent";key="lab": "{SIGNER}"\n'
            f'"@signature-params": {params}'
        )
        signed = key.sign(
            base.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64),
            hashes.SHA512(),
        )
        f["signature"] = "lab=:" + base64.b64encode(signed).decode() + ":"
    assert observe(obs, f, NOW)["reason"] == "signature"
    keys[kid]["exp"] = NOW
    assert observe(obs, f, NOW)["reason"] == "key_outside_validity"
    keys[kid].update(nbf=NOW + 1, exp=NOW + 2)
    assert observe(obs, f, NOW)["reason"] == "key_outside_validity"


def test_legacy_draft_vector(lab):
    # draft-ietf-webbotauth-httpsig-protocol-01 Appendix E.2.2; public RFC 9421 test key.
    obs, _, _ = lab
    now = 1735689600
    keyspec = {"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
    kid = agentfeeds.thumb(keyspec)
    feed = replace(
        obs.settings.feeds["lab"], signer="https://signature-agent.test", thumbprint=True
    )
    f = log_fields(now)
    f.update(
        authority="example.com",
        signature_agent='"https://signature-agent.test"',
        signature_input=(
            'sig2=("@authority" "signature-agent");created=1735689600;'
            f'keyid="{kid}";alg="ed25519";expires=1735693200;'
            'nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7'
            'DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"'
        ),
        signature=(
            "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZD"
            "si6nJKuHxUi/5Syp3rLWBA==:"
        ),
    )
    row = parse_line(json.dumps(f).encode(), 0, now_ms=now * 1000, max_age_ms=1000)
    assert webbotauth.check(row, feed, {kid: keyspec}, obs.replay, now) == "valid"


def test_missing_signature_components_on_authoritative_claim_are_inconclusive(lab):
    obs, key, kid = lab
    obs.settings.feeds["ranges"] = replace(obs.settings.feeds["ranges"], authoritative=True)
    f = log_fields(NOW)
    sign_fields(f, NOW, key, kid)
    f.update(ua="LabBot", signature_input="")
    assert observe(obs, f, NOW)["verdict"] == "indeterminate"


def test_no_unpublished_identifier_fallback_or_signal_count_setting(tmp_path, lab):
    obs, _, _ = lab
    feed = replace(obs.settings.feeds["lab"], thumbprint=True)
    raw = json.loads((tmp_path / "pins/lab.json").read_bytes())
    del raw["keys"][0]["kid"]
    with pytest.raises(ValueError, match="identifier"):
        agentfeeds.parse_feed(feed, json.dumps(raw))
    obs.config.write_text(obs.config.read_text() + "\ncount_toward_block = true\n")
    with pytest.raises(ValueError, match="claim policy"):
        agentfeeds.settings(obs.config)


def test_signature_overflow_preserves_independent_range_credit(lab):
    obs, _, _ = lab
    fields = {**log_fields(NOW), "ua": "LabBot", "signature": "!overflow"}
    assert observe(obs, fields, NOW)["verdict"] == "indeterminate"
    fields["ip"] = "198.51.100.10"
    row = observe(obs, fields, NOW)
    assert row["reason"] == "ip_range" and row["signature_result"] == "capture_overflow"
