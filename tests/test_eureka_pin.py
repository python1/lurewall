# SPDX-License-Identifier: AGPL-3.0-only
"""The eureka dependency is the pinned commit, and nothing else will load."""

import json
import subprocess
import sys
from pathlib import Path

from lurewall import _eureka, signing

REPO = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(REPO), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def test_pin_is_a_full_40_character_sha():
    assert len(_eureka.EUREKA_COMMIT) == 40
    assert _eureka.EUREKA_COMMIT == "7f29b208d1da54ebf5963e9b409f79d483979f74"


def test_superproject_records_the_pinned_commit():
    mode, sha, _stage, path = _git("ls-files", "-s", str(_eureka.SUBMODULE_PATH)).split()
    assert (mode, sha, path) == ("160000", _eureka.EUREKA_COMMIT, "third_party/eureka_protocol")


def test_submodule_checkout_is_the_pinned_commit():
    head = _git("-C", str(_eureka.SUBMODULE_PATH), "rev-parse", "HEAD").strip()
    assert head == _eureka.EUREKA_COMMIT


def test_submodule_url_is_the_eureka_repo():
    url = _git("config", "-f", ".gitmodules", "submodule.third_party/eureka_protocol.url").strip()
    assert url == "https://github.com/python1/eureka_protocol.git"


def _import_with_crypto_at(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", "import lurewall._eureka"],
        env={"PATH": "", _eureka.CRYPTO_PATH_ENV_VAR: str(path)},
        capture_output=True,
        text=True,
    )


def test_modified_signing_code_is_refused(tmp_path):
    tampered = tmp_path / "crypto.py"
    tampered.write_bytes(_eureka.crypto_path().read_bytes() + b"\n# one byte more\n")
    result = _import_with_crypto_at(tampered)
    assert result.returncode != 0
    assert "not the pinned version" in result.stderr


def test_missing_signing_code_is_a_clear_error(tmp_path):
    result = _import_with_crypto_at(tmp_path / "absent.py")
    assert result.returncode != 0
    assert "git submodule update --init" in result.stderr


def test_exact_copy_elsewhere_loads(tmp_path):
    copy = tmp_path / "crypto.py"
    copy.write_bytes(_eureka.crypto_path().read_bytes())
    assert _import_with_crypto_at(copy).returncode == 0


def test_only_the_signing_module_is_loaded():
    code = (
        "import sys, lurewall.signing;"
        "bad = [m for m in sys.modules if m.split('.')[0] in"
        " ('fastapi', 'uvicorn', 'httpx', 'eureka_daemon')];"
        "sys.exit(1 if bad else 0)"
    )
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0  # noqa: S603


def test_agrees_with_eurekas_published_signature_vectors():
    """The loaded code produces eureka's published bytes and accepts its signatures."""
    document = json.loads(
        (REPO / _eureka.SUBMODULE_PATH / "vectors" / "signatures-v1.json").read_text()
    )
    vectors = document["vectors"]
    assert len(vectors) >= 5
    for vector in vectors:
        tag = vector["domain_tag"].encode()
        signed = tag + b"\x00" + _eureka.canonical_json_bytes(vector["payload"])
        assert signed.hex() == vector["signed_bytes_hex"]
        assert _eureka.EurekaCrypto.verify_json(
            document["public_key"], vector["signature"], vector["payload"], tag
        )


def test_lurewall_domains_are_not_eureka_domains(signer):
    crypto = _eureka.EurekaCrypto()
    payload = {"seq": 1}
    audit_sig = crypto.sign_audit_log(payload)
    key = crypto.get_public_key_hex()
    assert _eureka.EurekaCrypto.verify_audit_log(key, audit_sig, payload)
    assert not signing.verify(key, audit_sig, payload, signing.DOMAIN_EVENT)
    assert not signing.verify(key, audit_sig, payload, signing.DOMAIN_CHECKPOINT)

    event_sig = signer.sign(payload, signing.DOMAIN_EVENT)
    assert signing.verify(signer.public_key_hex, event_sig, payload, signing.DOMAIN_EVENT)
    assert not signing.verify(signer.public_key_hex, event_sig, payload, signing.DOMAIN_CHECKPOINT)
