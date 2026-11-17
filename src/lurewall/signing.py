# SPDX-License-Identifier: AGPL-3.0-only
"""Signing for the event log, on top of eureka-daemon's Ed25519 scheme.

A signature covers ``domain tag + NUL + canonical JSON``. Lurewall uses its own
tags, so a log entry, a checkpoint and any eureka protocol message can never be
passed off as one another, even under the same key.

The log writer is handed a ``Signer``: something that can sign and can state
its public key. It never sees private key bytes.
"""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from typing import Protocol

from lurewall import _eureka
from lurewall.canonical import check_value

DOMAIN_EVENT = b"lurewall/event/v1"
DOMAIN_CHECKPOINT = b"lurewall/checkpoint/v1"

_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_BYTES = 64

KeyFileError = _eureka.IdentityError


class Signer(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, payload: dict, domain: bytes) -> str: ...


class EurekaSigner:
    """A signing interface over an eureka identity file (mode 0600, outside the repo)."""

    def __init__(self, crypto: _eureka.EurekaCrypto) -> None:
        self._crypto = crypto

    @classmethod
    def load(cls, path: str | Path) -> EurekaSigner:
        """Load an existing key. Never creates one: a typo must not mint a new identity."""
        return cls(_eureka.EurekaCrypto.load(Path(path)))

    @classmethod
    def generate(cls, path: str | Path) -> EurekaSigner:
        """Create a new key file. Refuses to overwrite an existing one."""
        crypto = _eureka.EurekaCrypto()
        crypto.save(Path(path))
        return cls(crypto)

    @classmethod
    def ephemeral(cls) -> EurekaSigner:
        """An in-memory key that is never written anywhere. For tests."""
        return cls(_eureka.EurekaCrypto())

    @property
    def public_key_hex(self) -> str:
        return self._crypto.get_public_key_hex()

    def sign(self, payload: dict, domain: bytes) -> str:
        check_value(payload)
        return self._crypto.sign_json(payload, domain=domain)

    def __repr__(self) -> str:  # never print key material
        return f"EurekaSigner(public_key_hex={self.public_key_hex!r})"


def is_public_key_hex(value: object) -> bool:
    return type(value) is str and _PUBLIC_KEY_RE.fullmatch(value) is not None


def is_signature(value: object) -> bool:
    """True for the one canonical base64 spelling of a 64-byte signature.

    Base64 has several spellings for the same bytes. Accepting only the
    canonical one means a signature cannot be re-spelled to change a line's
    hash without changing what it says.
    """
    if type(value) is not str:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == _SIGNATURE_BYTES and base64.b64encode(raw).decode("ascii") == value


def verify(public_key_hex: str, signature: object, payload: dict, domain: bytes) -> bool:
    """True only if ``signature`` is this key's signature of ``payload`` in ``domain``."""
    if not is_public_key_hex(public_key_hex) or not is_signature(signature):
        return False
    check_value(payload)
    return _eureka.EurekaCrypto.verify_json(public_key_hex, signature, payload, domain=domain)


def read_public_key(text: str) -> str:
    """Accept a public key as 64 hex characters, or as a path to a file holding them."""
    candidate = text.strip().lower()
    if not is_public_key_hex(candidate):
        try:
            candidate = Path(text).read_text(encoding="ascii").strip().lower()
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise ValueError("public key is neither 64 hex characters nor a readable file") from exc
    if not is_public_key_hex(candidate):
        raise ValueError("public key file does not hold 64 hex characters")
    return candidate
