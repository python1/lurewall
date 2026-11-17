# SPDX-License-Identifier: AGPL-3.0-only
"""Loads eureka-daemon's signing module from the pinned git submodule.

eureka_protocol ships no packaging metadata, so it cannot be a pip dependency.
It is a git submodule at ``third_party/eureka_protocol``, pinned to
``EUREKA_COMMIT``. Git pins the commit; this loader also pins the exact bytes of
the one file Lurewall runs, so a submodule that was moved, or a file that was
edited in place, fails closed instead of silently signing with different code.

Only ``crypto.py`` is loaded. It imports nothing but the standard library and
``cryptography``, so none of the daemon's network code comes along.
"""

from __future__ import annotations

import hashlib
import os
import sys
import types
from pathlib import Path

EUREKA_COMMIT = "7f29b208d1da54ebf5963e9b409f79d483979f74"
EUREKA_CRYPTO_SHA256 = "8e629e7898afb1b744ff5a05023e2ee93a3aff2b01c7405ba399f3333e3cd1f5"

SUBMODULE_PATH = Path("third_party") / "eureka_protocol"
_CRYPTO_REL = SUBMODULE_PATH / "src" / "eureka_daemon" / "crypto.py"
_MODULE_NAME = "lurewall._eureka_crypto"

# Lets an install that is not a source checkout say where the file is. The
# content hash is checked either way, so this cannot swap in different code.
CRYPTO_PATH_ENV_VAR = "LUREWALL_EUREKA_CRYPTO"


def crypto_path() -> Path:
    override = os.environ.get(CRYPTO_PATH_ENV_VAR)
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / _CRYPTO_REL


def _load() -> types.ModuleType:
    path = crypto_path()
    try:
        source = path.read_bytes()
    except OSError as exc:
        raise ImportError(
            f"eureka signing code not found at {path}. Lurewall runs from a git checkout "
            "with its submodule fetched (`git submodule update --init`). Otherwise point "
            f"{CRYPTO_PATH_ENV_VAR} at eureka_daemon/crypto.py from commit {EUREKA_COMMIT}."
        ) from exc
    digest = hashlib.sha256(source).hexdigest()
    if digest != EUREKA_CRYPTO_SHA256:
        raise ImportError(
            f"eureka signing code at {path} is not the pinned version "
            f"(sha256 {digest}, expected {EUREKA_CRYPTO_SHA256}, commit {EUREKA_COMMIT}). "
            "Refusing to load it."
        )
    module = types.ModuleType(_MODULE_NAME)
    module.__file__ = str(path)
    # Compile the bytes that were just hashed, rather than importing the path
    # again, so the code that runs is exactly the code that was checked.
    exec(compile(source, str(path), "exec"), module.__dict__)  # noqa: S102
    sys.modules[_MODULE_NAME] = module
    return module


_crypto = _load()

EurekaCrypto = _crypto.EurekaCrypto
IdentityError = _crypto.IdentityError
canonical_json_bytes = _crypto.canonical_json_bytes

__all__ = [
    "CRYPTO_PATH_ENV_VAR",
    "EUREKA_COMMIT",
    "EUREKA_CRYPTO_SHA256",
    "SUBMODULE_PATH",
    "EurekaCrypto",
    "IdentityError",
    "canonical_json_bytes",
    "crypto_path",
]
