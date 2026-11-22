# SPDX-License-Identifier: AGPL-3.0-only
"""Operator trust configuration and validation shared by two separate processes."""

import base64
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

CONFIG = Path("/etc/lurewall/agents.toml")
CACHE = Path("/var/cache/lurewall-fetch")
REQUESTS = Path("/var/lib/lurewall-refresh")
REPLAY = Path("/var/lib/lurewall/agent-replay.sqlite")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
DEFAULT_LIMIT = 256 * 1024


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    signer: str
    authoritative: bool
    thumbprint: bool
    limit: int
    pin: str
    until: int


@dataclass(frozen=True)
class Settings:
    feeds: dict
    claims: dict
    ingress: tuple
    alert_hours: int


def settings(path=CONFIG):
    with path.open("rb") as stream:
        spec = tomllib.load(stream)
    feeds = {}
    for name, row in spec.get("feed", {}).items():
        url = urlsplit(row["url"])
        signer = row.get("signer", "")
        if (
            not NAME.fullmatch(name)
            or url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.fragment
            or url.port not in (None, 443)
            or not url.path.startswith("/")
            or (signer and row["url"] != signer + "/.well-known/http-message-signatures-directory")
        ):
            raise ValueError("invalid feed definition")
        limit = row.get("limit", DEFAULT_LIMIT)
        trust = row.get("coverage", "partial")
        pin = row.get("sha256", "")
        until = row.get("pin_until", 0)
        if (
            type(limit) is not int
            or not DEFAULT_LIMIT <= limit <= 4 * 1024**2
            or trust not in ("partial", "authoritative")
            or (
                pin
                and (not re.fullmatch("[a-f0-9]{64}", pin) or type(until) is not int or until <= 0)
            )
        ):
            raise ValueError("invalid feed limits or pin")
        feeds[name] = Feed(
            name,
            row["url"],
            signer,
            trust == "authoritative",
            row.get("thumbprint", False),
            limit,
            pin,
            until,
        )
    claims = spec.get("claim", {})
    for token, row in claims.items():
        if not NAME.fullmatch(token) or set(row) - {"ranges", "keys", "publisher"}:
            raise ValueError("invalid claim policy")
        for kind in ("ranges", "keys"):
            if kind in row and (
                row[kind] not in feeds or bool(feeds[row[kind]].signer) != (kind == "keys")
            ):
                raise ValueError("invalid claim feed")
    ingress = spec.get("visible_authorities", [])
    hours = spec.get("alert_after_hours", 6)
    if (
        not isinstance(ingress, list)
        or not all(isinstance(x, str) for x in ingress)
        or type(hours) is not int
        or hours < 1
    ):
        raise ValueError("invalid ingress or alert interval")
    return Settings(feeds, claims, tuple(ingress), hours)


def strict_json(data):
    def reject(value):
        raise ValueError("unsupported JSON number")

    def unique(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError("duplicate JSON member")
        return result

    return json.loads(data, parse_float=reject, parse_constant=reject, object_pairs_hook=unique)


def binary(value):
    if not isinstance(value, str) or not re.fullmatch("[A-Za-z0-9_-]+", value):
        raise ValueError("invalid JWK encoding")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def thumb(key):
    names = ("kty", "crv", "x") if key["kty"] == "OKP" else ("e", "kty", "n")
    raw = json.dumps({k: key[k] for k in names}, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def parse_feed(feed, raw):
    doc = strict_json(raw)
    if not isinstance(doc, dict):
        raise ValueError("invalid feed")
    # creationTime is advisory text. It can use either ISO spelling or be absent.
    if not feed.signer:
        rows = doc["prefixes"]
        if not isinstance(rows, list) or not 0 < len(rows) <= 32768:
            raise ValueError("invalid range count")
        networks = []
        for row in rows:
            if not isinstance(row, dict) or len(row) != 1:
                raise ValueError("invalid prefix")
            field, value = next(iter(row.items()))
            if not isinstance(value, str):
                raise ValueError("invalid prefix type")
            net = ipaddress.ip_network(value)
            if field != f"ipv{net.version}Prefix" or net.prefixlen == 0:
                raise ValueError("invalid range family")
            networks.append(net)
        return networks
    if doc.get("signature_agent", feed.signer) != feed.signer:
        raise ValueError("foreign directory")
    rows = doc["keys"]
    if not isinstance(rows, list) or len(rows) > 32:
        raise ValueError("invalid key count")
    keys = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid key")
        if row.get("kty") not in ("RSA", "OKP") or row.get("use", "sig") != "sig":
            continue
        if row["kty"] == "OKP":
            if row.get("crv") != "Ed25519":
                continue
            if len(binary(row["x"])) != 32:
                raise ValueError("invalid Ed25519 key")
        elif not 256 <= len(binary(row["n"])) <= 1024 or len(binary(row["e"])) > 4:
            raise ValueError("invalid RSA key")
        kid = row.get("kid", thumb(row) if feed.thumbprint else None)
        if not isinstance(kid, str) or not 0 < len(kid) <= 256 or kid in keys:
            raise ValueError("invalid key identifier")
        if row.get("signature_agent", feed.signer) != feed.signer:
            raise ValueError("foreign key")
        for bound in ("nbf", "exp"):
            if bound in row and type(row[bound]) is not int:
                raise ValueError("invalid key validity")
        keys[kid] = row
    return keys


def atomic(path, data, mode=0o644):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
