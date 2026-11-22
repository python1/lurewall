# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded RFC 9421 / Web Bot Auth -01 profile. Unsupported syntax is inconclusive."""

import base64
import contextlib
import hashlib
import json
import re
import sqlite3
from urllib.parse import parse_qsl, quote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from lurewall.agentfeeds import binary, thumb

LABEL = r"[a-z*][a-z0-9_.*-]*"
STRING = r'"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\])*"'
PARAM = re.compile(r"; *(" + LABEL + r")=(" + STRING + r"|-?(?:0|[1-9][0-9]{0,14}))")
COMP = re.compile("(" + STRING + ")")
SCHEMA = (
    "CREATE TABLE seen (identity TEXT PRIMARY KEY, request TEXT NOT NULL, expiry INTEGER NOT NULL)"
)


def initialize(path):
    # Only an explicit operator action can establish a new replay history.
    with path.open("xb"):
        pass
    path.chmod(0o600)
    with contextlib.closing(sqlite3.connect(path)) as db:
        db.execute(SCHEMA)
        db.execute("CREATE INDEX expiry ON seen(expiry)")


def replay_db(path):
    db = sqlite3.connect(path.absolute().as_uri() + "?mode=rw", uri=True, timeout=0)
    try:
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ValueError("damaged replay store")
        if db.execute("SELECT sql FROM sqlite_master WHERE name='seen'").fetchone() != (SCHEMA,):
            raise ValueError("unknown replay schema")
    except BaseException:
        db.close()
        raise
    return db


def remember(db, key, token, record, expiry, now):
    digest = hashlib.sha256(json.dumps([key, token]).encode()).hexdigest()
    request = record.request_id + ":" + record.line_sha256
    with db:
        db.execute("DELETE FROM seen WHERE expiry < ?", (now,))
        old = db.execute("SELECT request FROM seen WHERE identity=?", (digest,)).fetchone()
        if old:
            return "valid" if old[0] == request else "replay"
        if db.execute("SELECT count(*) FROM seen").fetchone()[0] >= 100000:
            return "replay_store_full"
        db.execute("INSERT INTO seen VALUES (?,?,?)", (digest, request, expiry))
    return "valid"


def params(text, pos):
    values = {}
    wire = ""
    while m := PARAM.match(text, pos):
        name, val = m.groups()
        if name in values:
            raise ValueError("duplicate parameter")
        values[name] = json.loads(val)
        wire += ";" + name + "=" + val
        pos = m.end()
    return values, wire, pos


def dictionary(text, kind):
    """Parse complete dictionaries, retaining the canonical component/parameter order."""
    result = {}
    pos = 0
    while pos < len(text):
        m = re.compile(r"[ \t]*(" + LABEL + r")=").match(text, pos)
        if not m or m[1] in result or len(result) >= 8:
            raise ValueError("unsupported dictionary")
        label, pos = m[1], m.end()
        if kind == "input":
            if text[pos : pos + 1] != "(":
                raise ValueError("expected inner list")
            pos += 1
            components = []
            while pos < len(text):
                pos += len(text[pos:]) - len(text[pos:].lstrip(" "))
                if text[pos : pos + 1] == ")":
                    break
                m = COMP.match(text, pos)
                if not m or len(components) >= 32:
                    raise ValueError("unsupported component")
                options, wire, pos = params(text, m.end())
                components.append((json.loads(m[1]), options, m[1] + wire))
                if text[pos : pos + 1] not in (" ", ")"):
                    raise ValueError("component delimiter")
            if text[pos : pos + 1] != ")" or not components:
                raise ValueError("incomplete list")
            values, wire, pos = params(text, pos + 1)
            result[label] = (
                components,
                values,
                "(" + " ".join(c[2] for c in components) + ")" + wire,
            )
        else:
            pattern = STRING if kind == "agent" else r":[A-Za-z0-9+/=]+:"
            m = re.compile(pattern).match(text, pos)
            if not m:
                raise ValueError("invalid field")
            result[label] = (
                json.loads(m[0]) if kind == "agent" else base64.b64decode(m[0][1:-1], validate=True)
            )
            pos = m.end()
        pos += len(text[pos:]) - len(text[pos:].lstrip(" \t"))
        if pos == len(text):
            break
        if text[pos] != "," or pos + 1 == len(text):
            raise ValueError("missing delimiter")
        pos += 1
    return result


def agents(header):
    header = header.strip()
    if re.fullmatch(STRING, header):
        return {None: json.loads(header)}
    return dictionary(header, "agent")


def signature_base(record, label, signer, components, wire, legacy):
    cap = record.capture
    host = cap["authority"]
    parsed = urlsplit("//" + host)
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("ambiguous authority")
    authority = parsed.hostname.lower()
    if ":" in authority:
        authority = "[" + authority + "]"
    if parsed.port is not None and parsed.port != 443:
        authority += ":" + str(parsed.port)
    uri = record.uri
    if not uri.startswith("/") or "#" in uri or not uri.isascii():
        raise ValueError("unsupported target")
    path, _, query = uri.partition("?")
    derived = {
        "@authority": authority,
        "@target-uri": cap["scheme"] + "://" + host + uri,
        "@request-target": uri,
        "@scheme": cap["scheme"],
        "@method": record.method,
        "@path": path,
        "@query": "?" + query,
        "user-agent": record.ua,
    }
    covered = set()
    lines = []
    bound = False
    for name, options, identifier in components:
        if identifier in covered:
            raise ValueError("duplicate component")
        covered.add(identifier)
        if name == "signature-agent":
            if legacy and not options:
                val = cap["signature_agent"].strip()
            elif not legacy and options == {"key": label}:
                val = json.dumps(signer)
            else:
                raise ValueError("unbound signer")
            bound = True
        elif name == "@query-param" and set(options) == {"name"}:
            pairs = [
                (quote(k, safe=""), quote(v, safe=""))
                for k, v in parse_qsl(query, keep_blank_values=True, errors="strict")
            ]
            matches = [v for k, v in pairs if k == options["name"]]
            if len(matches) != 1:
                raise ValueError("ambiguous query parameter")
            val = matches[0]
        elif name in derived and not options:
            val = derived[name]
        else:
            raise ValueError("uncaptured component")
        if not val.isascii() or any(ord(ch) < 32 or ord(ch) == 127 for ch in val):
            raise ValueError("ambiguous bytes")
        lines.append(identifier + ": " + val)
    if not bound or not covered.intersection({'"@authority"', '"@target-uri"'}):
        raise ValueError("insufficient coverage")
    return "\n".join([*lines, '"@signature-params": ' + wire]).encode("ascii")


def verify_one(record, feed, keys, label, entry, sig, legacy, db, now):
    components, p, wire = entry
    if p.get("tag") != "web-bot-auth" or not isinstance(p.get("keyid"), str):
        return "unsupported"
    kid = p["keyid"]
    if kid not in keys:
        return "unknown_kid"
    key = keys[kid]
    if feed.thumbprint and kid != thumb(key):
        return "key_mismatch"
    base = signature_base(record, label, feed.signer, components, wire, legacy)
    created, expires = p.get("created"), p.get("expires")
    if (
        type(created) is not int
        or type(expires) is not int
        or not created <= expires <= created + 86400
    ):
        return "unsupported_lifetime"
    arrival = (record.ts_ms - record.duration_ms) // 1000
    if not all(key.get("nbf", 0) <= t < key.get("exp", 2**63) for t in (created, arrival, now)):
        return "key_outside_validity"
    alg, jwa = ("ed25519", "EdDSA") if key["kty"] == "OKP" else ("rsa-pss-sha512", "PS512")
    if (
        p.get("alg", alg) != alg
        or key.get("alg", jwa) not in (jwa, alg)
        or "verify" not in key.get("key_ops", ["verify"])
    ):
        return "unsupported_algorithm"
    try:
        if alg == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(binary(key["x"])).verify(sig, base)
        else:
            pub = rsa.RSAPublicNumbers(
                int.from_bytes(binary(key["e"]), "big"), int.from_bytes(binary(key["n"]), "big")
            ).public_key()
            pub.verify(
                sig,
                base,
                padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64),
                hashes.SHA512(),
            )
    except InvalidSignature:
        return "bad_signature"
    if not created - 60 <= arrival <= expires + 60:
        return "expired"
    if now > expires + 60:
        return "stale_capture"
    nonce = p.get("nonce")
    if nonce is not None and not isinstance(nonce, str):
        return "unsupported"
    # Track the signature base when nonce is absent, including randomized RSA signatures.
    token = ["nonce", nonce] if nonce else ["base", hashlib.sha256(base).hexdigest()]
    return remember(db, thumb(key), token, record, expires + 60, now)


def check(record, feed, keys, replay, now):
    cap = record.capture
    try:
        with contextlib.closing(replay_db(replay)) as db:
            directory = agents(cap["signature_agent"])
            inputs = dictionary(cap["signature_input"], "input")
            signatures = dictionary(cap["signature"], "signature")
            legacy = None in directory
            results = []
            for label, entry in inputs.items():
                if directory.get(None if legacy else label) != feed.signer:
                    continue
                if label not in signatures:
                    return "incomplete"
                outcome = verify_one(
                    record, feed, keys, label, entry, signatures[label], legacy, db, now
                )
                if outcome == "valid":
                    return outcome
                results.append(outcome)
            if "unknown_kid" in results:
                return "unknown_kid"
            if results and all(r in ("bad_signature", "expired") for r in results):
                return results[0]
            return next(
                (r for r in results if r not in ("bad_signature", "expired")), "foreign_signer"
            )
    except (OSError, sqlite3.Error):
        return "replay_store_unavailable"
    except (ValueError, KeyError, TypeError, OverflowError):
        return "indeterminate"
