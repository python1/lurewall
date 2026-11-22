# SPDX-License-Identifier: AGPL-3.0-only
"""Post-request identity observations. This module has no decision-engine interface."""

import base64
import contextlib
import hashlib
import ipaddress
import re

from lurewall import webbotauth
from lurewall.agentfeeds import CACHE, REPLAY, REQUESTS, atomic, parse_feed, strict_json


class Observer:
    def __init__(self, config, settings, cache=CACHE, requests=REQUESTS, replay=REPLAY):
        self.settings = settings
        self.config = config
        self.cache, self.requests, self.replay = cache, requests, replay
        self.loaded = {}
        self.requested = {}
        self.tokens = re.compile(
            r"(?<![A-Za-z0-9_-])("
            + "|".join(re.escape(token) for token in settings.claims)
            + r")(?![A-Za-z0-9_-])",
            re.ASCII,
        )

    def snapshot(self, feed, now):
        path = (
            self.config.parent / "pins" / (feed.name + ".json")
            if feed.pin
            else self.cache / (feed.name + ".json")
        )
        try:
            stat = path.stat()
            stamp = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
            stored = self.loaded.get(feed.name)
            if stored is None or stored[0] != stamp:
                limit = feed.limit if feed.pin else 2 * feed.limit + 1024
                with path.open("rb") as stream:
                    raw = stream.read(limit + 1)
                if len(raw) > limit:
                    raise ValueError("oversized snapshot")
                if feed.pin:
                    digest, until, start = feed.pin, feed.until, 0
                else:
                    snap = strict_json(raw)
                    if snap["url"] != feed.url:
                        raise ValueError("different source")
                    raw = base64.b64decode(snap["body"], validate=True)
                    digest, until, start = snap["digest"], snap["expires"], snap["fetched"]
                    if type(start) is not int or type(until) is not int or until - start > 3600:
                        raise ValueError("bad snapshot clock")
                if len(raw) > feed.limit or hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError("snapshot digest mismatch")
                stored = stamp, start, until, parse_feed(feed, raw), digest
                self.loaded[feed.name] = stored
            if stored[1] <= now < stored[2]:
                return stored[3], stored[4]
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            pass
        return None, None

    def refresh_request(self, feed, now):
        if feed.pin or now - self.requested.get(feed.name, -60) < 60:
            return
        self.requested[feed.name] = now
        with contextlib.suppress(OSError):  # Timer refresh is independent.
            atomic(self.requests / feed.name, b"refresh\n")

    def observe(self, record, now_ms):
        now = now_ms // 1000
        cap = record.capture
        claims = set(self.tokens.findall(record.ua)) if self.settings.claims else set()
        if len(claims) > 1:
            return {
                "verdict": "indeterminate",
                "reason": "ambiguous_claim",
                "claim": "multiple",
                "counted": False,
            }
        claim = next(iter(claims), None)
        policy = self.settings.claims.get(claim, {})
        signed = bool(
            cap and any(cap[k] for k in ("signature", "signature_input", "signature_agent"))
        )
        if not claim and not signed:
            return None
        feeds = self.settings.feeds
        keyfeed = feeds.get(policy.get("keys"))
        if not claim:
            try:
                urls = set(webbotauth.agents(cap["signature_agent"]).values())
            except (TypeError, ValueError):
                return None
            candidates = [f for f in feeds.values() if f.signer and f.signer in urls]
            if len(candidates) != 1:
                return None
            keyfeed = candidates[0]
        row = {
            "claim": policy.get("publisher", claim) if claim else keyfeed.name,
            "ua_claim": claim,
            "counted": False,
            "duration_ms": record.duration_ms,
        }

        def verdict(status, reason):
            return {**row, "verdict": status, "reason": reason}

        if (
            not cap
            or record.invalid_utf8
            or record.duration_ms is None
            or not record.client_visible
            or cap["authority"].lower() not in self.settings.ingress
            or cap["ingress"].lower() != cap["authority"].lower().split(":")[0]
            or record.status in (400, 414, 431)
            or any(
                v == "!overflow" or len(v.encode("utf-8", errors="replace")) > 8192
                for v in cap.values()
            )
        ):
            return verdict("indeterminate", "ingress_unconfirmed")
        ranges = feeds.get(policy.get("ranges"))
        ip_state = "unmapped"
        if ranges:
            networks, ref = self.snapshot(ranges, now)
            if networks is None:
                ip_state = "snapshot_unavailable"
            else:
                row["range_snapshot"] = ref
                ip = ipaddress.ip_address(record.ip)
                if any(ip in n for n in networks):
                    ip_state = "match"
                elif not any(n.version == ip.version for n in networks):
                    ip_state = "unsupported_family"
                else:
                    ip_state = "authoritative_miss" if ranges.authoritative else "partial_miss"
        sig = "absent"
        if signed and keyfeed:
            keys, ref = self.snapshot(keyfeed, now)
            if keys is None or cap["scheme"] != "https":
                sig = "key_unavailable" if keys is None else "insecure_transport"
            else:
                row["key_snapshot"] = ref
                sig = webbotauth.check(record, keyfeed, keys, self.replay, now)
                if sig == "unknown_kid":
                    self.refresh_request(keyfeed, now)
        row.update(ip_result=ip_state, signature_result=sig)
        if sig == "valid" or ip_state == "match":
            method = (
                "both"
                if sig == "valid" and ip_state == "match"
                else ("signature" if sig == "valid" else "ip_range")
            )
            return verdict("verified", method)
        if not claim or ip_state == "unsupported_family":
            return verdict("indeterminate", sig if not claim else ip_state)
        if sig in ("bad_signature", "expired"):
            return verdict("impersonation", sig)
        if ip_state == "authoritative_miss" and sig in ("absent", "foreign_signer"):
            return verdict("impersonation", ip_state)
        return verdict("indeterminate", sig if sig != "absent" else ip_state)
