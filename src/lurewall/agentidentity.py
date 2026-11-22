# SPDX-License-Identifier: AGPL-3.0-only
"""Post-request identity observations. This module has no decision-engine interface."""

import base64
import contextlib
import hashlib
import ipaddress
import os
import re
import stat

from lurewall import agentfeeds, webbotauth
from lurewall.agentfeeds import CACHE, REPLAY, REQUESTS, atomic, parse_feed, strict_json


class Observer:
    def __init__(
        self, config, settings, cache=CACHE, requests=REQUESTS, replay=REPLAY, *, store=None
    ):
        self.settings = settings
        self.config = config
        self.cache, self.requests, self.replay = cache, requests, replay
        self.store = store if store is not None else webbotauth.ReplayStore(replay)
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
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("invalid snapshot file")
                stamp = (info.st_ino, info.st_mtime_ns, info.st_size)
                stored = self.loaded.get(feed.name)
                if stored is not None and stored[0] == stamp:
                    return (stored[3], stored[4]) if stored[1] <= now < stored[2] else (None, None)
                limit = feed.limit if feed.pin else 2 * feed.limit + 1024
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
        claims = sorted(set(self.tokens.findall(record.ua))) if self.settings.claims else []
        signed = bool(
            cap and any(cap[k] for k in ("signature", "signature_input", "signature_agent"))
        )
        if not claims:
            return self._judge(record, None, now, signed) if signed else None
        rows = [self._judge(record, claim, now, signed) for claim in claims]
        if len(rows) == 1:
            return rows[0]
        # Several claimed names: each is judged on its own, so adding a second name
        # can never hide a conclusive failure of the first.
        summary = {
            claim: f"{row['verdict']}:{row['reason']}"
            for claim, row in zip(claims, rows, strict=True)
        }
        failed = [row for row in rows if row["verdict"] == "impersonation"]
        if failed:
            return {**failed[0], "ua_claims": claims, "claim_results": summary}
        if all(row["verdict"] == "verified" for row in rows):
            return {**rows[0], "ua_claims": claims, "claim_results": summary}
        return {
            "verdict": "indeterminate",
            "reason": "ambiguous_claim",
            "claim": "multiple",
            "ua_claim": None,
            "ua_claims": claims,
            "claim_results": summary,
            "counted": False,
            "alert": False,
            "duration_ms": record.duration_ms,
        }

    def _visible(self, record):
        cap = record.capture
        if (
            not cap
            or record.stale
            or record.invalid_utf8
            or record.duration_ms is None
            or not record.client_visible
            or cap["scheme"] != "https"
            or record.request != f"{record.method} {record.uri} {cap['protocol']}"
            or record.status in (400, 414, 431)
        ):
            return False
        # The authority must be one the operator confirmed, logged by a server block
        # the operator confirmed. nginx logs only that block's first server_name.
        return (
            cap["authority"].lower() in self.settings.ingress
            and cap["ingress"].lower() in self.settings.server_names
        )

    def _judge(self, record, claim, now, signed):
        cap = record.capture
        policy = self.settings.claims.get(claim, {}) if claim else {}
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
            return {
                **row,
                "verdict": status,
                "reason": reason,
                "alert": status == "impersonation" and policy.get("alert", True),
            }

        if not self._visible(record):
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
                elif ranges.authoritative and agentfeeds.may_be_authoritative(ranges.url):
                    ip_state = "authoritative_miss"
                else:
                    ip_state = "partial_miss"
        sig = "absent"
        if any(
            cap[k] == "!overflow" or len(cap[k].encode("utf-8", errors="replace")) > 8192
            for k in ("signature", "signature_input", "signature_agent")
        ):
            sig = "capture_overflow"
        elif signed and keyfeed:
            keys, ref = self.snapshot(keyfeed, now)
            if keys is None:
                sig = "key_unavailable"
            else:
                row["key_snapshot"] = ref
                sig = webbotauth.check(record, keyfeed, keys, self.store, now, evidence=row)
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
        # Conclusive only: a signature that fails under the signer's own key, or a
        # miss against an authoritative feed with no valid signature for the claim.
        if sig == "bad_signature":
            return verdict("impersonation", sig)
        if ip_state == "authoritative_miss" and sig in ("absent", "foreign_signer"):
            return verdict("impersonation", ip_state)
        return verdict("indeterminate", sig if sig != "absent" else ip_state)

    def close(self):
        self.store.close()


class Runtime:
    """The reader's identity feature: optional, reloadable, and never fatal.

    A missing file means the feature is off. A file that cannot be read or parsed
    leaves the last good settings in force (or the feature off) and reports why,
    so a typo in an alert-only feature never stops the detector. Edits are picked
    up without a restart, the same way the fetch helper reads the file each run.
    """

    CHECK_EVERY_MS = 5_000

    def __init__(self, path, *, cache=CACHE, requests=REQUESTS, replay=REPLAY, report):
        self.path = path
        self.cache, self.requests = cache, requests
        self.store = webbotauth.ReplayStore(replay)
        self.replay = replay
        self.report = report  # report(event_type, detail)
        self.observer = None
        self._stamp = None
        self._checked_at = None

    @property
    def active(self):
        return self.observer is not None

    def reload(self, now_ms, *, force=False):
        if (
            not force
            and self._checked_at is not None
            and 0 <= now_ms - self._checked_at < self.CHECK_EVERY_MS
        ):
            return
        self._checked_at = now_ms
        try:
            info = os.stat(self.path)
            # ctime too: a chmod that makes the file readable must be noticed.
            stamp = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)
        except FileNotFoundError:
            stamp = None
        except OSError as exc:
            stamp = ("error", type(exc).__name__)
        if stamp == self._stamp:
            return
        self._stamp = stamp
        if stamp is None:
            if self.observer is not None:
                self.observer = None
                self.report("agent_config_removed", {"path": str(self.path)})
            return
        try:
            if stamp[0] == "error":
                raise OSError(stamp[1])
            settings = agentfeeds.settings(self.path)
        except Exception as exc:  # any failure leaves the detector running
            self.report(
                "agent_config_invalid",
                {
                    "path": str(self.path),
                    "error": f"{type(exc).__name__}: {exc}"[:300],
                    "identity": "unchanged" if self.observer is not None else "off",
                },
            )
            return
        self.observer = Observer(
            self.path, settings, self.cache, self.requests, self.replay, store=self.store
        )
        self.report(
            "agent_config_loaded",
            {
                "path": str(self.path),
                "feeds": len(settings.feeds),
                "claims": len(settings.claims),
                "warnings": list(settings.warnings),
            },
        )

    def observe(self, record, now_ms):
        self.reload(now_ms)
        if self.observer is None:
            return None
        return self.observer.observe(record, now_ms)

    def close(self):
        self.store.close()
