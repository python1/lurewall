# SPDX-License-Identifier: AGPL-3.0-only
"""Outbound one-shot service. Its only writable output is the public evidence cache."""

import base64
import contextlib
import hashlib
import http.client
import ipaddress
import json
import logging
import re
import signal
import socket
import ssl
import time
from urllib.parse import urlsplit

from lurewall import __version__
from lurewall.agentfeeds import CACHE, CONFIG, REQUESTS, atomic, parse_feed, settings, strict_json

UA = f"Lurewall/{__version__} (+https://github.com/python1/lurewall)"
LOG = logging.getLogger(__name__)


class FetchDeadline(Exception):  # not an OSError, so no retry loop can absorb it
    """The whole fetch, resolver to last body byte, ran past its wall-clock deadline."""


def _timeout(*_args):
    raise FetchDeadline("feed deadline")


def download(feed):
    """Hard wall-clock deadline includes resolver, TLS and a slowly streamed body."""
    url = urlsplit(feed.url)
    previous = signal.signal(signal.SIGALRM, _timeout)
    signal.setitimer(signal.ITIMER_REAL, 3)
    try:
        answers = socket.getaddrinfo(url.hostname, 443, type=socket.SOCK_STREAM)
        for *_, address in answers:
            ip = ipaddress.ip_address(address[0])
            ip = getattr(ip, "ipv4_mapped", None) or ip
            if (
                not ip.is_global
                or ip.is_reserved
                or getattr(ip, "is_site_local", False)
                or ip.is_multicast
                or getattr(ip, "sixtofour", None)
                or getattr(ip, "teredo", None)
            ):
                raise ValueError("nonpublic destination")
        if not answers:
            raise ValueError("no addresses")
        # Every answer was vetted above. Try them in resolver order, so a host with
        # a broken IPv6 route still reaches the publisher over IPv4.
        sock, last_error = None, None
        candidates = list(dict.fromkeys((a[0], a[1], a[2], a[4]) for a in answers))
        for index, (family, kind, proto, address) in enumerate(candidates):
            candidate = socket.socket(family, kind, proto)
            try:
                # Leave time for a later address when this one is blackholed.
                candidate.settimeout(3 if index == len(candidates) - 1 else 1)
                candidate.connect(address)
            except OSError as exc:
                candidate.close()
                last_error = exc
                continue
            candidate.settimeout(3)
            sock = candidate
            break
        if sock is None:
            raise last_error or OSError("no reachable address")
        ctx = ssl.create_default_context()
        with sock, ctx.wrap_socket(sock, server_hostname=url.hostname) as tls:
            target = url.path + ("?" + url.query if url.query else "")
            tls.sendall(
                (
                    f"GET {target} HTTP/1.1\r\nHost: {url.hostname}\r\n"
                    f"User-Agent: {UA}\r\nAccept-Encoding: identity\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            with http.client.HTTPResponse(tls) as res:
                res.begin()
                if (
                    res.status != 200
                    or res.getheader("Content-Encoding", "identity").lower() != "identity"
                ):
                    raise ValueError("unusable response")
                raw = res.read(feed.limit + 1)
                if len(raw) > feed.limit:
                    raise ValueError("size limit")
                cache = res.getheader("Cache-Control", "").lower()
                age = re.search(r"(?:^|,)\s*max-age=(\d{1,12})(?:,|$)", cache)
                ttl = min(3600, int(age[1])) if age else 3600
                return raw, 0 if "no-cache" in cache or "no-store" in cache else ttl
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


# Publisher cache directives are honoured inside these bounds. The floor keeps a
# no-store directory from being fetched every minute; the ceiling leaves room for
# retries before the one-hour local evidence lifetime runs out. A reader's request
# for an unknown key bypasses both (still at most once a minute).
REFRESH_FLOOR_S = 15 * 60
REFRESH_CEILING_S = 45 * 60


def refresh(config=CONFIG, cache=CACHE, requests=REQUESTS, *, fetch=download, clock=time.time):
    cfg = settings(config)
    for warning in cfg.warnings:
        LOG.warning("%s", warning)
    unhealthy = False
    for feed in cfg.feeds.values():
        if feed.pin:
            continue
        now = int(clock())
        path = cache / (feed.name + ".json")
        attempt = cache / (feed.name + ".attempt")
        marker = requests / feed.name
        # A reader can only request the configured directory, never a URL or a kid.
        requested = marker.stat().st_mtime_ns if marker.is_file() else 0
        old = {}
        with contextlib.suppress(OSError, ValueError, TypeError):
            old = strict_json(path.read_bytes())
        if not isinstance(old, dict):
            old = {}
        if (
            old.get("url") == feed.url
            and type(old.get("refresh")) is int
            and old["refresh"] > now
            and requested == old.get("request", 0)
        ):
            continue
        first, last = now, 0
        with contextlib.suppress(OSError, ValueError):
            first, last = map(int, attempt.read_text().split())
        if 0 <= now - last < 60:
            continue
        atomic(attempt, f"{first} {now}".encode())
        try:
            raw, ttl = fetch(feed)
            parse_feed(feed, raw)
            # Private verification evidence, with an independent local age limit.
            # Never persist an HTTP response or reuse it to satisfy an HTTP request.
            doc = strict_json(raw)
            evidence = {"keys": doc["keys"]} if feed.signer else {"prefixes": doc["prefixes"]}
            raw = json.dumps(evidence, separators=(",", ":")).encode()
            snapshot = {
                "url": feed.url,
                "fetched": now,
                "expires": now + 3600,
                "refresh": now + min(max(REFRESH_FLOOR_S, ttl), REFRESH_CEILING_S),
                "request": requested,
                "digest": hashlib.sha256(raw).hexdigest(),
                "body": base64.b64encode(raw).decode(),
            }
            atomic(path, json.dumps(snapshot).encode())
            atomic(attempt, f"{now} {now}".encode())
        except (
            FetchDeadline,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            RecursionError,
            http.client.HTTPException,
        ):
            LOG.warning("Fetch failed for %s", feed.name)
            if now - first >= cfg.alert_hours * 3600:
                LOG.error("Feed unavailable for configured alert interval: %s", feed.name)
                unhealthy = True
    return int(unhealthy)
