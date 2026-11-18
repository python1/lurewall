# SPDX-License-Identifier: AGPL-3.0-only
"""Turn one access-log record into signals. Pure functions, no state.

Two classes of signal, kept apart by type:

- **attack** signals (sensitive-path probe, injection-like text, verb abuse)
  are the only ones that can count toward a block;
- **behavior** signals (library user agent, prose in a URL, and the timing
  signals added by the tracker) are context for the log and count for nothing.

Rules this module holds to:

- every request is matched twice, on the URI as sent and on a normalized form
  (percent-decoded once, slashes merged, dot segments resolved, lowercased);
- nothing reads a request body: none is logged;
- a request the browser marks cross-site, or whose Referer names another
  host, is ``cross_site`` and yields no attack signal and no canary hit;
- a request nginx answers with a decoy is never a sensitive-path probe.

Every field of a record is attacker-controlled. Nothing here raises on any
input, and no pattern can backtrack without bound.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes, urlsplit

from lurewall.accesslog import Record
from lurewall.canaries import CanaryHit, CanarySet, nginx_normalize
from lurewall.sigconfig import SignalConfig, check_against_site

ATTACK = "attack"
BEHAVIOR = "behavior"

RAW = "raw"
NORMALIZED = "normalized"
# Attack-path rules only: the path percent-decoded a second time, so /%252eenv
# is the /.env probe. nginx decodes once and serves no such file, but nothing
# honest double-encodes a dot in front of a sensitive name.
DOUBLE_DECODED = "double_decoded"

# The only signal kinds that may ever count toward a block. Timing, order and
# header signals are not in this set and never will be.
ATTACK_KINDS = frozenset({"path", "injection", "method"})
BEHAVIOR_KINDS = frozenset(
    {
        "library_user_agent",
        "no_user_agent",
        "no_accept_language",
        "prose_in_url",
        "prose_in_user_agent",
        "unexpected_fetch_metadata",
        "steady_timing",
        "no_asset_loads",
        "methodical_order",
    }
)

# Text longer than this is cut before pattern matching. nginx's own request
# line limit is 8 KiB by default; this only bounds the work per request.
MAX_MATCH_CHARS = 16 * 1024


@dataclass(frozen=True)
class Signal:
    cls: str  # ATTACK or BEHAVIOR
    kind: str
    rule: str  # the config rule or pattern family; never text from the request
    form: str  # RAW, NORMALIZED or DOUBLE_DECODED: which spelling matched

    @property
    def key(self) -> str:
        """What makes two signals "distinct". Spelling variants share one key."""
        return f"{self.kind}:{self.rule}" if self.rule else self.kind


@dataclass(frozen=True)
class Classification:
    cross_site: str | None  # None, "sec_fetch_site" or "referer"
    canary: CanaryHit | None  # the decoy this request reached, counted or not
    attack: tuple[Signal, ...]  # empty whenever cross_site is set
    behavior: tuple[Signal, ...]
    suppressed: tuple[Signal, ...]  # attack signals seen on a cross-site request
    asset: bool  # a successful load of one of the site's assets
    browser_metadata: bool  # Sec-Fetch-Site says the browser made it for this site
    path: str | None  # the normalized, lowercased path, or None if nginx would refuse it
    # The quiet canaries this response body carried to the source.
    carries: tuple[str, ...] = ()

    @property
    def counted_canary(self) -> CanaryHit | None:
        """The decoy hit, unless the request was cross-site. Binding comes later."""
        return None if self.cross_site else self.canary


# -- URI forms -------------------------------------------------------------------


def _strip_origin(uri: str) -> str:
    # An absolute-form request line ("GET http://host/path") names the path
    # after the authority.
    lowered = uri[:8].lower()
    if lowered.startswith(("http://", "https://")):
        rest = uri.split("//", 1)[1]
        authority_and_path, query_separator, query = rest.partition("?")
        _, slash, path = authority_and_path.partition("/")
        return (slash + path or "/") + query_separator + query
    return uri


def _decode_once(text: str) -> str:
    return unquote_to_bytes(text).decode("utf-8", errors="replace")


def normalized_path(uri: str) -> str | None:
    """Percent-decoded once, slashes merged, dot segments resolved, lowercased."""
    path = nginx_normalize(_strip_origin(uri).partition("?")[0])
    return None if path is None else path.lower()


def lenient_path(path: str) -> str | None:
    """A normalized path as other servers may read it, for attack-path rules only.

    Path parameters are dropped (``/..;/`` is ``/../`` to Tomcat, ``x.php;a``
    is ``x.php``), and trailing dots come off each segment (``/.env.`` is
    ``/.env`` to Windows servers). nginx itself does neither.
    """
    out: list[str] = []
    for segment in path.split("/"):
        bare = segment.split(";", 1)[0]
        if bare not in (".", ".."):
            bare = bare.rstrip(".") or bare
        if bare in ("", "."):
            continue
        if bare == "..":
            if out:
                out.pop()  # above the root it stays at the root
            continue
        out.append(bare)
    lenient = "/" + "/".join(out)
    if path.endswith("/") and lenient != "/":
        lenient += "/"
    return None if lenient == path else lenient.lower()


# -- attack paths ---------------------------------------------------------------------


def _match_path(config: SignalConfig, path: str) -> list[str]:
    found = []
    trimmed = path.rstrip("/") or "/"
    if trimmed in config.exact:
        found.append(trimmed)
    for rule in config.tree:
        if trimmed == rule or path.startswith(rule + "/"):
            found.append(rule)
    for segment in path.split("/"):
        if segment in config.segment:
            found.append(f"*/{segment}")
    last = trimmed.rsplit("/", 1)[-1]
    for suffix in config.suffix:
        if len(last) > len(suffix) and last.endswith(suffix):
            found.append(f"*{suffix}")
    return found


def _path_matches(config: SignalConfig, uri: str) -> list[tuple[str, str]]:
    """(rule, form) pairs, raw matches first. One entry per rule."""
    raw_path = _strip_origin(uri).partition("?")[0][:MAX_MATCH_CHARS]
    seen: dict[str, str] = {}
    for rule in _match_path(config, raw_path):
        seen.setdefault(rule, RAW)
    normal = normalized_path(raw_path)
    if normal is not None:
        for rule in _match_path(config, normal):
            seen.setdefault(rule, NORMALIZED)
        lenient = lenient_path(normal)
        if lenient is not None:
            for rule in _match_path(config, lenient):
                seen.setdefault(rule, NORMALIZED)
        if "%" in normal:
            # Decoded once more. Still a path nginx would accept, or nothing.
            twice = nginx_normalize(normal)
            if twice is not None:
                for rule in _match_path(config, twice.lower()):
                    seen.setdefault(rule, DOUBLE_DECODED)
    return list(seen.items())


def match_attack_paths(config: SignalConfig, uri: str) -> list[str]:
    """The attack-path rules a URI matches, in its raw or its normalized form."""
    return [rule for rule, _form in _path_matches(config, uri)]


# -- injection-like text ----------------------------------------------------------------

# Every pattern is a flat alternation with bounded repeats, so matching is
# linear in the text. They run over lowercased text.
_GAP = r"[\s+/*]{1,16}"
_INJECTION: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(
        r"'\s{0,8}(?:or|and)\s{1,8}['\"\d]"
        r"|\b(?:or|and)\s{1,8}\d{1,6}\s{0,4}=\s{0,4}\d{1,6}"
        rf"|\bunion{_GAP}(?:all{_GAP})?select\b"
        r"|\b(?:sleep|benchmark|pg_sleep)\s{0,4}\("
        r"|\bwaitfor\s{1,8}delay\b"
        r"|;\s{0,8}(?:drop|insert|update|delete)\s{1,8}"
        r"|'\s{0,8}(?:--|#|;)"
    ),
    "traversal": re.compile(r"(?:^|[/\\=&?])\.\.(?:[/\\]|$)"),
    "xss": re.compile(
        r"<\s{0,4}/?\s{0,4}(?:script|img|svg|iframe|body|object|embed)\b"
        r"|\bjavascript:"
        r"|\bon(?:error|load|click|mouseover|focus)\s{0,4}="
    ),
    "jndi": re.compile(r"\$\{\s{0,4}(?:jndi\s{0,4}:|\$\{|lower:|upper:|env:|sys:|::-)"),
    "command": re.compile(
        r"(?:;|\||&&|\$\(|`)\s{0,4}"
        r"(?:cat|id|whoami|uname|curl|wget|nc|bash|sh|ping|ls|sleep)(?:[\s);`|/]|$)"
    ),
    "file": re.compile(
        r"/etc/(?:passwd|shadow|hosts)\b"
        r"|/proc/self/"
        r"|\bwin\.ini\b|\bboot\.ini\b"
        r"|\b(?:php|file|expect|gopher|dict)://"
    ),
}


def _injection_matches(config: SignalConfig, uri: str) -> list[tuple[str, str]]:
    """(family, form) pairs. Looks at the path and query string only."""
    target = _strip_origin(uri)[:MAX_MATCH_CHARS]
    raw = target.lower()
    path, _, query = target.partition("?")
    # In a query string a plus sign is a space; in a path it is a plus sign.
    decoded = (_decode_once(path) + "?" + _decode_once(query.replace("+", " "))).lower()
    found = []
    for family in sorted(config.injection_families):
        pattern = _INJECTION[family]
        if pattern.search(raw):
            found.append((family, RAW))
        elif pattern.search(decoded):
            found.append((family, NORMALIZED))
    return found


def attack_signals_for(
    config: SignalConfig, method: str, uri: str, *, decoy: bool
) -> tuple[Signal, ...]:
    """Every attack signal one request raises, before the cross-site filter.

    ``decoy`` is True when nginx answers the request with a decoy body: such a
    request is never a sensitive-path probe, whatever the path rules say.
    """
    found: list[Signal] = []
    if not decoy:
        found += [Signal(ATTACK, "path", rule, form) for rule, form in _path_matches(config, uri)]
    found += [
        Signal(ATTACK, "injection", family, form)
        for family, form in _injection_matches(config, uri)
    ]
    if method in config.abuse_methods:
        # One signal for any abused verb: PUT then DELETE is one habit, not two.
        found.append(Signal(ATTACK, "method", "", RAW))
    return tuple(found)


# -- cross-site filter ---------------------------------------------------------------


def _host_key(host: str) -> str:
    host = host.strip("[]").rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


def cross_site_reason(config: SignalConfig, sec_fetch_site: str, referer: str) -> str | None:
    """Why a request is cross-site, or None. The headers are untrusted text."""
    if config.https and sec_fetch_site.strip().lower() == "cross-site":
        return "sec_fetch_site"
    referer = referer.strip()
    if not referer:
        return None
    try:
        parts = urlsplit(referer[:2048])
        host = parts.hostname
    except ValueError:
        return "referer"  # not a URL of this site, whatever else it is
    if not host or parts.scheme.lower() not in ("http", "https"):
        return "referer"
    hosts = {_host_key(name) for name in config.hosts}
    return None if _host_key(host) in hosts else "referer"


# -- behavior context --------------------------------------------------------------------

_LIBRARY_UA = re.compile(
    r"^(?:curl|wget|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|"
    r"java|okhttp|node-fetch|node|axios|undici|libwww-perl|lwp|httpie|ruby|faraday|"
    r"guzzlehttp|php|scrapy|httpclient|apache-httpclient|restsharp|dart|reqwest|got)"
    r"(?:[/ ]|$)"
)
_WORD_RE = re.compile(r"[a-z]{2,24}", re.ASCII)
_STOPWORDS = frozenset(
    {
        "the",
        "to",
        "of",
        "and",
        "is",
        "are",
        "was",
        "you",
        "your",
        "please",
        "this",
        "that",
        "with",
        "for",
        "from",
        "it",
        "in",
        "on",
        "at",
        "as",
        "be",
        "can",
        "will",
        "should",
        "must",
        "not",
        "do",
        "does",
        "if",
        "then",
        "all",
        "any",
        "me",
        "my",
        "we",
        "our",
        "they",
        "them",
        "what",
        "which",
        "who",
        "how",
        "ignore",
        "previous",
        "instructions",
        "system",
        "prompt",
        "assistant",
    }
)


def _is_prose(text: str, *, min_words: int) -> bool:
    words = text[:MAX_MATCH_CHARS].lower().split()
    plain = [word for word in words if _WORD_RE.fullmatch(word.strip(".,;:!?\"'()"))]
    if len(plain) < min_words:
        return False
    common = sum(1 for word in plain if word.strip(".,;:!?\"'()") in _STOPWORDS)
    return common >= 3


def _behavior(record: Record, target: str) -> list[Signal]:
    found = []
    ua = record.ua.strip()
    if not ua:
        found.append(Signal(BEHAVIOR, "no_user_agent", "", RAW))
    elif _LIBRARY_UA.match(ua[:64].lower()):
        found.append(Signal(BEHAVIOR, "library_user_agent", "", RAW))
    elif _is_prose(ua, min_words=8):
        found.append(Signal(BEHAVIOR, "prose_in_user_agent", "", RAW))
    if not record.lang.strip():
        found.append(Signal(BEHAVIOR, "no_accept_language", "", RAW))
    spaced = re.sub(r"[/?&=_+-]", " ", _decode_once(target[:MAX_MATCH_CHARS]))
    if _is_prose(spaced, min_words=6):
        found.append(Signal(BEHAVIOR, "prose_in_url", "", NORMALIZED))
    return found


# -- the classifier ----------------------------------------------------------------------


class Classifier:
    """Classifies records for one site. Refuses a config that does not fit it."""

    def __init__(
        self,
        config: SignalConfig,
        canary_set: CanarySet,
        real_paths,
        carriers: Mapping[str, tuple[str, ...]] | None = None,
    ) -> None:
        # No classifier exists for a config under which a decoy, or a real
        # page, could count as an attack path.
        check_against_site(config, canary_set, real_paths)
        self.config = config
        self._canaries = canary_set
        present = {canary.id for canary in canary_set.canaries}
        self._carriers = {
            path: tuple(i for i in ids if i in present)
            for path, ids in (carriers or {}).items()
            if any(i in present for i in ids)
        }

    def classify(self, record: Record) -> Classification:
        config = self.config
        target = _strip_origin(record.uri)
        canary = self._canaries.lookup_uri(target)
        if canary is not None and canary.canary.quiet and record.method not in ("GET", "HEAD"):
            canary = None  # a quiet decoy counts for GET and HEAD only
        found = attack_signals_for(config, record.method, target, decoy=canary is not None)
        reason = cross_site_reason(config, record.sec_fetch_site, record.referer)
        path = normalized_path(target)

        clean = not found and canary is None and reason is None
        fetch_site = record.sec_fetch_site.strip().lower() if config.https else ""
        behavior = _behavior(record, target)
        if not config.https and record.sec_fetch_site.strip():
            # No browser sends this header to a plain-HTTP site.
            behavior.append(Signal(BEHAVIOR, "unexpected_fetch_metadata", "", RAW))
        asset = (
            clean
            and path is not None
            and record.method in ("GET", "HEAD")
            and (200 <= record.status < 300 or record.status == 304)
            and (
                path.startswith(config.asset_prefixes)
                or path.rpartition(".")[2] in config.asset_extensions
            )
        )
        carries: tuple[str, ...] = ()
        # The quiet carriers are in the response body, which HEAD omits.
        if (
            reason is None
            and canary is None
            and path is not None
            and record.method == "GET"
            and record.status == 200
        ):
            carries = self._carriers.get(path, ())
        return Classification(
            cross_site=reason,
            canary=canary,
            attack=() if reason else found,
            behavior=tuple(behavior),
            suppressed=found if reason else (),
            asset=asset,
            browser_metadata=clean and fetch_site in ("same-origin", "same-site", "none"),
            path=path,
            carries=carries,
        )
