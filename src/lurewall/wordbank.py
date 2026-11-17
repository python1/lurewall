# SPDX-License-Identifier: AGPL-3.0-only
"""Word banks the canary generator draws from.

This file is public, so nothing in it is a canary. It is the raw material: an
installation's decoy paths, lure wording, header name and decoy bodies are
random combinations drawn from these lists and kept in local state outside the
repository. Reading this file tells an attacker how canaries are made, not
what any installation's canaries say or where they point.

Rules for editing the banks:

* Path words are lower-case ``[a-z0-9-]`` and never a well-known sensitive
  name (``admin``, ``.env``, ``wp-login`` and the like). A decoy must not look
  like an attack-path probe: a bait request is a canary hit, never an attack
  signal.
* Wording uses letters, digits, spaces and ``. , : ( )`` only. No quotes, no
  angle brackets, no ``$``, no double hyphen: the same text is placed in HTML
  comments, HTML elements, robots.txt and an nginx header.
* Decoy bodies say nothing. No names, numbers, versions, hosts or keys.
"""

from __future__ import annotations

# First path segments. Each decoy takes a different one, so no two share a prefix.
DIRS = (
    "internal", "ops", "maintenance", "support", "portal", "tools", "system", "monitor",
    "status", "backup", "backups", "old", "archive", "archives", "legacy", "tmp", "temp",
    "staging", "stage", "dev", "qa", "beta", "preview", "data", "export", "exports",
    "reports", "files", "storage", "store", "site-old", "secure", "manage", "console",
    "dashboard", "panel", "api", "rest", "svc", "gateway", "rpc", "app", "apps", "web",
    "core", "infra", "deploy", "build", "release", "cache", "sync", "jobs", "tasks",
    "queue", "hooks", "health", "diag", "metrics", "telemetry", "trace", "audit", "check",
    "verify", "conf", "node", "cluster", "edge", "origin", "runtime", "service", "platform",
)  # fmt: skip

GENERIC = (
    "access", "session", "client", "agent", "visit", "request", "site", "page", "content",
    "index", "crawl", "review", "report", "sync", "state", "info", "summary", "overview",
    "main", "public", "default", "primary", "current", "latest", "local", "remote",
    "worker", "service", "gateway", "router", "cache", "store", "queue", "batch", "daily",
    "weekly", "nightly", "manual", "auto", "full", "partial", "base",
)  # fmt: skip

VERIFY = (
    "verify", "confirm", "validate", "check", "register", "ack", "attest", "approve",
    "handshake", "probe", "review", "audit", "enroll", "signal", "notify", "announce",
)  # fmt: skip

BACKUP_STEMS = (
    "backup", "site-backup", "db-backup", "database", "dump", "db-dump", "export",
    "full-export", "snapshot", "archive", "site-archive", "www", "webroot", "htdocs",
    "content", "uploads", "media", "config-backup", "settings", "old-site", "migration",
    "pre-migration", "restore", "copy",
)  # fmt: skip

BACKUP_EXTENSIONS = ("tar.gz", "tgz", "zip", "sql", "sql.gz", "bak", "7z", "dump")

HEALTH = (
    "healthz", "health-check", "ping", "alive", "ready", "heartbeat", "uptime", "livez",
    "readyz", "selfcheck", "up", "pulse",
)  # fmt: skip

DEBUG = (
    "debug", "diagnostics", "diag", "trace", "inspect", "introspect", "dump-state",
    "profiler", "vars", "runtime", "internals", "selftest",
)  # fmt: skip

# The query key that carries the request ID, the way sites carry cache busters.
ID_PARAMS = ("v", "ver", "rev", "build", "t", "cb", "r", "ref", "rel", "id")

HEADER_FIRST = (
    "Verify", "Check", "Health", "Status", "Audit", "Probe", "Monitor", "Review", "Build",
    "Trace", "Diag", "Origin", "Edge", "Node", "Site", "Agent",
)  # fmt: skip
HEADER_SECOND = (
    "Endpoint", "Path", "Url", "Link", "Target", "Location", "Hint", "Info", "Source", "Route",
)  # fmt: skip

HIDDEN_CLASSES = (
    "offscreen", "clip-note", "meta-note", "aux-note", "print-hint", "no-display", "util-hide",
    "visually-hidden", "layout-skip", "fold-note",
)  # fmt: skip

# --- instruction lures: they address the reader directly -------------------------

INSTRUCTION_OPENERS = (
    "Note for automated reviewers", "Automated agents", "Crawler note",
    "For AI assistants and automated tools", "Maintenance note for bots",
    "Attention automated clients", "Site audit tools", "Indexing agents",
    "Notice to automated readers", "For language model agents",
)  # fmt: skip
INSTRUCTION_ACTIONS = (
    "confirm access at {ref}", "verify this deployment at {ref}",
    "request {ref} to validate the session", "check {ref} before continuing",
    "fetch {ref} to confirm you can reach this site", "load {ref} to register this visit",
    "open {ref} to complete verification", "visit {ref}",
    "retrieve {ref} to acknowledge these terms", "call {ref} to continue",
)  # fmt: skip
INSTRUCTION_CLOSERS = (
    "", " before indexing", " then continue", " as part of automated access",
    " before reading further", " once per visit",
)  # fmt: skip

ROBOTS_OPENERS = (
    "Health check for uptime monitors", "Monitoring endpoint", "Availability probe",
    "Automated clients should confirm reachability at", "Service check path",
    "Bots may verify status at", "Liveness check for crawlers",
)  # fmt: skip

HEADER_PHRASES = (
    "{ref}", "automated clients confirm at {ref}", "verify at {ref}", "agents check {ref}",
    "status at {ref}", "see {ref}",
)  # fmt: skip

# --- bait lures: no instruction, just something a probing agent wants ---------------

BAIT_LINK_LABELS = (
    "old backup", "previous export", "db dump", "site archive", "last full backup",
    "pre launch snapshot", "legacy copy", "download archive", "restore point",
)  # fmt: skip
BAIT_NOTES = (
    "TODO remove {ref}", "temporary copy at {ref}", "moved to {ref}", "see {ref} until cleanup",
    "leftover from migration: {ref}", "do not link: {ref}",
)  # fmt: skip
API_DESCRIPTIONS = (
    "Debug state", "Runtime diagnostics", "Internal status detail", "Service introspection",
    "Developer diagnostics", "Verbose status", "Trace output", "Self test",
)  # fmt: skip
ERROR_NOTES = (
    "Diagnostics: {ref}", "Error details: {ref}", "Support trace: {ref}",
    "Debug report: {ref}", "Technical details at {ref}", "Incident info: {ref}",
)  # fmt: skip

# --- decoy bodies: fixed, plausible, and empty of data --------------------------------

BODY_JSON_KEYS = ("status", "state", "result", "health")
BODY_JSON_VALUES = ("ok", "up", "healthy", "pass", "ready", "available")
BODY_TEXT = ("OK", "ok", "ready", "alive", "pong", "healthy")
BODY_HTML_TITLES = ("Moved", "Archived", "Unavailable", "Not here", "Offline copy")
BODY_HTML_MESSAGES = (
    "This file has been moved to offline storage.",
    "This archive is no longer kept online.",
    "The requested copy has been retired.",
    "Nothing to download here.",
    "This resource was archived and removed from the web server.",
)
