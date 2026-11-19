# SPDX-License-Identifier: AGPL-3.0-only
"""Local operator controls and read-only diagnostics."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
import subprocess
import tempfile
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from lurewall import accesslog, canaries, engineconfig, labsite, sigconfig, signing, verify
from lurewall.entry import Entry
from lurewall.nft import NftAdapter, NftError, element_for, system_runner
from lurewall.sources import source_key

MAX_DECISIONS = 200
_LOG_SAMPLE_BYTES = 512 * 1024
_CLOCK_TOLERANCE_MS = 5 * 60_000
_UNBLOCK_FILE = "unblock"
_DECISION_EVENTS = frozenset(
    {
        "attack_signal",
        "block",
        "block_applied",
        "block_expired",
        "block_restored",
        "canary_hit",
        "canary_relayed",
        "canary_unbound",
        "cap_reached",
        "decision",
        "enforcement_failed",
        "manual_unblock",
        "would_block",
    }
)
_DETAIL_KEYS = frozenset(
    {
        "action",
        "applied",
        "attack_count",
        "count",
        "counted",
        "enforced",
        "expiry_ms",
        "normal_browsing",
        "of",
        "outcome",
        "reason",
        "signal",
        "signals",
        "stale",
        "ttl_ms",
    }
)


def _read_text(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        mode = os.fstat(handle.fileno()).st_mode
        if not stat.S_ISREG(mode) or mode & 0o022:
            raise ValueError("managed allowlist must be a regular file writable only by its owner")
        raw = handle.read(engineconfig.MAX_CONFIG_BYTES + 1)
    if len(raw) > engineconfig.MAX_CONFIG_BYTES:
        raise ValueError("allowlist file is too large")
    return raw.decode("utf-8")


def _allowlist_lines(text: str) -> list[tuple[str, engineconfig.Network | None]]:
    lines = text.splitlines(keepends=True)
    values = [line.partition("#")[0].strip() for line in lines]
    entries = [value for value in values if value]
    networks = iter(engineconfig.parse_networks(entries, "managed allowlist"))
    return [
        (line, next(networks) if value else None) for line, value in zip(lines, values, strict=True)
    ]


def read_allowlist(path: Path) -> tuple[engineconfig.Network, ...]:
    """Read the managed file. An explicitly configured missing file is an error."""
    return tuple(
        dict.fromkeys(network for _, network in _allowlist_lines(_read_text(path)) if network)
    )


def change_allowlist(path: Path, operation: str, address: str) -> bool:
    """Update the managed list atomically while preserving the rest of the file."""
    (network,) = engineconfig.parse_networks([address], "managed allowlist")
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(lock_fd, "rb") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("allowlist lock is not a regular file")
        fcntl.flock(lock, fcntl.LOCK_EX)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise ValueError("managed allowlist must be a regular file writable only by its owner")
        text = _read_text(path)
        lines = _allowlist_lines(text)
        exists = any(entry == network for _, entry in lines)
        if (operation == "add") == exists:
            return False
        if operation == "add":
            updated = (text if not text or text.endswith("\n") else text + "\n") + f"{network}\n"
        else:
            updated = "".join(line for line, entry in lines if entry != network)
        _allowlist_lines(updated)
        data = updated.encode("utf-8")
        if len(data) > engineconfig.MAX_CONFIG_BYTES:
            raise ValueError("allowlist file is too large")
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".allowlist-", delete=False
        ) as tmp:
            staged = Path(tmp.name)
            try:
                own = os.fstat(tmp.fileno())
                if (info.st_uid, info.st_gid) != (own.st_uid, own.st_gid):
                    os.fchown(tmp.fileno(), info.st_uid, info.st_gid)
                os.fchmod(tmp.fileno(), stat.S_IMODE(info.st_mode))
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
                os.replace(staged, path)
            finally:
                staged.unlink(missing_ok=True)
    return True


def _address_source(address: str) -> str:
    if "%" in address:
        raise ValueError("provide a single IPv4 or IPv6 address without a zone")
    try:
        return source_key(address)
    except ValueError as exc:
        raise ValueError("provide a single IPv4 or IPv6 address") from exc


def _control_dir(path: Path) -> int:
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
        os.close(fd)
        raise ValueError("operator directory must have mode 0700")
    return fd


def validate_control_dir(path: Path) -> None:
    fd = _control_dir(path)
    try:
        if os.fstat(fd).st_uid != os.geteuid():
            raise ValueError("operator directory must be owned by the service account")
    finally:
        os.close(fd)


def queue_unblock(path: Path, address: str) -> str:
    """Publish one request without replacing a still-pending request."""
    source = _address_source(address)
    element_for(source)
    fd = _control_dir(path)
    try:
        info = os.fstat(fd)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".unblock-") as temporary:
            temporary_name = Path(temporary.name).name
            if info.st_uid != os.geteuid() or info.st_gid != os.fstat(temporary.fileno()).st_gid:
                os.fchown(temporary.fileno(), info.st_uid, info.st_gid)
            temporary.write(f"{source}\n".encode("ascii"))
            temporary.flush()
            os.fsync(temporary.fileno())
            try:
                os.link(temporary_name, _UNBLOCK_FILE, src_dir_fd=fd, dst_dir_fd=fd)
            except FileExistsError as exc:
                raise ValueError("an unblock request is already pending") from exc
            temporary.close()
            os.fsync(fd)
    finally:
        os.close(fd)
    return source


def consume_unblock(path: Path, engine) -> bool:
    """Process one request in the same writer that owns firewall and engine state."""
    fd = _control_dir(path)
    try:
        try:
            request = os.open(
                _UNBLOCK_FILE, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd
            )
        except FileNotFoundError:
            return True
        except OSError as exc:
            if exc.errno != errno.ELOOP:
                raise
            engine.reject_unblock()
        else:
            info = os.fstat(request)
            if stat.S_ISDIR(info.st_mode):
                os.close(request)
                engine.reject_unblock()
                return False
            with os.fdopen(request, "rb") as handle:
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                    engine.reject_unblock()
                else:
                    try:
                        raw = handle.read(80)
                        source = raw.decode("ascii").rstrip("\n")
                        if raw != f"{source}\n".encode("ascii"):
                            raise ValueError("request format")
                        element_for(source)
                    except ValueError:
                        engine.reject_unblock()
                    else:
                        if not engine.unblock(source):
                            return False
        os.unlink(_UNBLOCK_FILE, dir_fd=fd)
        os.fsync(fd)
        return True
    finally:
        os.close(fd)


def explain(
    address: str, log: Path, public_key: str, anchors: list[Path], limit: int
) -> tuple[verify.Report, str, int, deque[dict]]:
    source = _address_source(address)
    if not 1 <= limit <= MAX_DECISIONS:
        raise ValueError(f"limit must be between 1 and {MAX_DECISIONS}")
    history: deque[dict] = deque(maxlen=limit)
    matched = 0

    def visit(item: Entry) -> None:
        nonlocal matched
        if item.source != source:
            return
        kind = item.detail.get("of") if item.type == "rollup" else item.type
        if not isinstance(kind, str) or kind not in _DECISION_EVENTS:
            return
        matched += 1
        history.append(
            {
                "seq": item.seq,
                "ts_ms": item.ts,
                "type": item.type,
                "detail": {key: value for key, value in item.detail.items() if key in _DETAIL_KEYS},
            }
        )

    report = verify.verify_log(log, public_key, anchors, visit=visit)
    return report, source, matched, history


@dataclass(frozen=True)
class Check:
    name: str
    level: str
    detail: str


def _sample(
    path: Path, config: engineconfig.EngineConfig, require_peer_log: bool
) -> tuple[Check, Check]:
    with path.open("rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        start = max(0, size - _LOG_SAMPLE_BYTES)
        handle.seek(start)
        data = handle.read(_LOG_SAMPLE_BYTES)
    lines = data.split(b"\n")
    # In a live file, discard the first or last records if the snapshot split them.
    lines = lines[int(bool(start)) : -1]
    if not lines:
        return (
            Check("nginx log", "warn", "no complete entries yet; send a normal request and retry"),
            Check("clock", "warn", "no nginx timestamp available"),
        )
    now = time.time_ns() // 1_000_000
    newest = None
    for line in lines[-20:]:
        record = accesslog.parse_line(
            line,
            0,
            now_ms=now,
            max_age_ms=_CLOCK_TOLERANCE_MS,
            require_peer_log=require_peer_log or bool(config.trusted_proxies),
            trusted_proxies=config.trusted_proxies,
        )
        if isinstance(record, accesslog.ParseFailure):
            return (
                Check(
                    "nginx log",
                    "fail",
                    f"recent entry does not match the required format ({record.reason})",
                ),
                Check("clock", "warn", "sample could not be parsed"),
            )
        newest = record.ts_ms if newest is None else max(newest, record.ts_ms)
    if newest > now + _CLOCK_TOLERANCE_MS:
        clock = Check("clock", "fail", "recent nginx timestamp is more than five minutes ahead")
    elif newest < now - _CLOCK_TOLERANCE_MS:
        clock = Check(
            "clock", "warn", "sample is old; send a normal request and check clock synchronization"
        )
    else:
        clock = Check("clock", "pass", "recent nginx timestamps agree with the local clock")
    return Check("nginx log", "pass", "recent complete entries match the required format"), clock


def _local_command_read(args: list[str]) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - only fixed local diagnostics below call this
            args,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return result.stdout.strip()


def unit_state() -> str:
    """The systemd state for the installed default service, when available."""
    state = _local_command_read(["/usr/bin/systemctl", "is-active", "lurewall.service"])
    return (
        state
        if state in {"active", "inactive", "failed", "activating", "deactivating"}
        else "unknown"
    )


def doctor(
    *,
    engine_path: Path,
    signals_path: Path,
    canaries_path: Path,
    allowlist_path: Path | None,
    access_log: Path,
    event_log: Path,
    key: Path,
    checkpoint: Path | None,
    operator_dir: Path | None,
    require_peer_log: bool,
) -> list[Check]:
    """Read only. Report setup errors without exposing log entries or credentials."""
    checks: list[Check] = []
    try:
        config = engineconfig.load(engine_path)
        if allowlist_path is not None:
            read_allowlist(allowlist_path)
        if config.enforcing and require_peer_log and not config.tcp_ports:
            raise ValueError("enforcement.tcp_ports is required for operator enforcement")
        signal_config = sigconfig.load(signals_path)
        canary_set = canaries.load_state(canaries_path)
        routes = labsite.site_routes()
        if canaries.find_collisions(canary_set, routes):
            raise ValueError("a canary collides with a site route; rotate and rebuild")
        try:
            sigconfig.check_against_site(signal_config, canary_set, routes)
        except sigconfig.SignalConfigError as exc:
            raise ValueError(
                "signals overlap a canary or site route; run signals check locally"
            ) from exc
    except (OSError, ValueError) as exc:
        checks.append(Check("config", "fail", ascii(str(exc))[1:-1]))
        return checks
    mode = "enforcing" if config.enforcing else "dry-run" if config.dry_run else "log-only"
    checks.append(Check("config", "pass", f"engine, signals and canaries are valid ({mode})"))
    if config.enforcing and not config.tcp_ports:
        checks.append(
            Check("listener scope", "fail", "set enforcement.tcp_ports before using a real server")
        )

    try:
        paths = ((access_log, os.R_OK), (event_log.parent, os.W_OK | os.X_OK))
        if any(not os.access(path, access) for path, access in paths):
            raise OSError("nginx log is unreadable or signed-log directory is unwritable")
        if checkpoint is not None and not os.access(checkpoint.parent, os.W_OK | os.X_OK):
            raise OSError("checkpoint directory is unwritable")
        if operator_dir is not None:
            fd = _control_dir(operator_dir)
            os.close(fd)
        log_mode = access_log.stat().st_mode
        if not stat.S_ISREG(log_mode) or log_mode & 0o022:
            raise OSError("nginx access log must be a regular file writable only by its owner")
        public_key = signing.EurekaSigner.load(key).public_key_hex
    except (OSError, ValueError, signing.KeyFileError) as exc:
        checks.append(Check("permissions", "fail", ascii(str(exc))[1:-1]))
        return checks
    identity = f"checked access as effective UID {os.geteuid()}"
    if os.geteuid() == 0:
        identity += ". Confirm filesystem access separately as the service account"
    checks.append(Check("permissions", "warn" if os.geteuid() == 0 else "pass", identity))

    try:
        checks.extend(_sample(access_log, config, require_peer_log))
    except OSError:
        checks.append(Check("nginx log", "fail", "cannot read the configured access log"))
    sync = _local_command_read(["/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if sync == "yes":
        checks.append(Check("time synchronization", "pass", "systemd reports a synchronized clock"))
    else:
        checks.append(
            Check(
                "time synchronization", "warn", "could not confirm synchronization via timedatectl"
            )
        )

    try:
        if not NftAdapter(system_runner(config.nft_path), dry_run=False).installed():
            checks.append(
                Check(
                    "nftables",
                    "warn",
                    "managed table is absent; it is created on enforcement startup",
                )
            )
        else:
            checks.append(Check("nftables", "pass", "read-only managed table probe succeeded"))
    except NftError:
        checks.append(
            Check(
                "nftables",
                "fail" if config.enforcing else "warn",
                "read-only probe failed; check installation and CAP_NET_ADMIN",
            )
        )

    if not event_log.exists():
        checks.append(
            Check("checkpoint", "warn", "signed log is absent; start the service before verifying")
        )
        if checkpoint is not None and checkpoint.exists():
            checks.append(Check("checkpoint", "fail", "checkpoint exists without its signed log"))
    else:
        try:
            anchors = [] if checkpoint is None else [checkpoint]
            report = verify.verify_log(event_log, public_key, anchors)
        except OSError:
            checks.append(
                Check("checkpoint", "fail", "could not read the signed log or checkpoint")
            )
        else:
            if not report.ok:
                checks.append(
                    Check(
                        "checkpoint", "fail", "integrity check failed; run verify on a stable copy"
                    )
                )
            elif checkpoint is None:
                checks.append(
                    Check("checkpoint", "warn", "log verifies; no checkpoint was specified")
                )
            else:
                checks.append(Check("checkpoint", "pass", "signed log and local checkpoint agree"))
    return checks
