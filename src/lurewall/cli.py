# SPDX-License-Identifier: AGPL-3.0-only
"""The ``lurewall`` command."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lurewall import __version__

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lurewall", description="Lurewall: defensive, lab-only. Not ready for use."
    )
    parser.add_argument("--version", action="version", version=f"lurewall {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser(
        "verify",
        help="check a signed log's chain, signatures and anchored checkpoints",
        description="Exit status: 0 the log verifies, 1 it does not, 2 it could not be checked.",
    )
    verify.add_argument("--log", required=True, type=Path, help="the signed log file")
    verify.add_argument(
        "--pubkey",
        required=True,
        help="the published public key: 64 hex characters, or a file holding them",
    )
    verify.add_argument(
        "--anchors",
        action="append",
        type=Path,
        default=[],
        metavar="PATH",
        help="an anchored checkpoint file, or a directory of them (repeatable)",
    )
    verify.add_argument("--json", action="store_true", help="print the report as JSON")

    keygen = commands.add_parser(
        "keygen", help="create a signing key file (mode 0600) and print its public key"
    )
    keygen.add_argument("--key", required=True, type=Path, help="where to write the key file")

    pubkey = commands.add_parser("pubkey", help="print the public key of a signing key file")
    pubkey.add_argument("--key", required=True, type=Path, help="the key file")

    state_help = "this installation's canary state file (outside any git repository)"
    site = commands.add_parser("lab-site", help="the throwaway lab site")
    site_commands = site.add_subparsers(dest="site_command", required=True)
    build = site_commands.add_parser(
        "build",
        help="build the lab site and its nginx config; creates the canary set on first use",
        description="Fails if any decoy path collides with a real site path.",
    )
    build.add_argument("--state", required=True, type=Path, help=state_help)
    build.add_argument("--out", required=True, type=Path, help="output directory (outside git)")
    build.add_argument(
        "--deploy-root",
        help="where the output will live on the web server, if not the output directory",
    )
    build.add_argument("--listen", default="80", help="nginx listen value (default: 80)")

    canaries = commands.add_parser("canaries", help="this installation's canaries")
    canary_commands = canaries.add_subparsers(dest="canary_command", required=True)
    listing = canary_commands.add_parser("list", help="print the lookup table")
    listing.add_argument("--state", required=True, type=Path, help=state_help)
    rotate = canary_commands.add_parser(
        "rotate",
        help="replace canaries after a suspected leak (never on a schedule), then rebuild",
    )
    rotate.add_argument("--state", required=True, type=Path, help=state_help)
    which = rotate.add_mutually_exclusive_group(required=True)
    which.add_argument("--id", action="append", default=[], help="a canary id (repeatable)")
    which.add_argument("--all", action="store_true", help="replace every canary")

    signals = commands.add_parser("signals", help="the per-site attack-signal config")
    signal_commands = signals.add_subparsers(dest="signal_command", required=True)
    check = signal_commands.add_parser(
        "check",
        help="check a signals config against the lab site's routes and the canary table",
        description=(
            "Exit status: 0 the config fits, 1 a decoy or a real site path would count "
            "as an attack path, 2 the config or the canary state could not be read."
        ),
    )
    check.add_argument("--config", required=True, type=Path, help="the signals config (TOML)")
    check.add_argument("--state", required=True, type=Path, help=state_help)

    run = commands.add_parser(
        "run",
        help="run the service: tail the access log, collect signals, decide",
        description=(
            "Dry-run unless the engine config says otherwise. On startup the enforcement "
            "adapter is reconciled with the saved state."
        ),
    )
    run.add_argument("--access-log", required=True, type=Path, help="nginx's JSON access log")
    run.add_argument("--reader-state", required=True, type=Path, help="the reader's position file")
    run.add_argument("--event-log", required=True, type=Path, help="the signed event log")
    run.add_argument("--key", required=True, type=Path, help="the signing key file")
    run.add_argument("--canaries", required=True, type=Path, help=state_help)
    run.add_argument("--signals", required=True, type=Path, help="the signals config (TOML)")
    run.add_argument("--engine", required=True, type=Path, help="the engine config (TOML)")
    run.add_argument("--engine-state", required=True, type=Path, help="the engine's saved state")
    run.add_argument("--checkpoint", type=Path, help="where to write the signed checkpoint file")
    run.add_argument("--once", action="store_true", help="process what is there, then exit")

    sweep = commands.add_parser(
        "sweep",
        help="remove nftables entries that are past due (run by its own timer)",
        description=(
            "Reads expiry times from the live entries, so it works with the service stopped "
            "and its state lost. Writes to its own signed log, not the service's. "
            "Exit status: 0 done, 1 nft failed, 2 the log or key could not be used."
        ),
    )
    sweep.add_argument("--event-log", required=True, type=Path, help="the sweeper's signed log")
    sweep.add_argument("--key", required=True, type=Path, help="the signing key file")
    sweep.add_argument("--nft", default="/usr/sbin/nft", help="the nft binary")

    engine_state_help = "the engine's saved state file (outside any git repository)"
    status = commands.add_parser(
        "status", help="show active blocks and any standing alert from the engine's saved state"
    )
    status.add_argument("--state", required=True, type=Path, help=engine_state_help)
    alerts = commands.add_parser("alerts", help="standing alerts")
    alert_commands = alerts.add_subparsers(dest="alert_command", required=True)
    clear = alert_commands.add_parser("clear", help="clear the standing alert once reviewed")
    clear.add_argument("--state", required=True, type=Path, help=engine_state_help)
    return parser


def _verify(args: argparse.Namespace) -> int:
    from lurewall import signing
    from lurewall.verify import format_report, verify_log

    try:
        public_key = signing.read_public_key(args.pubkey)
    except ValueError as exc:
        print(f"lurewall verify: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        report = verify_log(args.log, public_key, args.anchors)
    except OSError as exc:
        print(f"lurewall verify: cannot read the log: {exc.strerror}", file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_report(report))
    return EXIT_OK if report.ok else EXIT_FAIL


def _key_command(args: argparse.Namespace) -> int:
    from lurewall import signing

    try:
        if args.command == "keygen":
            signer = signing.EurekaSigner.generate(args.key)
        else:
            signer = signing.EurekaSigner.load(args.key)
    except (signing.KeyFileError, OSError) as exc:
        print(f"lurewall {args.command}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(signer.public_key_hex)
    return EXIT_OK


def _canary_command(args: argparse.Namespace) -> int:
    from lurewall import canaries, labsite

    name = f"lurewall {args.command}"
    try:
        if args.command == "lab-site":
            if args.state.exists():
                canary_set = canaries.load_state(args.state)
            else:
                canary_set = canaries.generate(labsite.site_routes())
                canaries.save_state(canary_set, args.state)
                print(f"generated a new canary set: {args.state}")
            result = labsite.build(
                canary_set, args.out, deploy_root=args.deploy_root, listen=args.listen
            )
            counts = canary_set.lure_counts()
            print(f"site built: {result.web_root}")
            print(f"nginx config: {result.nginx_conf}")
            print(
                f"canaries: {len(canary_set.canaries)} "
                f"({counts['instruction']} instruction, {counts['bait']} bait); "
                f"checked against {len(result.routes)} real routes, no collisions"
            )
            return EXIT_OK
        canary_set = canaries.load_state(args.state)
        if args.canary_command == "rotate":
            ids = list(canaries.PLACEMENTS) if args.all else args.id
            canary_set = canaries.rotate(canary_set, ids, labsite.site_routes())
            canaries.save_state(canary_set, args.state)
            print(f"rotated {len(set(ids))} canaries. Rebuild the site to put them in place.")
            return EXIT_OK
        for canary in canary_set.canaries:
            print(f"{canary.id}\t{canary.lure}\t{canary.path}\t{canary.param}")
        return EXIT_OK
    except canaries.CollisionError as exc:
        print(f"{name}: BUILD FAILED: {exc}", file=sys.stderr)
        return EXIT_FAIL
    except (canaries.CanaryError, OSError) as exc:
        print(f"{name}: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _signals_command(args: argparse.Namespace) -> int:
    from lurewall import canaries, labsite, sigconfig

    try:
        config = sigconfig.load(args.config)
        canary_set = canaries.load_state(args.state)
    except (sigconfig.SignalConfigError, canaries.CanaryError, OSError) as exc:
        print(f"lurewall signals: {exc}", file=sys.stderr)
        return EXIT_USAGE
    routes = labsite.site_routes()
    try:
        sigconfig.check_against_site(config, canary_set, routes)
    except sigconfig.SignalConfigError as exc:
        print(f"lurewall signals: CHECK FAILED: {exc}", file=sys.stderr)
        return EXIT_FAIL
    rules = len(config.exact) + len(config.tree) + len(config.segment)
    print(
        f"signals config fits: {rules} attack-path rules checked against "
        f"{len(canary_set.canaries)} decoys and {len(routes)} real routes; "
        f"block threshold needs {config.distinct_attack_signals} distinct attack signals"
    )
    return EXIT_OK


def _service_command(args: argparse.Namespace) -> int:
    import signal
    import threading

    from lurewall import service
    from lurewall.eventlog import LogLockedError
    from lurewall.signing import KeyFileError

    name = f"lurewall {args.command}"
    try:
        if args.command == "sweep":
            removed, ok = service.sweep(args.event_log, args.key, nft_path=args.nft)
            if removed or not ok:
                print(f"swept {removed} entries" + ("" if ok else "; nft failed"))
            return EXIT_OK if ok else EXIT_FAIL
        running = service.Service(
            service.Paths(
                access_log=args.access_log,
                reader_state=args.reader_state,
                event_log=args.event_log,
                key=args.key,
                canaries=args.canaries,
                signals=args.signals,
                engine_config=args.engine,
                engine_state=args.engine_state,
                checkpoint=args.checkpoint,
            )
        )
    except (ValueError, OSError, KeyFileError, LogLockedError) as exc:
        # Config, canary and key errors are ValueErrors written by Lurewall.
        print(f"{name}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    mode = "dry-run" if running.config.dry_run else f"ENFORCING with {running.config.adapter}"
    print(f"lurewall is running ({mode})", flush=True)
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    try:
        if args.once:
            while running.step():
                pass
        else:
            running.run(stop)
    finally:
        running.close()
    return EXIT_OK


def _engine_command(args: argparse.Namespace) -> int:
    from lurewall import engine

    if args.command == "alerts":
        try:
            engine.clear_alert(args.state)
        except OSError as exc:
            print(f"lurewall alerts: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print("alert cleared")
        return EXIT_OK
    try:
        status = engine.read_status(args.state)
    except FileNotFoundError:
        print("no engine state yet: no blocks, no alert")
        return EXIT_OK
    except (OSError, ValueError):
        print("lurewall status: the engine state file could not be read", file=sys.stderr)
        return EXIT_USAGE
    if status["alert_standing"]:
        print("WARNING: the block cap was reached and new blocks were refused.")
        print("         Review, then run `lurewall alerts clear`.")
    enforced = status["enforced_blocks"]
    print(
        f"active blocks: {status['active_blocks']} "
        f"({enforced} enforced, {status['active_blocks'] - enforced} dry-run)"
    )
    print(f"sources with a counted canary hit: {status['sources_with_canary_hit']}")
    for expiry, source, is_enforced in status["blocks"]:
        kind = "enforced" if is_enforced else "dry-run"
        print(f"  {source}\t{kind}\texpires at {expiry} ms")
    # A standing alert is a failing status, so a monitor can watch the exit code.
    return EXIT_FAIL if status["alert_standing"] else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "verify":
        return _verify(args)
    if args.command in ("lab-site", "canaries"):
        return _canary_command(args)
    if args.command == "signals":
        return _signals_command(args)
    if args.command in ("run", "sweep"):
        return _service_command(args)
    if args.command in ("status", "alerts"):
        return _engine_command(args)
    return _key_command(args)


if __name__ == "__main__":
    sys.exit(main())
