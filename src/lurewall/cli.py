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
    build.add_argument(
        "--checkpoint-file",
        help="serve this signed checkpoint file at /lurewall-checkpoint.json (absolute path)",
    )

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

    lab = commands.add_parser("lab", help="the lab test harness (run on the Mac or Alienware)")
    lab_commands = lab.add_subparsers(dest="lab_command", required=True)
    lab_commands.add_parser("list", help="list the test cases")
    case = lab_commands.add_parser(
        "case",
        help="run one test case from this machine and record the run in the ledger",
        description="Plain GET requests to the lab target only. Refuses any public address.",
    )
    case.add_argument("number", type=int, help="the case number (1-20)")
    case.add_argument(
        "--from", dest="source", required=True, help="mac, alienware, or this machine's LAN IP"
    )
    case.add_argument("--target", default="http://192.168.1.160", help="the lab site")
    case.add_argument("--ledger", type=Path, help="the run ledger (default ~/lurewall-lab)")
    case.add_argument("--label", default="", help="agent, model and version, for agent cases")
    case.add_argument("--part", default="", help="cases 10 and 12: which half of the case")
    case.add_argument("--reference", default="", help="case 10: the reference to request")
    case.add_argument("--scripted", action="store_true", help="case 2: scripted rehearsal")
    case.add_argument("--watch", action="store_true", help="case 13: time the block")
    results = lab_commands.add_parser(
        "results",
        help="verify the signed log, join it with the ledger, write results.md and results.csv",
        description="Exit status: 0 written, 1 the log does not verify, 2 inputs unusable.",
    )
    results.add_argument("--log", required=True, type=Path, help="a copy of the signed log")
    results.add_argument("--pubkey", required=True, help="the published public key, or a file")
    results.add_argument("--anchors", action="append", type=Path, default=[], metavar="PATH")
    results.add_argument(
        "--ledger",
        action="append",
        type=Path,
        default=[],
        help="a run ledger (repeatable: one from each client; default ~/lurewall-lab)",
    )
    results.add_argument("--out", required=True, type=Path, help="output directory")
    results.add_argument(
        "--allow-unverified", action="store_true", help="export anyway, marked UNVERIFIED"
    )
    tamper = lab_commands.add_parser("tamper", help="case 6: verify four damaged copies of a log")
    tamper.add_argument("--log", required=True, type=Path, help="a copy of the signed log")
    tamper.add_argument("--pubkey", required=True, help="the published public key, or a file")
    tamper.add_argument("--anchors", action="append", type=Path, default=[], metavar="PATH")
    tamper.add_argument("--work", required=True, type=Path, help="where to write the copies")

    checkpoint = commands.add_parser("checkpoint", help="the anchored checkpoints")
    checkpoint_commands = checkpoint.add_subparsers(dest="checkpoint_command", required=True)
    pull = checkpoint_commands.add_parser(
        "pull",
        help="fetch the lab's checkpoint, check it, store and commit it (Mac job)",
        description=(
            "Exit status: 0 stored or unchanged, 1 refused (bad signature, a different "
            "checkpoint for a stored sequence number, or one that went backwards), "
            "2 not fetched."
        ),
    )
    pull.add_argument(
        "--url", default="http://192.168.1.160/lurewall-checkpoint.json", help="checkpoint URL"
    )
    pull.add_argument("--pubkey", required=True, help="the published public key, or a file")
    pull.add_argument("--repo", required=True, type=Path, help="local checkpoints repository")
    pull.add_argument("--ots", help="path to the OpenTimestamps client, to stamp each checkpoint")
    pull.add_argument("--push", action="store_true", help="git push after committing")
    return parser


def _lab_command(args: argparse.Namespace) -> int:
    from lurewall import labcases, labclient, results, signing, verify

    name = f"lurewall lab {args.lab_command}"
    if args.lab_command == "list":
        for case in labcases.CASES.values():
            flag = " [dry-run only]" if case.dry_run_only else ""
            print(f"{case.number:>2}  {case.kind:<8} {case.title}{flag}")
        return EXIT_OK
    if args.lab_command == "case":
        ledger = args.ledger or labcases.default_ledger()
        case = labcases.CASES.get(args.number)
        if case is None:
            print(f"{name}: no case {args.number}", file=sys.stderr)
            return EXIT_USAGE
        try:
            client = labclient.Client(labclient.parse_target(args.target))
            ctx = labcases.Context(
                client=client,
                source=labcases.source_address(args.source),
                label=args.label,
                part=args.part,
                reference=args.reference,
                scripted=args.scripted,
                watch=args.watch,
            )
            print(f"case {case.number}: {case.title}")
            print(f"  expected: {case.expect}")
            record = labcases.run_case(case, ctx)
        except ValueError as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        labcases.append_run(ledger, record)
        print(f"recorded run {record['run']}: {record['sent']} requests, {record['statuses']}")
        return EXIT_OK
    try:
        public_key = signing.read_public_key(args.pubkey)
    except ValueError as exc:
        print(f"{name}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.lab_command == "tamper":
        try:
            anchored, _ = verify.load_anchors(args.anchors, public_key)
            copies = labcases.tamper_copies(args.log, args.work, anchored)
        except (OSError, ValueError) as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        caught = 0
        for kind, path in copies.items():
            report = verify.verify_log(path, public_key, args.anchors)
            bad = report.bad_entry
            if bad is not None:
                where = f"first bad entry at line {bad.line} ({bad.reason})"
            elif report.truncated_missing:
                where = (
                    f"truncated: {report.truncated_missing} entries missing after the last "
                    f"anchor match (seq {report.last_matched_anchor_seq})"
                )
            else:
                where = "NOT CAUGHT"
            caught += not report.ok
            print(f"{kind:<9} {where}")
        return EXIT_OK if caught == len(copies) else EXIT_FAIL
    try:
        runs = [
            run for path in (args.ledger or [labcases.default_ledger()])
            for run in labcases.read_runs(path)
        ]  # fmt: skip
        runs.sort(key=lambda run: run["started_ms"])
        report, rows, written = results.export(
            args.log,
            public_key,
            args.anchors,
            runs,
            args.out,
            allow_unverified=args.allow_unverified,
        )
    except (OSError, ValueError) as exc:
        print(f"{name}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if not written:
        print(f"{name}: the log does not verify; nothing exported", file=sys.stderr)
        print(verify.format_report(report), file=sys.stderr)
        return EXIT_FAIL
    if not args.anchors:
        print("note: no anchors given, so truncation after the last entry cannot be seen")
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.verdict] = counts.get(row.verdict, 0) + 1
    print(", ".join(f"{count} {verdict}" for verdict, count in sorted(counts.items())))
    for path in written:
        print(f"wrote {path}")
    return EXIT_OK if report.ok else EXIT_FAIL


def _checkpoint_command(args: argparse.Namespace) -> int:
    from lurewall import anchorjob, signing

    try:
        public_key = signing.read_public_key(args.pubkey)
        result = anchorjob.pull(args.url, public_key, args.repo, ots=args.ots, push=args.push)
    except (ValueError, OSError) as exc:
        print(f"lurewall checkpoint pull: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if result.status == "fetch_failed":
        print("lurewall checkpoint pull: could not fetch the checkpoint", file=sys.stderr)
        return EXIT_USAGE
    done = [word for word, flag in (("stamped", result.stamped), ("committed", result.committed),
            ("pushed", result.pushed)) if flag]  # fmt: skip
    print(f"checkpoint {result.seq}: {result.status}" + (f" ({', '.join(done)})" if done else ""))
    return EXIT_OK if result.ok else EXIT_FAIL


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
                canary_set,
                args.out,
                deploy_root=args.deploy_root,
                listen=args.listen,
                checkpoint_file=args.checkpoint_file,
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
    if args.command == "lab":
        return _lab_command(args)
    if args.command == "checkpoint":
        return _checkpoint_command(args)
    return _key_command(args)


if __name__ == "__main__":
    sys.exit(main())
