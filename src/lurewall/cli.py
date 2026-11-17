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


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "verify":
        return _verify(args)
    return _key_command(args)


if __name__ == "__main__":
    sys.exit(main())
