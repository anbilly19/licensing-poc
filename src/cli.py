"""onemachine-license -- unified CLI entry point.

Subcommands
-----------
  keygen       (Vendor) Generate Ed25519 keypair
  fingerprint  (Client) Print + save machine fingerprint
  issue        (Vendor) Sign and write a license file
  demo         (Client) Run the feature-gated demo REPL
"""
from __future__ import annotations

import argparse
import sys


def cmd_keygen(_args: argparse.Namespace) -> None:
    from src.keygen import main as _keygen
    _keygen()


def cmd_fingerprint(_args: argparse.Namespace) -> None:
    from src.fingerprint import get_machine_fingerprint
    from pathlib import Path

    fp = get_machine_fingerprint()
    print(fp)
    Path("fingerprint.txt").write_text(fp)
    print("[saved to fingerprint.txt -- send this to the vendor]")


def cmd_issue(args: argparse.Namespace) -> None:
    from src.issuer import issue_license

    features = [f.strip() for f in args.features.split(",") if f.strip()]
    issue_license(
        machine_fingerprint=args.fingerprint,
        features=features,
        minutes_valid=args.minutes,
    )


def cmd_demo(_args: argparse.Namespace) -> None:
    from src.demo_app import main as _demo
    _demo()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onemachine-license",
        description="OneMachine Licensing POC",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # keygen
    sub.add_parser("keygen", help="(Vendor) Generate Ed25519 keypair")

    # fingerprint
    sub.add_parser(
        "fingerprint",
        help="(Client) Print machine fingerprint and save to fingerprint.txt",
    )

    # issue
    p_issue = sub.add_parser("issue", help="(Vendor) Issue a signed license")
    p_issue.add_argument(
        "--fingerprint",
        required=True,
        metavar="HEX",
        help="Machine fingerprint from the client (64-char hex)",
    )
    p_issue.add_argument(
        "--features",
        default="rag_chat,transcriber",
        metavar="FEAT1,FEAT2",
        help="Comma-separated feature list (default: rag_chat,transcriber)",
    )
    p_issue.add_argument(
        "--minutes",
        type=int,
        default=60,
        metavar="N",
        help="License validity in minutes (default: 60)",
    )

    # demo
    sub.add_parser("demo", help="(Client) Run feature-gated demo REPL")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "keygen": cmd_keygen,
        "fingerprint": cmd_fingerprint,
        "issue": cmd_issue,
        "demo": cmd_demo,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
