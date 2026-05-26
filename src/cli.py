"""onemachine-license -- unified CLI entry point.

Subcommands
-----------
  keygen       (Vendor) Generate Ed25519 keypair
  fingerprint  (Client) Print + save machine fingerprint
  issue        (Vendor) Sign and write a license file (use --bundle for single-file delivery)
  install      (Client) Install a license bundle (extracts public_key.pem + license.json)
  demo         (Client) Run the feature-gated demo REPL
"""
from __future__ import annotations

import argparse
from pathlib import Path


def cmd_keygen(_args: argparse.Namespace) -> None:
    from src.keygen import generate_keypair
    generate_keypair(Path("private_key.pem"), Path("public_key.pem"))
    print("Keys written: private_key.pem, public_key.pem")
    print("Copy public_key.pem to each client machine (or use --bundle on issue).")


def cmd_fingerprint(_args: argparse.Namespace) -> None:
    from src.fingerprint import get_machine_fingerprint
    fp = get_machine_fingerprint()
    print(fp)
    Path("fingerprint.txt").write_text(fp)
    print("[saved to fingerprint.txt -- send this to the vendor]")


def cmd_issue(args: argparse.Namespace) -> None:
    from src.issuer import issue_and_write
    features = [f.strip() for f in args.features.split(",") if f.strip()]
    issue_and_write(
        machine_fingerprint=args.fingerprint,
        features=features,
        private_key_path=Path("private_key.pem"),
        db_path=Path("seats.db"),
        minutes_valid=args.minutes,
        bundle=args.bundle,
    )


def cmd_install(args: argparse.Namespace) -> None:
    """Extract public_key.pem + license.json from a bundle file."""
    import json
    bundle_path = Path(args.bundle_file)
    if not bundle_path.exists():
        print(f"Error: {bundle_path} not found.")
        return

    try:
        data = json.loads(bundle_path.read_text())
        public_key_pem: str = data["public_key"]
        license_obj: dict = data["license"]
    except (KeyError, json.JSONDecodeError) as e:
        print(f"Error: invalid bundle file ({e}).")
        return

    Path("public_key.pem").write_text(public_key_pem)
    Path("license.json").write_text(json.dumps(license_obj, indent=2))

    fp = license_obj.get("payload", {}).get("machine_fingerprint", "unknown")[:8]
    not_after = license_obj.get("payload", {}).get("not_after", "unknown")
    features = license_obj.get("payload", {}).get("features", [])

    print("Bundle installed successfully.")
    print(f"  public_key.pem  -> written")
    print(f"  license.json    -> written")
    print(f"  machine         : {fp}...")
    print(f"  valid until     : {not_after}")
    print(f"  features        : {', '.join(features)}")
    print("Run: onemachine-license demo")


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

    sub.add_parser("keygen", help="(Vendor) Generate Ed25519 keypair")
    sub.add_parser(
        "fingerprint",
        help="(Client) Print machine fingerprint and save to fingerprint.txt",
    )

    p_issue = sub.add_parser("issue", help="(Vendor) Issue a signed license")
    p_issue.add_argument(
        "--fingerprint", required=True, metavar="HEX",
        help="Machine fingerprint from the client (64-char hex)",
    )
    p_issue.add_argument(
        "--features", default="rag_chat,transcriber", metavar="FEAT1,FEAT2",
        help="Comma-separated feature list (default: rag_chat,transcriber)",
    )
    p_issue.add_argument(
        "--minutes", type=int, default=60, metavar="N",
        help="License validity in minutes (default: 60)",
    )
    p_issue.add_argument(
        "--bundle", action="store_true", default=False,
        help="Also write a license_bundle_<fp8>.json with public_key embedded (send this single file to client)",
    )

    p_install = sub.add_parser(
        "install",
        help="(Client) Install a license bundle — extracts public_key.pem + license.json",
    )
    p_install.add_argument(
        "bundle_file", metavar="BUNDLE_FILE",
        help="Path to license_bundle_<fp8>.json received from vendor",
    )

    sub.add_parser("demo", help="(Client) Run feature-gated demo REPL")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    dispatch = {
        "keygen": cmd_keygen,
        "fingerprint": cmd_fingerprint,
        "issue": cmd_issue,
        "install": cmd_install,
        "demo": cmd_demo,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
