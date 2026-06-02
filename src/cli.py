"""poc-license -- unified CLI entry point.

Subcommands
-----------
  keygen       (Vendor) Generate Ed25519 keypair
  fingerprint  (Client) Print + save machine fingerprint
  issue        (Vendor) Sign and write a license file
  create-key   (Vendor) Register an activation key for a customer in seats.db
  activate     (Client) Activate this machine against the online server
  heartbeat    (Client) Force a heartbeat / license renewal check now
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
        max_seats=args.max_seats,
    )


def cmd_create_key(args: argparse.Namespace) -> None:
    from src.issuer import create_activation_key
    features = [f.strip() for f in args.features.split(",") if f.strip()]
    create_activation_key(
        activation_key=args.activation_key,
        customer_id=args.customer_id,
        customer_name=args.customer_name,
        max_seats=args.max_seats,
        features=features,
        license_minutes=args.license_minutes,
        subscription_days=args.subscription_days,
        db_path=Path(args.db) if args.db else Path("seats.db"),
    )


def cmd_activate(args: argparse.Namespace) -> None:
    from src.fingerprint import get_machine_fingerprint
    from src.activation_client import activate
    fp = get_machine_fingerprint()
    activate(
        activation_key=args.activation_key,
        machine_fingerprint=fp,
        license_path=Path(args.license_out),
    )


def cmd_heartbeat(args: argparse.Namespace) -> None:
    from src.fingerprint import get_machine_fingerprint
    from src.activation_client import heartbeat
    fp = get_machine_fingerprint()
    refreshed = heartbeat(
        license_path=Path(args.license),
        machine_fingerprint=fp,
        force=True,
    )
    if not refreshed:
        print("Heartbeat: no renewal was performed (server returned not-valid or network error).")


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
    customer = license_obj.get("payload", {}).get("customer", "unknown")
    customer_id = license_obj.get("payload", {}).get("customer_id", "")

    print("Bundle installed successfully.")
    print(f"  public_key.pem  -> written")
    print(f"  license.json    -> written")
    print(f"  customer        : {customer} ({customer_id})")
    print(f"  machine         : {fp}...")
    print(f"  valid until     : {not_after}")
    print(f"  features        : {', '.join(features)}")
    print("Run: poc-license demo")


def cmd_demo(_args: argparse.Namespace) -> None:
    from src.demo_app import main as _demo
    _demo()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="poc-license",
        description="Licensing POC",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    sub.add_parser("keygen", help="(Vendor) Generate Ed25519 keypair")
    sub.add_parser(
        "fingerprint",
        help="(Client) Print machine fingerprint and save to fingerprint.txt",
    )

    # --- issue (vendor, manual/dev) ---
    p_issue = sub.add_parser("issue", help="(Vendor) Issue a signed license directly")
    p_issue.add_argument("--fingerprint", required=True, metavar="HEX")
    p_issue.add_argument("--features", default="rag_chat,transcriber", metavar="FEAT1,FEAT2")
    p_issue.add_argument("--minutes", type=float, default=60.0, metavar="N",
                         help="License validity in minutes; floats allowed e.g. 0.5 = 30 seconds (default: 60)")
    p_issue.add_argument("--max-seats", type=int, default=2, metavar="N")
    p_issue.add_argument("--bundle", action="store_true", default=False)

    # --- create-key (vendor) ---
    p_ck = sub.add_parser(
        "create-key",
        help="(Vendor) Register an activation key for a customer in seats.db",
    )
    p_ck.add_argument("--activation-key",   required=True, metavar="KEY",
                      help="e.g. MULL-2024-ABCD-EFGH")
    p_ck.add_argument("--customer-id",      required=True, metavar="ID",
                      help="e.g. cust-de-0042")
    p_ck.add_argument("--customer-name",    required=True, metavar="NAME",
                      help="e.g. 'M\u00fcller GmbH'")
    p_ck.add_argument("--max-seats",        type=int, default=2, metavar="N")
    p_ck.add_argument("--features",         default="rag_chat,transcriber", metavar="FEAT1,FEAT2")
    p_ck.add_argument("--license-minutes",  type=float, default=10080.0, metavar="N",
                      help="How long each issued license.json window lasts in minutes "
                           "(default: 10080 = 7 days). Heartbeat renews with this same window.")
    p_ck.add_argument("--subscription-days", type=float, default=365.0, metavar="N",
                      help="How long the activation key itself stays valid in days "
                           "(default: 365). After this the server refuses renewals.")
    p_ck.add_argument("--db",               default=None, metavar="PATH",
                      help="Path to seats.db (default: seats.db)")

    # --- activate (client) ---
    p_act = sub.add_parser(
        "activate",
        help="(Client) Activate this machine against the online activation server",
    )
    p_act.add_argument("--activation-key", required=True, metavar="KEY",
                       help="Activation key provided by your vendor")
    p_act.add_argument("--license-out",    default="license.json", metavar="PATH",
                       help="Where to write the license file (default: license.json)")

    # --- heartbeat (client) ---
    p_hb = sub.add_parser(
        "heartbeat",
        help="(Client) Force a heartbeat / license renewal check now",
    )
    p_hb.add_argument("--license", default="license.json", metavar="PATH")

    # --- install (dev/legacy) ---
    p_install = sub.add_parser(
        "install",
        help="(Dev) Install a license bundle — extracts public_key.pem + license.json",
    )
    p_install.add_argument("bundle_file", metavar="BUNDLE_FILE")

    sub.add_parser("demo", help="(Client) Run feature-gated demo REPL")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    dispatch = {
        "keygen":      cmd_keygen,
        "fingerprint": cmd_fingerprint,
        "issue":       cmd_issue,
        "create-key":  cmd_create_key,
        "activate":    cmd_activate,
        "heartbeat":   cmd_heartbeat,
        "install":     cmd_install,
        "demo":        cmd_demo,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
