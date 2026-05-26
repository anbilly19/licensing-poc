from pathlib import Path
from src.fingerprint import get_machine_fingerprint
from src.license_core import (
    load_and_verify_license,
    License,
    LicenseError,
    DEFAULT_LICENSE_PATH,
    DEFAULT_PUBLIC_KEY_PATH,
    DEFAULT_LAST_SEEN_PATH,
)


class FeatureNotEnabledError(Exception):
    """Raised when a feature is not enabled in the license."""


def _require_feature(lic: License, feature: str) -> None:
    if feature not in lic.features:
        raise FeatureNotEnabledError(
            f"Feature '{feature}' is not enabled in your license."
        )


def run_rag(lic: License) -> str:
    _require_feature(lic, "rag_chat")
    return "[RAG] Query executed."


def run_transcriber(lic: License) -> str:
    _require_feature(lic, "transcriber")
    return "[Transcriber] Audio transcribed."


def run_nl_sql(lic: License) -> str:
    _require_feature(lic, "nl_sql")
    return "[NL-SQL] Query generated."


def run_reports(lic: License) -> str:
    _require_feature(lic, "reports")
    return "[Reports] Report generated."


_COMMANDS = {
    "rag":        (run_rag,         "rag_chat"),
    "transcribe": (run_transcriber, "transcriber"),
    "sql":        (run_nl_sql,      "nl_sql"),
    "reports":    (run_reports,     "reports"),
}


def main() -> None:
    fp = get_machine_fingerprint()

    try:
        lic = load_and_verify_license(
            license_path=DEFAULT_LICENSE_PATH,
            public_key_path=DEFAULT_PUBLIC_KEY_PATH,
            expected_fingerprint=fp,
            last_seen_path=DEFAULT_LAST_SEEN_PATH,
        )
    except LicenseError as exc:
        print(f"[LICENSE ERROR] {exc}")
        return

    print()
    print("=" * 50)
    print("  OneMachine Licensing POC")
    print("=" * 50)
    print(f"  License ID : {lic.license_id}")
    print(f"  Customer   : {lic.customer}")
    print(f"  Valid until: {lic.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Features   : {', '.join(lic.features)}")
    print("=" * 50)
    print()
    print("Commands: rag | transcribe | sql | reports | info | quit")
    print()

    while True:
        try:
            cmd = input("onemachine> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if cmd == "quit":
            print("Goodbye.")
            break
        elif cmd == "info":
            print(f"  License : {lic.license_id}")
            print(f"  Features: {', '.join(lic.features)}")
        elif cmd in _COMMANDS:
            fn, _ = _COMMANDS[cmd]
            try:
                print(fn(lic))
            except FeatureNotEnabledError as exc:
                print(f"[DENIED] {exc}")
        elif cmd == "":
            continue
        else:
            print(f"Unknown command '{cmd}'. Try: rag | transcribe | sql | reports | info | quit")


if __name__ == "__main__":
    main()
