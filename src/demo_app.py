import sys
from pathlib import Path

from src.fingerprint import get_machine_fingerprint
from src.license_core import load_and_verify_license, LicenseError, License


class FeatureNotEnabledError(Exception):
    pass


def require_feature(license: License, feature: str) -> None:
    if feature not in license.features:
        raise FeatureNotEnabledError(f"Feature '{feature}' not enabled in your license")


def run_rag(license: License) -> str:
    require_feature(license, "rag_chat")
    return "[RAG] Query executed."


def run_transcriber(license: License) -> str:
    require_feature(license, "transcriber")
    return "[Transcriber] Audio transcribed."


def run_nl_sql(license: License) -> str:
    require_feature(license, "nl_sql")
    return "[NL-SQL] Query generated."


def run_reports(license: License) -> str:
    require_feature(license, "reports")
    return "[Reports] Report generated."


COMMANDS = {
    "rag": run_rag,
    "transcribe": run_transcriber,
    "nlsql": run_nl_sql,
    "reports": run_reports,
}


def main(
    license_path: Path = Path("license.json"),
    public_key_path: Path = Path("public_key.pem"),
    last_seen_path: Path = Path("last_seen.json"),
):
    fp = get_machine_fingerprint()
    try:
        lic = load_and_verify_license(license_path, public_key_path, fp, last_seen_path)
    except LicenseError as e:
        print(f"License error: {e}")
        sys.exit(1)

    print(f"License {lic.license_id} | {lic.customer} | valid until {lic.not_after}")
    print(f"Features: {', '.join(lic.features)}")
    print("Commands: " + ", ".join(COMMANDS) + ", quit")

    while True:
        cmd = input("> ").strip().lower()
        if cmd == "quit":
            break
        elif cmd in COMMANDS:
            try:
                print(COMMANDS[cmd](lic))
            except FeatureNotEnabledError as e:
                print(f"Access denied: {e}")
        else:
            print(f"Unknown command: {cmd!r}")


if __name__ == "__main__":
    main()
