from pathlib import Path
from src.fingerprint import get_machine_fingerprint
from src.license_core import (
    load_and_verify_license,
    LicenseError,
    DEFAULT_LICENSE_PATH,
    DEFAULT_PUBLIC_KEY_PATH,
    DEFAULT_LAST_SEEN_PATH,
)


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

    commands = {
        "rag":       ("rag_chat",    "[RAG] Running a semantic search query... done."),
        "transcribe":("transcriber", "[Transcriber] Transcribing audio... done."),
        "summarize": ("summarizer",  "[Summarizer] Summarizing document... done."),
    }

    print("Commands: rag | transcribe | summarize | info | quit")
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
        elif cmd in commands:
            feature_key, success_msg = commands[cmd]
            if feature_key in lic.features:
                print(success_msg)
            else:
                print(f"[DENIED] Feature '{feature_key}' is not enabled in your license.")
        elif cmd == "":
            continue
        else:
            print(f"Unknown command '{cmd}'. Try: rag | transcribe | summarize | info | quit")


if __name__ == "__main__":
    main()
