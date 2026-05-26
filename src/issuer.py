import base64
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

DB_PATH = Path("seats.db")
PRIVATE_KEY_PATH = Path("private_key.pem")
MAX_SEATS = 2


def _load_private_key() -> Ed25519PrivateKey:
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(
            "private_key.pem not found. Run: onemachine-license keygen"
        )
    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(), password=None
    )


def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS issued_licenses (
            license_id TEXT PRIMARY KEY,
            machine_fingerprint TEXT UNIQUE,
            issued_at TEXT
        )
        """
    )
    conn.commit()
    return conn


def _count_seats(conn: sqlite3.Connection) -> int:
    (count,) = conn.execute("SELECT COUNT(*) FROM issued_licenses").fetchone()
    return count


def issue_license(
    machine_fingerprint: str,
    features: List[str],
    minutes_valid: int = 60,
) -> None:
    conn = _init_db()

    # Check for duplicate fingerprint
    existing = conn.execute(
        "SELECT license_id FROM issued_licenses WHERE machine_fingerprint = ?",
        (machine_fingerprint,),
    ).fetchone()
    if existing:
        raise RuntimeError(
            f"License already issued for this machine ({existing[0]}). "
            "Revoke it first or use a new fingerprint."
        )

    seats_used = _count_seats(conn)
    if seats_used >= MAX_SEATS:
        raise RuntimeError(
            f"Seat cap reached ({MAX_SEATS}/{MAX_SEATS}). "
            "No more licenses can be issued."
        )

    private_key = _load_private_key()
    now = datetime.now(timezone.utc)

    payload = {
        "license_id": f"L-{seats_used + 1:04d}",
        "customer": "DemoCorp",
        "machine_fingerprint": machine_fingerprint,
        "not_before": now.isoformat().replace("+00:00", "Z"),
        "not_after": (now + timedelta(minutes=minutes_valid))
        .isoformat()
        .replace("+00:00", "Z"),
        "features": features,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "max_version": "1.0.0",
    }

    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    license_obj = {"payload": payload, "signature": signature_b64}
    filename = f"license_{machine_fingerprint[:8]}.json"
    Path(filename).write_text(json.dumps(license_obj, indent=2))

    conn.execute(
        "INSERT INTO issued_licenses (license_id, machine_fingerprint, issued_at) VALUES (?, ?, ?)",
        (payload["license_id"], machine_fingerprint, now.isoformat()),
    )
    conn.commit()

    print(f"Issued {payload['license_id']}")
    print(f"  machine : {machine_fingerprint}")
    print(f"  features: {', '.join(features)}")
    print(f"  valid   : {minutes_valid} minutes")
    print(f"  file    : {filename}")
    print(f"  seats   : {seats_used + 1}/{MAX_SEATS}")
    print("Send this file to the client as license.json")


if __name__ == "__main__":
    fp = input("Machine fingerprint: ").strip()
    feats = [f.strip() for f in input("Features: ").split(",") if f.strip()]
    mins = int(input("Minutes valid: ").strip() or "60")
    issue_license(fp, feats, mins)
