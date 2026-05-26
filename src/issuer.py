from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization

DEFAULT_DB_PATH = Path("seats.db")
DEFAULT_PRIVATE_KEY_PATH = Path("private_key.pem")
DEFAULT_MAX_SEATS = 2


class SeatCapError(RuntimeError):
    """Raised when the seat cap has been reached."""


def _init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS issued_licenses (
            license_id   TEXT PRIMARY KEY,
            machine_fingerprint TEXT UNIQUE,
            issued_at    TEXT
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
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    max_seats: int = DEFAULT_MAX_SEATS,
    minutes_valid: int = 60,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Sign and store a license. Returns the license dict (payload + signature)."""
    if now is None:
        now = datetime.now(timezone.utc)

    conn = _init_db(db_path)

    existing = conn.execute(
        "SELECT license_id FROM issued_licenses WHERE machine_fingerprint = ?",
        (machine_fingerprint,),
    ).fetchone()
    if existing:
        raise RuntimeError(
            f"License already issued for this machine ({existing[0]})."
        )

    seats_used = _count_seats(conn)
    if seats_used >= max_seats:
        raise SeatCapError(
            f"Seat cap reached ({seats_used}/{max_seats}). "
            "No more licenses can be issued."
        )

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )

    payload: Dict[str, Any] = {
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
    signature_b64 = base64.b64encode(private_key.sign(payload_bytes)).decode("ascii")

    conn.execute(
        "INSERT INTO issued_licenses (license_id, machine_fingerprint, issued_at) VALUES (?, ?, ?)",
        (payload["license_id"], machine_fingerprint, now.isoformat()),
    )
    conn.commit()

    return {"payload": payload, "signature": signature_b64}


def issue_and_write(
    machine_fingerprint: str,
    features: List[str],
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    max_seats: int = DEFAULT_MAX_SEATS,
    minutes_valid: int = 60,
) -> Path:
    """issue_license + write to disk. Used by the CLI."""
    lic = issue_license(
        machine_fingerprint, features, private_key_path, db_path, max_seats, minutes_valid
    )
    filename = Path(f"license_{machine_fingerprint[:8]}.json")
    filename.write_text(json.dumps(lic, indent=2))

    seats_used = _count_seats(_init_db(db_path))
    print(f"Issued {lic['payload']['license_id']}")
    print(f"  machine : {machine_fingerprint}")
    print(f"  features: {', '.join(features)}")
    print(f"  valid   : {minutes_valid} minutes")
    print(f"  file    : {filename}")
    print(f"  seats   : {seats_used}/{max_seats}")
    print("Send this file to the client as license.json")
    return filename
