import base64
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SeatCapError(Exception):
    pass


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS issued_licenses (
            license_id   TEXT PRIMARY KEY,
            machine_fingerprint TEXT,
            issued_at    TEXT
        )
        """
    )
    conn.commit()
    return conn


def _seat_count(conn: sqlite3.Connection) -> int:
    (count,) = conn.execute("SELECT COUNT(*) FROM issued_licenses").fetchone()
    return count


def issue_license(
    machine_fingerprint: str,
    features: List[str],
    private_key_path: Path,
    db_path: Path,
    max_seats: int = 2,
    minutes_valid: int = 5,
    now: Optional[datetime] = None,
) -> dict:
    conn = _init_db(db_path)
    if _seat_count(conn) >= max_seats:
        raise SeatCapError(f"Seat cap reached ({max_seats})")

    if now is None:
        now = datetime.now(timezone.utc)

    private_key = _load_private_key(private_key_path)
    payload = {
        "license_id": f"L-{_seat_count(conn) + 1:04d}",
        "customer": "DemoCorp",
        "machine_fingerprint": machine_fingerprint,
        "not_before": now.isoformat().replace("+00:00", "Z"),
        "not_after": (now + timedelta(minutes=minutes_valid)).isoformat().replace("+00:00", "Z"),
        "features": features,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "max_version": "1.0.0",
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = base64.b64encode(private_key.sign(payload_bytes)).decode()
    license_obj = {"payload": payload, "signature": signature}

    conn.execute(
        "INSERT INTO issued_licenses (license_id, machine_fingerprint, issued_at) VALUES (?, ?, ?)",
        (payload["license_id"], machine_fingerprint, now.isoformat()),
    )
    conn.commit()
    return license_obj
