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
    """Raised when the seat cap has been reached by a new (unknown) machine."""


def _init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS issued_licenses (
            license_id          TEXT PRIMARY KEY,
            machine_fingerprint TEXT UNIQUE,
            issued_at           TEXT
        )
        """
    )
    conn.commit()
    return conn


def _count_unique_machines(conn: sqlite3.Connection) -> int:
    (count,) = conn.execute(
        "SELECT COUNT(DISTINCT machine_fingerprint) FROM issued_licenses"
    ).fetchone()
    return count


def _is_known_machine(conn: sqlite3.Connection, machine_fingerprint: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM issued_licenses WHERE machine_fingerprint = ?",
        (machine_fingerprint,),
    ).fetchone()
    return row is not None


def issue_license(
    machine_fingerprint: str,
    features: List[str],
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    max_seats: int = DEFAULT_MAX_SEATS,
    minutes_valid: int = 60,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Sign and store a license.

    - Known machines (renewals): always allowed, overwrites the existing seat.
    - New machines: blocked if seat cap is reached.
    Returns the license dict {payload, signature}.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    conn = _init_db(db_path)
    is_renewal = _is_known_machine(conn, machine_fingerprint)

    if not is_renewal:
        seats_used = _count_unique_machines(conn)
        if seats_used >= max_seats:
            raise SeatCapError(
                f"Seat cap reached ({seats_used}/{max_seats}). "
                "No more new machines can be licensed."
            )

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )

    # Determine license_id: reuse existing id for renewals
    existing = conn.execute(
        "SELECT license_id FROM issued_licenses WHERE machine_fingerprint = ?",
        (machine_fingerprint,),
    ).fetchone()
    if existing:
        license_id = existing[0]
    else:
        seat_number = _count_unique_machines(conn) + 1
        license_id = f"L-{seat_number:04d}"

    payload: Dict[str, Any] = {
        "license_id": license_id,
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

    # Upsert: insert new or update existing seat
    conn.execute(
        """
        INSERT INTO issued_licenses (license_id, machine_fingerprint, issued_at)
        VALUES (?, ?, ?)
        ON CONFLICT(machine_fingerprint) DO UPDATE SET
            license_id = excluded.license_id,
            issued_at  = excluded.issued_at
        """,
        (license_id, machine_fingerprint, now.isoformat()),
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
    conn = _init_db(db_path)
    is_renewal = _is_known_machine(conn, machine_fingerprint)

    lic = issue_license(
        machine_fingerprint, features, private_key_path, db_path, max_seats, minutes_valid
    )

    filename = Path(f"license_{machine_fingerprint[:8]}.json")
    filename.write_text(json.dumps(lic, indent=2))

    seats_used = _count_unique_machines(_init_db(db_path))
    action = "Renewed" if is_renewal else "Issued"
    print(f"{action} {lic['payload']['license_id']}")
    print(f"  machine : {machine_fingerprint}")
    print(f"  features: {', '.join(features)}")
    print(f"  valid   : {minutes_valid} minutes")
    print(f"  file    : {filename}")
    print(f"  seats   : {seats_used}/{max_seats} unique machines")
    if is_renewal:
        print("  [renewal — existing seat updated, no new seat consumed]")
    print("Send this file to the client as license.json")
    return filename
