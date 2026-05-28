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


class InvalidActivationKeyError(RuntimeError):
    """Raised when the activation key is not found or has expired."""


def _init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS issued_licenses (
            license_id          TEXT PRIMARY KEY,
            machine_fingerprint TEXT UNIQUE,
            customer_id         TEXT,
            activation_key      TEXT,
            issued_at           TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS activation_keys (
            activation_key      TEXT PRIMARY KEY,
            customer_id         TEXT NOT NULL,
            customer_name       TEXT NOT NULL,
            max_seats           INTEGER NOT NULL DEFAULT 2,
            features            TEXT NOT NULL DEFAULT 'rag_chat',
            license_minutes     REAL NOT NULL DEFAULT 10080,
            subscription_days   REAL NOT NULL DEFAULT 365,
            created_at          TEXT NOT NULL,
            expires_at          TEXT
        )
        """
    )
    # Migrate old schema: add new columns if they don't exist yet.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(activation_keys)")}
    if "license_minutes" not in existing:
        conn.execute(
            "ALTER TABLE activation_keys ADD COLUMN license_minutes REAL NOT NULL DEFAULT 10080"
        )
    if "subscription_days" not in existing:
        conn.execute(
            "ALTER TABLE activation_keys ADD COLUMN subscription_days REAL NOT NULL DEFAULT 365"
        )
    # Back-fill legacy rows: treat minutes_valid as license_minutes if present.
    if "minutes_valid" in existing:
        conn.execute(
            """
            UPDATE activation_keys
            SET license_minutes = minutes_valid
            WHERE license_minutes = 10080
            """
        )
    conn.commit()
    return conn


def _count_seats_for_key(conn: sqlite3.Connection, activation_key: str) -> int:
    (count,) = conn.execute(
        "SELECT COUNT(*) FROM issued_licenses WHERE activation_key = ?",
        (activation_key,),
    ).fetchone()
    return count


def _is_known_machine(conn: sqlite3.Connection, machine_fingerprint: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM issued_licenses WHERE machine_fingerprint = ?",
        (machine_fingerprint,),
    ).fetchone()
    return row is not None


def _count_unique_machines(conn: sqlite3.Connection) -> int:
    (count,) = conn.execute(
        "SELECT COUNT(DISTINCT machine_fingerprint) FROM issued_licenses"
    ).fetchone()
    return count


def create_activation_key(
    activation_key: str,
    customer_id: str,
    customer_name: str,
    max_seats: int = 2,
    features: List[str] = None,
    license_minutes: float = 10080.0,   # window of each issued license.json (default: 7 days)
    subscription_days: float = 365.0,   # how long the activation key itself is valid
    # Legacy alias: minutes_valid<=0 means "already expired" subscription;
    # minutes_valid>0 is treated as the license window only (subscription stays at 365 days).
    minutes_valid: Optional[float] = None,
    db_path: Path = DEFAULT_DB_PATH,
    now: Optional[datetime] = None,
) -> None:
    """Register a new activation key for a customer (vendor operation).

    license_minutes   — how long each issued license.json window lasts (e.g. 10080 = 7 days).
                        Heartbeat renews with this same window each time.
    subscription_days — how long the activation key itself stays valid before the
                        server refuses heartbeat renewals (e.g. 365 = 1 year subscription).
    """
    # Backwards-compat: minutes_valid<=0 signals an already-expired subscription
    # (used in tests to simulate an expired key). minutes_valid>0 maps to license_minutes
    # for callers that predate the license_minutes/subscription_days split.
    if minutes_valid is not None:
        if minutes_valid <= 0:
            # Negative or zero: the subscription itself should be already expired.
            # Convert minutes to days (negative) so expires_at ends up in the past.
            subscription_days = minutes_valid / 1440.0
        else:
            license_minutes = minutes_valid

    if now is None:
        now = datetime.now(timezone.utc)
    if features is None:
        features = ["rag_chat"]

    conn = _init_db(db_path)
    key_expires_at = (
        (now + timedelta(days=subscription_days)).isoformat().replace("+00:00", "Z")
    )
    conn.execute(
        """
        INSERT INTO activation_keys
            (activation_key, customer_id, customer_name, max_seats, features,
             license_minutes, subscription_days, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(activation_key) DO UPDATE SET
            customer_name     = excluded.customer_name,
            max_seats         = excluded.max_seats,
            features          = excluded.features,
            license_minutes   = excluded.license_minutes,
            subscription_days = excluded.subscription_days,
            expires_at        = excluded.expires_at
        """,
        (
            activation_key,
            customer_id,
            customer_name,
            max_seats,
            json.dumps(features),
            license_minutes,
            subscription_days,
            now.isoformat().replace("+00:00", "Z"),
            key_expires_at,
        ),
    )
    conn.commit()

    if license_minutes < 60:
        lic_str = f"{license_minutes:.1f} minutes"
    elif license_minutes < 1440:
        lic_str = f"{license_minutes / 60:.2f} hours"
    else:
        lic_str = f"{license_minutes / 1440:.1f} days"

    print(f"Activation key created: {activation_key}")
    print(f"  customer         : {customer_name} ({customer_id})")
    print(f"  seats            : {max_seats}")
    print(f"  features         : {', '.join(features)}")
    print(f"  license window   : {lic_str} (each issued license.json is valid this long)")
    print(f"  subscription     : {subscription_days:.1f} days (key expires: {key_expires_at})")


def issue_license(
    machine_fingerprint: str,
    features: List[str],
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    max_seats: int = DEFAULT_MAX_SEATS,
    minutes_valid: float = 60.0,
    now: Optional[datetime] = None,
    customer: str = "DemoCorp",
    customer_id: str = "cust-0000",
    activation_key: str = "DEMO-0000-0000-0000",
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
        "license_id":          license_id,
        "customer":            customer,
        "customer_id":         customer_id,
        "activation_key":      activation_key,
        "machine_fingerprint": machine_fingerprint,
        "not_before":          now.isoformat().replace("+00:00", "Z"),
        "not_after":           (now + timedelta(minutes=minutes_valid))
                               .isoformat().replace("+00:00", "Z"),
        "features":            features,
        "issued_at":           now.isoformat().replace("+00:00", "Z"),
        "max_version":         "1.0.0",
    }

    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    signature_b64 = base64.b64encode(private_key.sign(payload_bytes)).decode("ascii")

    conn.execute(
        """
        INSERT INTO issued_licenses
            (license_id, machine_fingerprint, customer_id, activation_key, issued_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(machine_fingerprint) DO UPDATE SET
            license_id     = excluded.license_id,
            customer_id    = excluded.customer_id,
            activation_key = excluded.activation_key,
            issued_at      = excluded.issued_at
        """,
        (license_id, machine_fingerprint, customer_id, activation_key, now.isoformat()),
    )
    conn.commit()

    return {"payload": payload, "signature": signature_b64}


def issue_license_for_activation(
    activation_key: str,
    machine_fingerprint: str,
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Issue a license against a registered activation key.

    This is the server-side path called by /activate and /heartbeat.
    Uses license_minutes for the issued window; checks expires_at (subscription)
    to decide whether renewal is still permitted.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    conn = _init_db(db_path)

    row = conn.execute(
        "SELECT customer_id, customer_name, max_seats, features, license_minutes, expires_at "
        "FROM activation_keys WHERE activation_key = ?",
        (activation_key,),
    ).fetchone()
    if row is None:
        raise InvalidActivationKeyError(f"Activation key '{activation_key}' not found.")

    customer_id, customer_name, max_seats, features_json, license_minutes, expires_at = row
    features = json.loads(features_json)

    # Subscription expiry check — independent of the license window length.
    if expires_at:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if now > exp_dt:
            raise InvalidActivationKeyError(
                f"Activation key '{activation_key}' subscription expired at {expires_at}."
            )

    # Seat cap check (per activation key).
    is_renewal = _is_known_machine(conn, machine_fingerprint)
    if not is_renewal:
        seats_used = _count_seats_for_key(conn, activation_key)
        if seats_used >= max_seats:
            raise SeatCapError(
                f"Seat cap reached for {customer_name} ({seats_used}/{max_seats})."
            )

    return issue_license(
        machine_fingerprint=machine_fingerprint,
        features=features,
        private_key_path=private_key_path,
        db_path=db_path,
        max_seats=max_seats,
        minutes_valid=float(license_minutes),
        now=now,
        customer=customer_name,
        customer_id=customer_id,
        activation_key=activation_key,
    )


def issue_and_write(
    machine_fingerprint: str,
    features: List[str],
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    max_seats: int = DEFAULT_MAX_SEATS,
    minutes_valid: float = 60.0,
    bundle: bool = False,
) -> Path:
    """issue_license + write to disk. Used by the CLI `issue` command."""
    conn = _init_db(db_path)
    is_renewal = _is_known_machine(conn, machine_fingerprint)

    lic = issue_license(
        machine_fingerprint, features, private_key_path, db_path, max_seats, minutes_valid
    )

    license_filename = Path(f"license_{machine_fingerprint[:8]}.json")
    license_filename.write_text(json.dumps(lic, indent=2))

    bundle_filename: Optional[Path] = None
    if bundle:
        public_key_path = private_key_path.parent / "public_key.pem"
        if not public_key_path.exists():
            print("Warning: public_key.pem not found next to private_key.pem, skipping bundle.")
        else:
            bundle_obj = {
                "public_key": public_key_path.read_text(),
                "license": lic,
            }
            bundle_filename = Path(f"license_bundle_{machine_fingerprint[:8]}.json")
            bundle_filename.write_text(json.dumps(bundle_obj, indent=2))

    seats_used = _count_unique_machines(_init_db(db_path))
    action = "Renewed" if is_renewal else "Issued"
    print(f"{action} {lic['payload']['license_id']}")
    print(f"  customer : {lic['payload']['customer']} ({lic['payload']['customer_id']})")
    print(f"  machine  : {machine_fingerprint}")
    print(f"  features : {', '.join(features)}")
    print(f"  valid    : {minutes_valid} minutes")
    print(f"  seats    : {seats_used}/{max_seats} unique machines")
    if is_renewal:
        print("  [renewal - existing seat updated, no new seat consumed]")
    if bundle_filename:
        print(f"  bundle   : {bundle_filename}  <-- send this single file to the client")
    else:
        print(f"  file     : {license_filename}")

    return bundle_filename or license_filename
