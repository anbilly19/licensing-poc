from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives import serialization

DEFAULT_LICENSE_PATH = Path("license.json")
DEFAULT_PUBLIC_KEY_PATH = Path("public_key.pem")
DEFAULT_LAST_SEEN_PATH = Path("last_seen.json")


@dataclass
class License:
    license_id: str
    customer: str
    machine_fingerprint: str
    not_before: datetime
    not_after: datetime
    features: List[str]
    issued_at: datetime
    max_version: str


class LicenseError(Exception):
    pass


def _parse_iso(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _check_clock_rollback(now: datetime, last_seen_path: Path) -> None:
    if last_seen_path.exists():
        data = json.loads(last_seen_path.read_text())
        last_seen = _parse_iso(data["last_seen"])
        if now < last_seen:
            raise LicenseError(
                f"Clock rollback detected (now={now.isoformat()}, "
                f"last_seen={last_seen.isoformat()})."
            )
    last_seen_path.write_text(
        json.dumps({"last_seen": now.isoformat().replace("+00:00", "Z")})
    )


def load_and_verify_license(
    license_path: Path = DEFAULT_LICENSE_PATH,
    public_key_path: Path = DEFAULT_PUBLIC_KEY_PATH,
    expected_fingerprint: str = "",
    last_seen_path: Path = DEFAULT_LAST_SEEN_PATH,
    now: Optional[datetime] = None,
) -> License:
    """Load, verify signature, check fingerprint, time bounds, and clock rollback."""
    if now is None:
        now = datetime.now(timezone.utc)

    if not license_path.exists():
        raise LicenseError(
            f"{license_path} not found. "
            "Run 'onemachine-license fingerprint', send the output to the vendor, "
            "then place the received license.json here."
        )
    if not public_key_path.exists():
        raise LicenseError(
            f"{public_key_path} not found. Copy it from the vendor machine."
        )

    license_obj = json.loads(license_path.read_text())
    payload = license_obj["payload"]
    signature_b64 = license_obj["signature"]

    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    signature = base64.b64decode(signature_b64)

    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    try:
        public_key.verify(signature, payload_bytes)
    except Exception as exc:
        raise LicenseError(f"Invalid signature: {exc}") from exc

    if payload["machine_fingerprint"] != expected_fingerprint:
        raise LicenseError(
            "This license was not issued for this machine. "
            "Request a new license with your machine fingerprint."
        )

    not_before = _parse_iso(payload["not_before"])
    not_after = _parse_iso(payload["not_after"])

    if now < not_before:
        raise LicenseError(f"License not yet valid (valid from {not_before}).")
    if now > not_after:
        raise LicenseError(f"License expired at {not_after}.")

    _check_clock_rollback(now, last_seen_path)

    return License(
        license_id=payload["license_id"],
        customer=payload["customer"],
        machine_fingerprint=payload["machine_fingerprint"],
        not_before=not_before,
        not_after=not_after,
        features=payload["features"],
        issued_at=_parse_iso(payload["issued_at"]),
        max_version=payload["max_version"],
    )
