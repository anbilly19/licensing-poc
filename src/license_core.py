import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class LicenseError(Exception):
    pass


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


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_and_verify_license(
    license_path: Path,
    public_key_path: Path,
    machine_fingerprint: str,
    last_seen_path: Path,
    now: datetime = None,
) -> License:
    if now is None:
        now = datetime.now(timezone.utc)

    if not license_path.exists():
        raise LicenseError("License file not found")

    data = json.loads(license_path.read_text())
    payload = data["payload"]
    sig = base64.b64decode(data["signature"])

    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    try:
        public_key.verify(sig, payload_bytes)
    except InvalidSignature:
        raise LicenseError("Invalid signature")

    if payload["machine_fingerprint"] != machine_fingerprint:
        raise LicenseError("License not issued for this machine")

    not_before = _parse_iso(payload["not_before"])
    not_after = _parse_iso(payload["not_after"])
    if now < not_before:
        raise LicenseError("License not yet valid")
    if now > not_after:
        raise LicenseError("License expired")

    if last_seen_path.exists():
        last_seen = _parse_iso(json.loads(last_seen_path.read_text())["last_seen"])
        if now < last_seen:
            raise LicenseError("Clock rollback detected")

    last_seen_path.write_text(json.dumps({"last_seen": now.isoformat().replace("+00:00", "Z")}))

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
