from __future__ import annotations

import base64
import hashlib
import hmac
import json
import platform
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives import serialization

DEFAULT_LICENSE_PATH = Path("license.json")
DEFAULT_PUBLIC_KEY_PATH = Path("public_key.pem")
DEFAULT_LAST_SEEN_PATH = Path("last_seen.json")

_REGISTRY_KEY = r"Software\OneMachine\LicensePOC"
_REGISTRY_VALUE = "last_seen_sig"


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


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _parse_iso(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _last_seen_hmac_key(public_key_path: Path) -> bytes:
    """Derive a stable HMAC key from the public key bytes."""
    return hashlib.sha256(public_key_path.read_bytes()).digest()


def _sign_last_seen(ts: str, key: bytes) -> str:
    return hmac.new(key, ts.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Windows registry helpers (no-op on non-Windows)
# ---------------------------------------------------------------------------

def _registry_write(sig: str) -> None:
    """Write sig to HKCU registry. Silently skipped on non-Windows."""
    if not _is_windows():
        return
    try:
        import winreg
        key = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, _REGISTRY_KEY, 0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, _REGISTRY_VALUE, 0, winreg.REG_SZ, sig)
        winreg.CloseKey(key)
    except Exception:
        pass  # Registry unavailable — degrade gracefully


def _registry_read() -> Optional[str]:
    """Read sig from HKCU registry. Returns None if not found or non-Windows."""
    if not _is_windows():
        return None
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _REGISTRY_KEY, 0, winreg.KEY_READ
        )
        value, _ = winreg.QueryValueEx(key, _REGISTRY_VALUE)
        winreg.CloseKey(key)
        return value
    except FileNotFoundError:
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# last_seen write / check
# ---------------------------------------------------------------------------

def _write_last_seen(now: datetime, last_seen_path: Path, key: bytes) -> None:
    ts = now.isoformat().replace("+00:00", "Z")
    sig = _sign_last_seen(ts, key)
    last_seen_path.write_text(json.dumps({"last_seen": ts, "sig": sig}))
    _registry_write(sig)  # mirror sig to registry on Windows


def _check_clock_rollback(
    now: datetime, last_seen_path: Path, public_key_path: Path
) -> None:
    key = _last_seen_hmac_key(public_key_path)
    reg_sig = _registry_read()  # None on Linux/macOS or if key absent

    if not last_seen_path.exists():
        # File missing — check registry to detect deliberate deletion
        if reg_sig is not None:
            raise LicenseError(
                "last_seen.json was deleted while a registry entry still exists. "
                "Possible tamper attempt."
            )
        # First run: no file, no registry entry — allow and initialise
        _write_last_seen(now, last_seen_path, key)
        return

    # File exists — validate its contents
    try:
        data = json.loads(last_seen_path.read_text())
        ts = data["last_seen"]
        stored_sig = data["sig"]
    except (KeyError, json.JSONDecodeError):
        raise LicenseError(
            "last_seen.json is malformed or missing signature. "
            "File may have been tampered with."
        )

    expected_sig = _sign_last_seen(ts, key)
    if not hmac.compare_digest(stored_sig, expected_sig):
        raise LicenseError(
            "last_seen.json signature invalid. "
            "File has been tampered with."
        )

    # Cross-check file sig against registry sig on Windows
    if reg_sig is not None and not hmac.compare_digest(stored_sig, reg_sig):
        raise LicenseError(
            "last_seen.json does not match registry record. "
            "File may have been replaced or tampered with."
        )

    last_seen = _parse_iso(ts)
    if now < last_seen:
        raise LicenseError(
            f"Clock rollback detected (now={now.isoformat()}, "
            f"last_seen={last_seen.isoformat()})."
        )

    _write_last_seen(now, last_seen_path, key)


# ---------------------------------------------------------------------------
# Main public API
# ---------------------------------------------------------------------------

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

    _check_clock_rollback(now, last_seen_path, public_key_path)

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
