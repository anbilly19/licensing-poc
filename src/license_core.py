from __future__ import annotations

import base64
import hashlib
import hmac
import json
import platform
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import serialization

DEFAULT_LICENSE_PATH = Path("license.json")
DEFAULT_PUBLIC_KEY_PATH = Path("public_key.pem")
DEFAULT_LAST_SEEN_PATH = Path("last_seen.json")

_REGISTRY_KEY = r"Software\OneMachine\LicensePOC"
_REGISTRY_VALUE = "last_seen_sig"
_MACOS_DEFAULTS_DOMAIN = "com.onemachine.licensepoc"
_MACOS_DEFAULTS_KEY = "last_seen_sig"
_XATTR_NAME = "user.onemachine_sig"
_LINUX_DOTFILE = Path.home() / ".config" / ".onemachine" / "anchor"

# Secret salt mixed into HMAC key derivation.
# An attacker with only public_key.pem cannot derive the correct HMAC key
# without also knowing this salt, which is compiled into the binary via Nuitka.
_HMAC_SALT = b"0m-p0c-s4lt-v1-d3f4ult-ch4ng3-b3f0r3-pr0d"


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


def _system() -> str:
    return platform.system()  # "Windows", "Darwin", "Linux"


def _parse_iso(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _last_seen_hmac_key(public_key_path: Path) -> bytes:
    """Derive a stable HMAC key from the salt + public key bytes.

    The salt prevents an attacker who has public_key.pem (which all clients do)
    from trivially computing the HMAC key and forging last_seen.json entries.
    """
    return hashlib.sha256(_HMAC_SALT + public_key_path.read_bytes()).digest()


def _get_mirror_path() -> Path:
    """Return platform-specific mirror storage path."""
    system = _system()
    if system == "Windows":
        appdata = os.environ.get("APPDATA", str(Path.home()))
        mirror_dir = Path(appdata) / "OneMachine"
    elif system == "Darwin":
        mirror_dir = Path.home() / "Library" / "Application Support" / "OneMachine"
    else:
        # Linux / other POSIX
        xdg = os.environ.get("XDG_DATA_HOME", "")
        mirror_dir = (Path(xdg) if xdg else Path.home() / ".local" / "share") / "onemachine"
    mirror_dir.mkdir(parents=True, exist_ok=True)
    return mirror_dir / "last_seen.json"


def _hash_entry(ts: str, prev_hash: str) -> str:
    """SHA-256 of ts + prev_hash for chain integrity."""
    raw = f"{ts}|{prev_hash}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sign_entry(ts: str, prev_hash: str, key: bytes) -> str:
    """HMAC-SHA256 over ts + prev_hash."""
    raw = f"{ts}|{prev_hash}".encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Windows registry helpers
# ---------------------------------------------------------------------------

def _registry_write(sig: str) -> None:
    if _system() != "Windows":
        return
    try:
        import winreg
        k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _REGISTRY_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, _REGISTRY_VALUE, 0, winreg.REG_SZ, sig)
        winreg.CloseKey(k)
    except Exception:
        pass


def _registry_read() -> Optional[str]:
    if _system() != "Windows":
        return None
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REGISTRY_KEY, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(k, _REGISTRY_VALUE)
        winreg.CloseKey(k)
        return value
    except FileNotFoundError:
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# macOS defaults (plist) helpers
# ---------------------------------------------------------------------------

def _defaults_write(sig: str) -> None:
    if _system() != "Darwin":
        return
    try:
        subprocess.run(
            ["defaults", "write", _MACOS_DEFAULTS_DOMAIN, _MACOS_DEFAULTS_KEY, sig],
            check=True,
            capture_output=True,
        )
    except Exception:
        pass


def _defaults_read() -> Optional[str]:
    if _system() != "Darwin":
        return None
    try:
        result = subprocess.run(
            ["defaults", "read", _MACOS_DEFAULTS_DOMAIN, _MACOS_DEFAULTS_KEY],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Linux xattr helpers — stored on the primary last_seen.json file itself.
# xattrs are NOT copied by plain `cp` (requires --preserve=xattr),
# so a naive file backup+restore drops the xattr and triggers tamper detection.
# Degrades gracefully if the filesystem does not support xattrs.
# ---------------------------------------------------------------------------

def _xattr_write(path: Path, sig: str) -> None:
    if _system() != "Linux":
        return
    try:
        os.setxattr(str(path), _XATTR_NAME, sig.encode("utf-8"))
    except (OSError, AttributeError):
        pass


def _xattr_read(path: Path) -> Optional[str]:
    if _system() != "Linux":
        return None
    try:
        val = os.getxattr(str(path), _XATTR_NAME)
        return val.decode("utf-8")
    except (OSError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Linux dotfile anchor — stored in ~/.config/.onemachine/anchor.
# Lives outside the working directory and outside the XDG mirror directory,
# so deleting both last_seen files still leaves this anchor intact.
# An attacker would need to know to delete three separate locations.
# ---------------------------------------------------------------------------

def _dotfile_write(sig: str) -> None:
    if _system() != "Linux":
        return
    try:
        _LINUX_DOTFILE.parent.mkdir(parents=True, exist_ok=True)
        _LINUX_DOTFILE.write_text(sig)
    except OSError:
        pass


def _dotfile_read() -> Optional[str]:
    if _system() != "Linux":
        return None
    try:
        if _LINUX_DOTFILE.exists():
            return _LINUX_DOTFILE.read_text().strip() or None
        return None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Unified third-anchor helpers
# Windows: registry
# macOS:   plist (defaults)
# Linux:   dotfile (~/.config/.onemachine/anchor) + xattr on primary file
# ---------------------------------------------------------------------------

def _anchor_write(sig: str, primary_path: Optional[Path] = None) -> None:
    _registry_write(sig)
    _defaults_write(sig)
    _dotfile_write(sig)
    if primary_path is not None:
        _xattr_write(primary_path, sig)


def _anchor_read(primary_path: Optional[Path] = None) -> Optional[str]:
    if _system() == "Windows":
        return _registry_read()
    if _system() == "Darwin":
        return _defaults_read()
    if _system() == "Linux":
        # Prefer dotfile (survives file deletion); fall back to xattr.
        val = _dotfile_read()
        if val is not None:
            return val
        if primary_path is not None:
            return _xattr_read(primary_path)
    return None


# ---------------------------------------------------------------------------
# Read / write a last_seen entry (chained)
# ---------------------------------------------------------------------------

def _read_entry(path: Path, key: bytes) -> Tuple[str, str, str]:
    """Read and validate a last_seen file. Returns (ts, prev_hash, entry_hash)."""
    try:
        data = json.loads(path.read_text())
        ts: str = data["last_seen"]
        prev_hash: str = data["prev_hash"]
        stored_sig: str = data["sig"]
    except (KeyError, json.JSONDecodeError):
        raise LicenseError(f"{path} is malformed or missing fields. Possible tamper.")

    expected_sig = _sign_entry(ts, prev_hash, key)
    if not hmac.compare_digest(stored_sig, expected_sig):
        raise LicenseError(f"{path} signature invalid. File has been tampered with.")

    return ts, prev_hash, _hash_entry(ts, prev_hash)


def _write_entry(path: Path, ts: str, prev_hash: str, key: bytes) -> str:
    """Write a chained last_seen entry. Returns the new entry_hash."""
    sig = _sign_entry(ts, prev_hash, key)
    path.write_text(json.dumps({"last_seen": ts, "prev_hash": prev_hash, "sig": sig}))
    return _hash_entry(ts, prev_hash)


# ---------------------------------------------------------------------------
# Clock rollback + tamper check
# ---------------------------------------------------------------------------

def _check_clock_rollback(
    now: datetime,
    last_seen_path: Path,
    public_key_path: Path,
) -> None:
    key = _last_seen_hmac_key(public_key_path)
    mirror_path = _get_mirror_path()
    ts_now = now.isoformat().replace("+00:00", "Z")

    primary_exists = last_seen_path.exists()
    mirror_exists = mirror_path.exists()

    # --- First run: neither file exists ---
    if not primary_exists and not mirror_exists:
        anchor = _anchor_read(primary_path=last_seen_path)
        if anchor is not None:
            raise LicenseError(
                "last_seen files missing but a system anchor entry exists. Possible tamper."
            )
        genesis_hash = "0" * 64
        _write_entry(last_seen_path, ts_now, genesis_hash, key)
        _write_entry(mirror_path, ts_now, genesis_hash, key)
        _anchor_write(_sign_entry(ts_now, genesis_hash, key), primary_path=last_seen_path)
        return

    # --- Deletion detection ---
    if not primary_exists and mirror_exists:
        raise LicenseError(
            "last_seen.json was deleted while a mirror entry still exists. Possible tamper."
        )
    if primary_exists and not mirror_exists:
        raise LicenseError(
            "Mirror last_seen was deleted while primary entry still exists. Possible tamper."
        )

    # --- Validate both files ---
    ts_primary, prev_hash_primary, entry_hash_primary = _read_entry(last_seen_path, key)
    ts_mirror, prev_hash_mirror, entry_hash_mirror = _read_entry(mirror_path, key)

    if not hmac.compare_digest(entry_hash_primary, entry_hash_mirror):
        raise LicenseError(
            "Primary and mirror last_seen do not match. File swap or tamper detected."
        )

    # --- Third-anchor cross-check (Windows registry / macOS plist / Linux dotfile+xattr) ---
    anchor_sig = _anchor_read(primary_path=last_seen_path)
    if anchor_sig is not None:
        expected_anchor_sig = _sign_entry(ts_primary, prev_hash_primary, key)
        if not hmac.compare_digest(anchor_sig, expected_anchor_sig):
            raise LicenseError(
                "last_seen.json does not match system anchor record. "
                "File may have been replaced or tampered with."
            )

    # --- Clock rollback ---
    last_seen_dt = _parse_iso(ts_primary)
    if now < last_seen_dt:
        raise LicenseError(
            f"Clock rollback detected (now={now.isoformat()}, last_seen={last_seen_dt.isoformat()})."
        )

    # --- Write next chained entry ---
    new_sig = _sign_entry(ts_now, entry_hash_primary, key)
    _write_entry(last_seen_path, ts_now, entry_hash_primary, key)
    _write_entry(mirror_path, ts_now, entry_hash_primary, key)
    _anchor_write(new_sig, primary_path=last_seen_path)


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

    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
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
