from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import platform
import os
import socket
import struct
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import serialization

DEFAULT_LICENSE_PATH = Path("license.json")
DEFAULT_PUBLIC_KEY_PATH = Path("public_key.pem")
DEFAULT_LAST_SEEN_PATH = Path("last_seen.json")

# Windows registry paths.
# HKLM requires admin to write/delete — protects against user-level wiping.
# HKCU is the fallback when the process lacks elevation.
_REGISTRY_KEY = r"Software\OneMachine\LicensePOC"
_REGISTRY_VALUE = "last_seen_sig"

_MACOS_DEFAULTS_DOMAIN = "com.onemachine.licensepoc"
_MACOS_DEFAULTS_KEY = "last_seen_sig"
_XATTR_NAME = "user.onemachine_sig"
_LINUX_DOTFILE = Path.home() / ".config" / ".onemachine" / "anchor"

# Secret salt mixed into HMAC key derivation.
_HMAC_SALT = b"0m-p0c-s4lt-v1-d3f4ult-ch4ng3-b3f0r3-pr0d"

# Clock sanity: maximum allowed divergence between local clock and any
# external time source (NTP or boot-time estimate) before we reject.
_CLOCK_SKEW_TOLERANCE = timedelta(seconds=90)

# NTP servers to try in order.
_NTP_SERVERS = ["time.cloudflare.com", "pool.ntp.org", "time.google.com"]
_NTP_PORT = 123
_NTP_TIMEOUT = 3  # seconds
# Epoch offset: NTP epoch is 1 Jan 1900; Unix epoch is 1 Jan 1970.
_NTP_DELTA = 2208988800


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
    return hashlib.sha256(_HMAC_SALT + public_key_path.read_bytes()).digest()


def _get_mirror_path() -> Path:
    system = _system()
    if system == "Windows":
        appdata = os.environ.get("APPDATA", str(Path.home()))
        mirror_dir = Path(appdata) / "OneMachine"
    elif system == "Darwin":
        mirror_dir = Path.home() / "Library" / "Application Support" / "OneMachine"
    else:
        xdg = os.environ.get("XDG_DATA_HOME", "")
        mirror_dir = (Path(xdg) if xdg else Path.home() / ".local" / "share") / "onemachine"
    mirror_dir.mkdir(parents=True, exist_ok=True)
    return mirror_dir / "last_seen.json"


def _hash_entry(ts: str, prev_hash: str) -> str:
    raw = f"{ts}|{prev_hash}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sign_entry(ts: str, prev_hash: str, key: bytes) -> str:
    raw = f"{ts}|{prev_hash}".encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Online time source: NTP (raw UDP)
# Returns UTC datetime from NTP server, or None on any failure.
# Uses raw UDP so there is no dependency beyond the stdlib.
# ---------------------------------------------------------------------------

def _ntp_time() -> Optional[datetime]:
    """Query NTP servers in order; return UTC datetime from the first that responds."""
    # 48-byte NTP request packet: LI=0, VN=3, Mode=3 (client)
    packet = b"\x1b" + b"\x00" * 47
    for server in _NTP_SERVERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(_NTP_TIMEOUT)
                s.sendto(packet, (server, _NTP_PORT))
                data, _ = s.recvfrom(1024)
            if len(data) < 48:
                continue
            # Transmit Timestamp is at bytes 40–43 (seconds since NTP epoch)
            ntp_seconds = struct.unpack("!I", data[40:44])[0]
            unix_ts = ntp_seconds - _NTP_DELTA
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Offline time source: platform-specific uptime
#
# Each platform exposes the system uptime via a different API:
#
#   Linux   — /proc/uptime  (seconds since boot as a float)
#   macOS   — sysctl kern.boottime (struct timeval: tv_sec + tv_usec)
#   Windows — GetTickCount64() (milliseconds since boot, wraps at ~49 days
#             on 32-bit but is 64-bit since Vista so effectively unlimited)
#
# The uptime is combined with a stored wall-clock snapshot to form a
# boot-time estimate of the current wall clock.  If the local clock deviates
# from this estimate by more than _CLOCK_SKEW_TOLERANCE, we raise.
# ---------------------------------------------------------------------------

_BOOT_ANCHOR_FILENAME = "boot_anchor.json"


def _get_boot_anchor_path() -> Path:
    return _get_mirror_path().parent / _BOOT_ANCHOR_FILENAME


def _read_uptime_seconds() -> Optional[float]:
    """
    Return current system uptime in seconds.

    Linux  : reads /proc/uptime
    macOS  : calls sysctl kern.boottime (struct timeval), computes now - boot
    Windows: calls GetTickCount64() via ctypes
    """
    system = _system()
    try:
        if system == "Linux":
            raw = Path("/proc/uptime").read_text().split()[0]
            return float(raw)

        elif system == "Darwin":
            # kern.boottime returns a struct timeval {tv_sec, tv_usec}
            # Use sysctl -n kern.boottime and parse the output, or use ctypes.
            # We use the subprocess approach (always available, no C extension needed).
            result = subprocess.run(
                ["sysctl", "-n", "kern.boottime"],
                capture_output=True, text=True, timeout=2,
            )
            if result.returncode != 0:
                return None
            # Output looks like: "{ sec = 1716720000, usec = 123456 } Tue May 26 ..."
            raw = result.stdout
            sec_part = [p for p in raw.split(",") if "sec" in p and "usec" not in p]
            usec_part = [p for p in raw.split(",") if "usec" in p]
            if not sec_part:
                return None
            boot_sec = int(sec_part[0].split("=")[1].strip().split()[0])
            boot_usec = 0
            if usec_part:
                try:
                    boot_usec = int(usec_part[0].split("=")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            boot_epoch = boot_sec + boot_usec / 1_000_000
            uptime = time.time() - boot_epoch
            return uptime if uptime >= 0 else None

        elif system == "Windows":
            # GetTickCount64 returns milliseconds since boot (ULONGLONG).
            get_tick = ctypes.windll.kernel32.GetTickCount64
            get_tick.restype = ctypes.c_uint64
            ms = get_tick()
            return ms / 1000.0

    except Exception:
        pass
    return None


def _boot_anchor_write(wall_ts: datetime, uptime_s: float, key: bytes) -> None:
    """Persist wall clock + uptime pair, HMAC-signed."""
    try:
        path = _get_boot_anchor_path()
        ts_str = wall_ts.isoformat().replace("+00:00", "Z")
        payload = f"{ts_str}|{uptime_s:.6f}"
        sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        path.write_text(json.dumps({"wall_ts": ts_str, "uptime_s": uptime_s, "sig": sig}))
    except Exception:
        pass


def _boot_anchor_read(key: bytes) -> Optional[Tuple[datetime, float]]:
    """Read and verify the boot anchor. Returns (wall_ts, uptime_s) or None."""
    try:
        path = _get_boot_anchor_path()
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        ts_str: str = data["wall_ts"]
        uptime_s: float = float(data["uptime_s"])
        stored_sig: str = data["sig"]
        payload = f"{ts_str}|{uptime_s:.6f}"
        expected_sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(stored_sig, expected_sig):
            return None  # tampered or stale key
        return _parse_iso(ts_str), uptime_s
    except Exception:
        return None


def _boot_time_estimate(key: bytes) -> Optional[datetime]:
    """
    Estimate what the wall clock *should* be based on the stored anchor + elapsed uptime.
    Returns None if uptime is unavailable or anchor is missing/stale.

    Works on Linux (/proc/uptime), macOS (sysctl kern.boottime),
    and Windows (GetTickCount64).
    """
    anchor = _boot_anchor_read(key)
    if anchor is None:
        return None
    prev_wall, prev_uptime = anchor
    current_uptime = _read_uptime_seconds()
    if current_uptime is None:
        return None
    elapsed = current_uptime - prev_uptime
    if elapsed < 0:
        # Machine rebooted since anchor was written — anchor is stale, ignore.
        return None
    return prev_wall + timedelta(seconds=elapsed)


# ---------------------------------------------------------------------------
# Clock sanity check
#
# Rules:
#   - Both sources available → BOTH must agree with local clock (within tolerance)
#   - Only boot-time available → accept if it agrees
#   - Only NTP available → accept if it agrees
#   - Neither available → degrade gracefully (no rejection)
# ---------------------------------------------------------------------------

def _check_clock_sanity(now: datetime, key: bytes) -> None:
    """
    Compare the local clock against NTP (online) and the boot-time anchor (offline).
    Raises LicenseError if any available source disagrees by more than the tolerance.
    """
    ntp_now = _ntp_time()
    boot_estimate = _boot_time_estimate(key)

    if ntp_now is not None and boot_estimate is not None:
        # Both available — both must agree with local clock.
        if abs(now - ntp_now) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError(
                f"System clock diverges from NTP by "
                f"{abs(now - ntp_now).total_seconds():.0f}s — possible clock manipulation."
            )
        if abs(now - boot_estimate) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError(
                f"System clock diverges from boot-time estimate by "
                f"{abs(now - boot_estimate).total_seconds():.0f}s — possible clock manipulation "
                f"or VM snapshot restore."
            )
    elif ntp_now is not None:
        # Only NTP available.
        if abs(now - ntp_now) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError(
                f"System clock diverges from NTP by "
                f"{abs(now - ntp_now).total_seconds():.0f}s — possible clock manipulation."
            )
    elif boot_estimate is not None:
        # Only boot-time anchor available (offline).
        if abs(now - boot_estimate) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError(
                f"System clock diverges from boot-time estimate by "
                f"{abs(now - boot_estimate).total_seconds():.0f}s — possible clock manipulation "
                f"or VM snapshot restore."
            )
    # Neither available — degrade gracefully.


# ---------------------------------------------------------------------------
# Windows registry helpers
# ---------------------------------------------------------------------------

def _registry_write(sig: str) -> None:
    if _system() != "Windows":
        return
    try:
        import winreg
        try:
            k = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, _REGISTRY_KEY, 0, winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(k, _REGISTRY_VALUE, 0, winreg.REG_SZ, sig)
            winreg.CloseKey(k)
        except OSError:
            pass
        k = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, _REGISTRY_KEY, 0, winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(k, _REGISTRY_VALUE, 0, winreg.REG_SZ, sig)
        winreg.CloseKey(k)
    except Exception:
        pass


def _registry_read() -> Optional[str]:
    if _system() != "Windows":
        return None
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                k = winreg.OpenKey(hive, _REGISTRY_KEY, 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(k, _REGISTRY_VALUE)
                winreg.CloseKey(k)
                return value
            except FileNotFoundError:
                continue
            except Exception:
                continue
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# macOS defaults helpers
# ---------------------------------------------------------------------------

def _defaults_write(sig: str) -> None:
    if _system() != "Darwin":
        return
    try:
        subprocess.run(
            ["defaults", "write", _MACOS_DEFAULTS_DOMAIN, _MACOS_DEFAULTS_KEY, sig],
            check=True, capture_output=True,
        )
    except Exception:
        pass


def _defaults_read() -> Optional[str]:
    if _system() != "Darwin":
        return None
    try:
        result = subprocess.run(
            ["defaults", "read", _MACOS_DEFAULTS_DOMAIN, _MACOS_DEFAULTS_KEY],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Linux xattr helpers
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
# Linux dotfile anchor
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
# Unified anchor helpers
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
        val = _dotfile_read()
        if val is not None:
            return val
        if primary_path is not None:
            return _xattr_read(primary_path)
    return None


# ---------------------------------------------------------------------------
# Read / write last_seen entry (chained)
# ---------------------------------------------------------------------------

def _read_entry(path: Path, key: bytes) -> Tuple[str, str, str]:
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
    uptime_now = _read_uptime_seconds()

    primary_exists = last_seen_path.exists()
    mirror_exists = mirror_path.exists()

    # --- Clock sanity (NTP + boot-time) ---
    _check_clock_sanity(now, key)

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
        if uptime_now is not None:
            _boot_anchor_write(now, uptime_now, key)
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

    # --- Third-anchor cross-check ---
    anchor_sig = _anchor_read(primary_path=last_seen_path)
    if anchor_sig is not None:
        expected_anchor_sig = _sign_entry(ts_primary, prev_hash_primary, key)
        if not hmac.compare_digest(anchor_sig, expected_anchor_sig):
            raise LicenseError(
                "last_seen.json does not match system anchor record. "
                "File may have been replaced or tampered with."
            )

    # --- Chain rollback ---
    last_seen_dt = _parse_iso(ts_primary)
    if now < last_seen_dt:
        raise LicenseError(
            f"Clock rollback detected (now={now.isoformat()}, last_seen={last_seen_dt.isoformat()})."
        )

    # --- Write next chained entry + refresh boot anchor ---
    new_sig = _sign_entry(ts_now, entry_hash_primary, key)
    _write_entry(last_seen_path, ts_now, entry_hash_primary, key)
    _write_entry(mirror_path, ts_now, entry_hash_primary, key)
    _anchor_write(new_sig, primary_path=last_seen_path)
    if uptime_now is not None:
        _boot_anchor_write(now, uptime_now, key)


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
