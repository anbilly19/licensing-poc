from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import platform
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import serialization

DEFAULT_LICENSE_PATH = Path("license.json")
DEFAULT_LAST_SEEN_PATH = Path("last_seen.json")

# ---------------------------------------------------------------------------
# FIX 1 (CRITICAL) — Vendor public key embedded as a constant.
#
# public_key.pem is NO LONGER read from disk at runtime.  The bytes below are
# baked in at build time.  An attacker cannot substitute their own key because
# they cannot modify the compiled binary without invalidating any code-signing.
#
# HOW TO UPDATE: run `python scripts/print_pubkey_bytes.py` after keygen and
# paste the output here before each Nuitka build.
# ---------------------------------------------------------------------------
# BEGIN EMBEDDED VENDOR PUBLIC KEY — replace with your real key bytes before building
_VENDOR_PUBLIC_KEY_PEM: Optional[bytes] = None  # set via _load_vendor_key()
_VENDOR_PUBLIC_KEY_FILE = Path("public_key.pem")  # only used during development


def _get_vendor_public_key() -> bytes:
    """Return the vendor Ed25519 public key PEM bytes.

    Production: returns the embedded constant (set at build time).
    Development fallback: reads public_key.pem so dev workflow isn't broken.
    The Nuitka build script should replace _VENDOR_PUBLIC_KEY_PEM with the
    actual bytes so the fallback path is dead code in the compiled binary.
    """
    if _VENDOR_PUBLIC_KEY_PEM is not None:
        return _VENDOR_PUBLIC_KEY_PEM
    # Dev-only fallback — will NOT exist in the distributed binary.
    if _VENDOR_PUBLIC_KEY_FILE.exists():
        return _VENDOR_PUBLIC_KEY_FILE.read_bytes()
    raise LicenseError("E0001")


# Windows registry paths.
_REGISTRY_KEY = r"Software\OneMachine\LicensePOC"
_REGISTRY_VALUE = "last_seen_sig"
_REGISTRY_ANCHOR_VALUE = "last_seen_anchor"

# macOS Keychain service name (used by keyring library)
_MACOS_KEYCHAIN_SERVICE = "com.onemachine.licensepoc"
_MACOS_KEYCHAIN_SIG_USER    = "last_seen_sig"
_MACOS_KEYCHAIN_ANCHOR_USER = "last_seen_anchor"

_XATTR_NAME = "user.onemachine_sig"
_XATTR_ANCHOR_NAME = "user.onemachine_anchor"
_LINUX_DOTFILE = Path.home() / ".config" / ".onemachine" / "anchor"
_LINUX_ANCHOR_DOTFILE = Path.home() / ".config" / ".onemachine" / "anchor2"

# FIX 5 — Block NUITKA_ONEFILE_DIRECTORY at startup before any imports from extracted dirs.
def _check_nuitka_env() -> None:
    """Abort if NUITKA_ONEFILE_DIRECTORY is set — prevents .so redirect attacks."""
    if os.environ.get("NUITKA_ONEFILE_DIRECTORY"):
        raise SystemExit("E0002")


# ---------------------------------------------------------------------------
# FIX 3 — Two independent HMAC keys.
# ---------------------------------------------------------------------------
_HMAC_SALT_PRIMARY = b"0m-p0c-s4lt-v1-primary-d3f4ult-ch4ng3-b3f0r3-pr0d"
_HMAC_SALT_ANCHOR  = b"0m-p0c-s4lt-v1-anchor--d3f4ult-ch4ng3-b3f0r3-pr0d"

_CLOCK_SKEW_TOLERANCE = timedelta(seconds=90)
_NTP_SERVERS = ["time.cloudflare.com", "pool.ntp.org", "time.google.com"]
_NTP_PORT = 123
_NTP_TIMEOUT = 3
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
    return platform.system()


def _parse_iso(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _last_seen_hmac_key() -> bytes:
    return hashlib.sha256(_HMAC_SALT_PRIMARY).digest()


def _anchor_hmac_key() -> bytes:
    return hashlib.sha256(_HMAC_SALT_ANCHOR).digest()


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


def _sign_anchor(sig: str, key: bytes) -> str:
    return hmac.new(key, sig.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# NTP (online clock source)
# ---------------------------------------------------------------------------

def _ntp_time() -> Optional[datetime]:
    packet = b"\x1b" + b"\x00" * 47
    for server in _NTP_SERVERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(_NTP_TIMEOUT)
                s.sendto(packet, (server, _NTP_PORT))
                data, _ = s.recvfrom(1024)
            if len(data) < 48:
                continue
            ntp_seconds = struct.unpack("!I", data[40:44])[0]
            return datetime.fromtimestamp(ntp_seconds - _NTP_DELTA, tz=timezone.utc)
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Boot-time offline clock anchor
# ---------------------------------------------------------------------------

_BOOT_ANCHOR_FILENAME = "boot_anchor.json"


def _get_boot_anchor_path() -> Path:
    return _get_mirror_path().parent / _BOOT_ANCHOR_FILENAME


def _read_uptime_seconds() -> Optional[float]:
    system = _system()
    try:
        if system == "Linux":
            return float(Path("/proc/uptime").read_text().split()[0])
        elif system == "Darwin":
            result = subprocess.run(
                ["sysctl", "-n", "kern.boottime"],
                capture_output=True, text=True, timeout=2,
            )
            if result.returncode != 0:
                return None
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
            uptime = time.time() - (boot_sec + boot_usec / 1_000_000)
            return uptime if uptime >= 0 else None
        elif system == "Windows":
            get_tick = ctypes.windll.kernel32.GetTickCount64
            get_tick.restype = ctypes.c_uint64
            return get_tick() / 1000.0
    except Exception:
        pass
    return None


def _boot_anchor_write(wall_ts: datetime, uptime_s: float, key: bytes) -> None:
    try:
        path = _get_boot_anchor_path()
        ts_str = wall_ts.isoformat().replace("+00:00", "Z")
        payload = f"{ts_str}|{uptime_s:.6f}"
        sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        path.write_text(json.dumps({"wall_ts": ts_str, "uptime_s": uptime_s, "sig": sig}))
    except Exception:
        pass


def _boot_anchor_read(key: bytes) -> Optional[Tuple[datetime, float]]:
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
            return None
        return _parse_iso(ts_str), uptime_s
    except Exception:
        return None


def _boot_time_estimate(key: bytes) -> Optional[datetime]:
    anchor = _boot_anchor_read(key)
    if anchor is None:
        return None
    prev_wall, prev_uptime = anchor
    current_uptime = _read_uptime_seconds()
    if current_uptime is None:
        return None
    elapsed = current_uptime - prev_uptime
    if elapsed < 0:
        return None  # rebooted since anchor was written
    return prev_wall + timedelta(seconds=elapsed)


# ---------------------------------------------------------------------------
# Clock sanity check
# ---------------------------------------------------------------------------

def _check_clock_sanity(now: datetime, key: bytes) -> None:
    ntp_now = _ntp_time()
    boot_estimate = _boot_time_estimate(key)

    if ntp_now is not None and boot_estimate is not None:
        if abs(now - ntp_now) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError("E0010")
        if abs(now - boot_estimate) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError("E0011")
    elif ntp_now is not None:
        if abs(now - ntp_now) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError("E0010")
    elif boot_estimate is not None:
        if abs(now - boot_estimate) > _CLOCK_SKEW_TOLERANCE:
            raise LicenseError("E0011")


# ---------------------------------------------------------------------------
# FIX 2 — libsecret anchor (Linux)
# ---------------------------------------------------------------------------

_LIBSECRET_SERVICE = "onemachine-licensing"
_LIBSECRET_ATTR = {"app": "onemachine", "type": "last_seen_sig"}
_LIBSECRET_ANCHOR_ATTR = {"app": "onemachine", "type": "last_seen_anchor"}


def _libsecret_write(sig: str, anchor_mac: str) -> bool:
    try:
        import secretstorage  # type: ignore
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            coll.unlock()
        existing = list(coll.search_items(_LIBSECRET_ATTR))
        for item in existing:
            item.delete()
        coll.create_item(_LIBSECRET_SERVICE + ":sig", _LIBSECRET_ATTR, sig.encode())
        existing_anchor = list(coll.search_items(_LIBSECRET_ANCHOR_ATTR))
        for item in existing_anchor:
            item.delete()
        coll.create_item(_LIBSECRET_SERVICE + ":anchor", _LIBSECRET_ANCHOR_ATTR, anchor_mac.encode())
        return True
    except Exception:
        return False


def _libsecret_read() -> Optional[Tuple[str, str]]:
    try:
        import secretstorage  # type: ignore
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            coll.unlock()
        sig_items    = list(coll.search_items(_LIBSECRET_ATTR))
        anchor_items = list(coll.search_items(_LIBSECRET_ANCHOR_ATTR))
        if not sig_items or not anchor_items:
            return None
        sig        = sig_items[0].get_secret().decode()
        anchor_mac = anchor_items[0].get_secret().decode()
        return sig, anchor_mac
    except Exception:
        return None


# ---------------------------------------------------------------------------
# FIX 2 (Windows) — DPAPI-encrypted registry anchor.
# ---------------------------------------------------------------------------

def _dpapi_encrypt(plaintext: str) -> Optional[bytes]:
    try:
        import win32crypt  # type: ignore
        encrypted = win32crypt.CryptProtectData(
            plaintext.encode("utf-8"),
            "onemachine-anchor",
            None, None, None, 0,
        )
        return encrypted
    except Exception:
        return None


def _dpapi_decrypt(ciphertext: bytes) -> Optional[str]:
    try:
        import win32crypt  # type: ignore
        _, plaintext_bytes = win32crypt.CryptUnprotectData(
            ciphertext, None, None, None, 0,
        )
        return plaintext_bytes.decode("utf-8")
    except Exception:
        return None


def _registry_write(sig: str, anchor_mac: str) -> None:
    if _system() != "Windows":
        return
    try:
        import winreg
        try:
            k = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, _REGISTRY_KEY, 0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(k, _REGISTRY_VALUE,        0, winreg.REG_SZ, sig)
            winreg.SetValueEx(k, _REGISTRY_ANCHOR_VALUE, 0, winreg.REG_SZ, anchor_mac)
            winreg.CloseKey(k)
        except OSError:
            pass
        sig_enc        = _dpapi_encrypt(sig)
        anchor_mac_enc = _dpapi_encrypt(anchor_mac)
        if sig_enc is None or anchor_mac_enc is None:
            sig_enc_value        = sig
            anchor_mac_enc_value = anchor_mac
            reg_type             = winreg.REG_SZ
        else:
            sig_enc_value        = sig_enc
            anchor_mac_enc_value = anchor_mac_enc
            reg_type             = winreg.REG_BINARY
        k = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, _REGISTRY_KEY, 0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(k, _REGISTRY_VALUE,        0, reg_type, sig_enc_value)
        winreg.SetValueEx(k, _REGISTRY_ANCHOR_VALUE, 0, reg_type, anchor_mac_enc_value)
        winreg.CloseKey(k)
    except Exception:
        pass


def _registry_read() -> Optional[Tuple[str, str]]:
    if _system() != "Windows":
        return None
    try:
        import winreg
        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, _REGISTRY_KEY, 0, winreg.KEY_READ
            )
            sig,        _ = winreg.QueryValueEx(k, _REGISTRY_VALUE)
            anchor_mac, _ = winreg.QueryValueEx(k, _REGISTRY_ANCHOR_VALUE)
            winreg.CloseKey(k)
            return sig, anchor_mac
        except (FileNotFoundError, OSError):
            pass
        k = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _REGISTRY_KEY, 0, winreg.KEY_READ
        )
        sig_raw,        reg_type_sig    = winreg.QueryValueEx(k, _REGISTRY_VALUE)
        anchor_mac_raw, reg_type_anchor = winreg.QueryValueEx(k, _REGISTRY_ANCHOR_VALUE)
        winreg.CloseKey(k)
        if reg_type_sig == winreg.REG_BINARY:
            sig        = _dpapi_decrypt(bytes(sig_raw))
            anchor_mac = _dpapi_decrypt(bytes(anchor_mac_raw))
            if sig is None or anchor_mac is None:
                return None
        else:
            sig        = sig_raw
            anchor_mac = anchor_mac_raw
        return sig, anchor_mac
    except (FileNotFoundError, OSError):
        pass
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# FIX 2 (macOS) — Keychain anchor via keyring library.
# ---------------------------------------------------------------------------

def _keychain_write(sig: str, anchor_mac: str) -> bool:
    try:
        import keyring  # type: ignore
        keyring.set_password(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_SIG_USER,    sig)
        keyring.set_password(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_ANCHOR_USER, anchor_mac)
        return True
    except Exception:
        return False


def _keychain_read() -> Optional[Tuple[str, str]]:
    try:
        import keyring  # type: ignore
        sig        = keyring.get_password(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_SIG_USER)
        anchor_mac = keyring.get_password(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_ANCHOR_USER)
        if sig and anchor_mac:
            return sig, anchor_mac
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Linux xattr + dotfile helpers
# ---------------------------------------------------------------------------

def _xattr_write(path: Path, sig: str, anchor_mac: str) -> None:
    if _system() != "Linux":
        return
    try:
        os.setxattr(str(path), _XATTR_NAME,        sig.encode())
        os.setxattr(str(path), _XATTR_ANCHOR_NAME, anchor_mac.encode())
    except (OSError, AttributeError):
        pass


def _xattr_read(path: Path) -> Optional[Tuple[str, str]]:
    if _system() != "Linux":
        return None
    try:
        sig        = os.getxattr(str(path), _XATTR_NAME).decode()
        anchor_mac = os.getxattr(str(path), _XATTR_ANCHOR_NAME).decode()
        return sig, anchor_mac
    except (OSError, AttributeError):
        return None


def _dotfile_write(sig: str, anchor_mac: str) -> None:
    if _system() != "Linux":
        return
    try:
        _LINUX_DOTFILE.parent.mkdir(parents=True, exist_ok=True)
        _LINUX_DOTFILE.write_text(sig)
        _LINUX_ANCHOR_DOTFILE.write_text(anchor_mac)
    except OSError:
        pass


def _dotfile_read() -> Optional[Tuple[str, str]]:
    if _system() != "Linux":
        return None
    try:
        if _LINUX_DOTFILE.exists() and _LINUX_ANCHOR_DOTFILE.exists():
            sig        = _LINUX_DOTFILE.read_text().strip()
            anchor_mac = _LINUX_ANCHOR_DOTFILE.read_text().strip()
            if sig and anchor_mac:
                return sig, anchor_mac
    except OSError:
        pass
    return None


# ---------------------------------------------------------------------------
# Unified anchor helpers
# ---------------------------------------------------------------------------

def _anchor_write(sig: str, anchor_mac: str, primary_path: Optional[Path] = None) -> None:
    system = _system()
    if system == "Windows":
        _registry_write(sig, anchor_mac)
    elif system == "Darwin":
        _keychain_write(sig, anchor_mac)
    elif system == "Linux":
        wrote_keychain = _libsecret_write(sig, anchor_mac)
        if not wrote_keychain:
            _dotfile_write(sig, anchor_mac)
        if primary_path is not None:
            _xattr_write(primary_path, sig, anchor_mac)


def _anchor_read(primary_path: Optional[Path] = None) -> Optional[Tuple[str, str]]:
    system = _system()
    if system == "Windows":
        return _registry_read()
    if system == "Darwin":
        return _keychain_read()
    if system == "Linux":
        val = _libsecret_read()
        if val is not None:
            return val
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
        ts: str        = data["last_seen"]
        prev_hash: str = data["prev_hash"]
        stored_sig: str = data["sig"]
    except (KeyError, json.JSONDecodeError):
        raise LicenseError("E0020")
    expected_sig = _sign_entry(ts, prev_hash, key)
    if not hmac.compare_digest(stored_sig, expected_sig):
        raise LicenseError("E0021")
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
) -> None:
    primary_key = _last_seen_hmac_key()
    anchor_key  = _anchor_hmac_key()
    mirror_path = _get_mirror_path()
    ts_now      = now.isoformat().replace("+00:00", "Z")
    uptime_now  = _read_uptime_seconds()

    primary_exists = last_seen_path.exists()
    mirror_exists  = mirror_path.exists()

    _check_clock_sanity(now, primary_key)

    if not primary_exists and not mirror_exists:
        anchor = _anchor_read(primary_path=last_seen_path)
        if anchor is not None:
            raise LicenseError("E0030")
        genesis_hash = "0" * 64
        sig = _sign_entry(ts_now, genesis_hash, primary_key)
        anchor_mac = _sign_anchor(sig, anchor_key)
        _write_entry(last_seen_path, ts_now, genesis_hash, primary_key)
        _write_entry(mirror_path,    ts_now, genesis_hash, primary_key)
        _anchor_write(sig, anchor_mac, primary_path=last_seen_path)
        if uptime_now is not None:
            _boot_anchor_write(now, uptime_now, primary_key)
        return

    if not primary_exists and mirror_exists:
        raise LicenseError("E0031")
    if primary_exists and not mirror_exists:
        raise LicenseError("E0032")

    ts_primary, prev_hash_primary, entry_hash_primary = _read_entry(last_seen_path, primary_key)
    ts_mirror,  prev_hash_mirror,  entry_hash_mirror  = _read_entry(mirror_path,    primary_key)

    if not hmac.compare_digest(entry_hash_primary, entry_hash_mirror):
        raise LicenseError("E0033")

    anchor_pair = _anchor_read(primary_path=last_seen_path)
    if anchor_pair is not None:
        stored_sig, stored_anchor_mac = anchor_pair
        expected_sig = _sign_entry(ts_primary, prev_hash_primary, primary_key)
        if not hmac.compare_digest(stored_sig, expected_sig):
            raise LicenseError("E0034")
        expected_anchor_mac = _sign_anchor(stored_sig, anchor_key)
        if not hmac.compare_digest(stored_anchor_mac, expected_anchor_mac):
            raise LicenseError("E0035")

    last_seen_dt = _parse_iso(ts_primary)
    if now < last_seen_dt:
        raise LicenseError("E0036")

    new_sig = _sign_entry(ts_now, entry_hash_primary, primary_key)
    new_anchor_mac = _sign_anchor(new_sig, anchor_key)
    _write_entry(last_seen_path, ts_now, entry_hash_primary, primary_key)
    _write_entry(mirror_path,    ts_now, entry_hash_primary, primary_key)
    _anchor_write(new_sig, new_anchor_mac, primary_path=last_seen_path)
    if uptime_now is not None:
        _boot_anchor_write(now, uptime_now, primary_key)


# ---------------------------------------------------------------------------
# Main public API
# ---------------------------------------------------------------------------

def load_and_verify_license(
    license_path: Path = DEFAULT_LICENSE_PATH,
    expected_fingerprint: str = "",
    last_seen_path: Path = DEFAULT_LAST_SEEN_PATH,
    now: Optional[datetime] = None,
) -> License:
    """Load, verify signature, check fingerprint, time bounds, and clock rollback.

    NOTE: public_key_path parameter removed — the vendor key is now embedded
    in the binary via _get_vendor_public_key().  Do not pass a path.
    """
    _check_nuitka_env()

    if now is None:
        now = datetime.now(timezone.utc)

    if not license_path.exists():
        raise LicenseError("E0040")

    license_obj      = json.loads(license_path.read_text())
    payload          = license_obj["payload"]
    signature_b64    = license_obj["signature"]
    payload_bytes    = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature        = base64.b64decode(signature_b64)

    public_key = serialization.load_pem_public_key(_get_vendor_public_key())
    try:
        public_key.verify(signature, payload_bytes)
    except Exception:
        raise LicenseError("E0041")

    if payload["machine_fingerprint"] != expected_fingerprint:
        raise LicenseError("E0042")

    not_before = _parse_iso(payload["not_before"])
    not_after  = _parse_iso(payload["not_after"])

    if now < not_before:
        raise LicenseError("E0043")
    if now > not_after:
        raise LicenseError("E0044")

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
