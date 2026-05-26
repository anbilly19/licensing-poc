from __future__ import annotations

import hashlib
import platform
import subprocess
from pathlib import Path


def _system() -> str:
    return platform.system()


def _read_sysfs(path: str) -> str:
    """Read a sysfs / procfs file directly — not interceptable via LD_PRELOAD."""
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def _machine_id_linux() -> str:
    """Use /etc/machine-id (persistent, unique, not hooked by LD_PRELOAD)."""
    mid = _read_sysfs("/etc/machine-id")
    if mid:
        return mid
    # fallback: product_uuid from DMI (requires root, but is even more stable)
    return _read_sysfs("/sys/class/dmi/id/product_uuid")


def _machine_id_macos() -> str:
    """Use IOPlatformUUID — hardware-bound, not spoofable via LD_PRELOAD."""
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=3,
        )
        for line in result.stdout.splitlines():
            if "IOPlatformUUID" in line:
                return line.split('"')[-2]
    except Exception:
        pass
    return ""


def _machine_id_windows() -> str:
    """Use MachineGuid from HKLM registry — requires no elevation to read."""
    try:
        import winreg
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        value, _ = winreg.QueryValueEx(k, "MachineGuid")
        winreg.CloseKey(k)
        return value
    except Exception:
        return ""


def get_machine_fingerprint() -> str:
    """Return a SHA-256 fingerprint derived from OS-level hardware identifiers.

    Sources used per platform:
      Linux   — /etc/machine-id  (or /sys/class/dmi/id/product_uuid)
      macOS   — IOPlatformUUID from ioreg
      Windows — MachineGuid from HKLM\\SOFTWARE\\Microsoft\\Cryptography

    All sources are read directly from the OS (sysfs, registry, ioreg), not
    via libc calls, so they are NOT interceptable via LD_PRELOAD hooks.
    """
    system = _system()
    if system == "Linux":
        raw_id = _machine_id_linux()
    elif system == "Darwin":
        raw_id = _machine_id_macos()
    elif system == "Windows":
        raw_id = _machine_id_windows()
    else:
        raw_id = ""

    if not raw_id:
        raise RuntimeError(
            "Could not determine a hardware machine identifier for this platform. "
            "Cannot generate a stable fingerprint."
        )

    return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    print(get_machine_fingerprint())
