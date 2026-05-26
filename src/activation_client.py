"""OneMachine Licensing — Activation Client.

Handles the client-side of online activation:
  - POST /activate  on first run (no license.json present)
  - POST /heartbeat periodically to renew (every HEARTBEAT_INTERVAL_DAYS days)

The activation server URL is baked in at build time via ACTIVATION_SERVER_URL.
During development it reads from the environment variable or falls back to localhost.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Server URL — override at build time by patching this constant (like the
# public key) or set ACTIVATION_SERVER_URL env var for dev.
# ---------------------------------------------------------------------------
_ACTIVATION_SERVER_URL: Optional[str] = None  # patched at Nuitka build time

HEARTBEAT_INTERVAL_DAYS = 7
HEARTBEAT_STAMP_FILE    = Path(".onemachine_heartbeat")


def _server_url() -> str:
    if _ACTIVATION_SERVER_URL:
        return _ACTIVATION_SERVER_URL.rstrip("/")
    env = os.environ.get("ACTIVATION_SERVER_URL", "http://localhost:8000")
    return env.rstrip("/")


def _post(endpoint: str, payload: dict) -> dict:
    """Raw HTTP POST — uses only stdlib urllib so no extra dep in compiled binary."""
    import urllib.request
    import urllib.error

    url  = f"{_server_url()}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(body).get("detail", body)
        except Exception:
            detail = body
        raise RuntimeError(f"Server error {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Cannot reach activation server at {_server_url()}. "
            f"Check your internet connection. ({e.reason})"
        )


def activate(
    activation_key: str,
    machine_fingerprint: str,
    license_path: Path,
) -> None:
    """Call /activate and write the returned license to license_path.

    Called on first run when no license.json is present.
    """
    print(f"Activating against {_server_url()} ...")
    resp = _post("/activate", {
        "activation_key":      activation_key,
        "machine_fingerprint": machine_fingerprint,
    })
    lic = resp["license"]
    license_path.write_text(json.dumps(lic, indent=2))
    fp8       = machine_fingerprint[:8]
    customer  = lic["payload"].get("customer", "")
    not_after = lic["payload"].get("not_after", "")
    features  = ", ".join(lic["payload"].get("features", []))
    print(f"Activation successful.")
    print(f"  customer  : {customer}")
    print(f"  machine   : {fp8}...")
    print(f"  valid until: {not_after}")
    print(f"  features  : {features}")
    print(f"  license   : {license_path}")


def heartbeat(
    license_path: Path,
    machine_fingerprint: str,
    force: bool = False,
) -> bool:
    """Call /heartbeat if HEARTBEAT_INTERVAL_DAYS have passed since last call.

    Returns True if license was refreshed, False if not due yet or server
    returned valid=false (in which case the existing license will expire
    naturally — no forced shutdown).

    force=True skips the interval check (useful for testing).
    """
    if not license_path.exists():
        return False

    # Check whether heartbeat is due
    if not force and HEARTBEAT_STAMP_FILE.exists():
        try:
            last = datetime.fromisoformat(
                HEARTBEAT_STAMP_FILE.read_text().strip()
            )
            if datetime.now(timezone.utc) - last < timedelta(days=HEARTBEAT_INTERVAL_DAYS):
                return False  # not due yet
        except Exception:
            pass

    try:
        lic_data = json.loads(license_path.read_text())
    except Exception:
        return False

    payload        = lic_data.get("payload", {})
    license_id     = payload.get("license_id", "")
    activation_key = payload.get("activation_key", "")

    if not license_id or not activation_key:
        return False  # legacy license without activation_key — skip heartbeat

    try:
        resp = _post("/heartbeat", {
            "license_id":          license_id,
            "machine_fingerprint": machine_fingerprint,
            "activation_key":      activation_key,
        })
    except RuntimeError as e:
        # Network failure — degrade gracefully, don't break offline usage
        print(f"[heartbeat] Warning: {e}  (offline mode — using cached license)")
        return False

    if not resp.get("valid", False):
        reason = resp.get("reason", "License invalidated by server.")
        print(f"[heartbeat] License no longer valid: {reason}")
        print("[heartbeat] This machine will stop working when the current license expires.")
        return False

    # Write refreshed license
    new_lic = resp.get("license")
    if new_lic:
        license_path.write_text(json.dumps(new_lic, indent=2))
        HEARTBEAT_STAMP_FILE.write_text(
            datetime.now(timezone.utc).isoformat()
        )
        print("[heartbeat] License refreshed.")
        return True

    return False
