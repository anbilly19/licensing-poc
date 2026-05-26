"""OneMachine Licensing — Activation Server.

A lightweight FastAPI server that handles:
  POST /activate    — validate activation key, check seat cap, return signed license.json
  POST /heartbeat   — re-sign and extend an existing license; returns {valid, license}
  POST /admin/create-key  — (protected) create a new activation key for a customer

Run (dev):
    uv run uvicorn src.activation_server:app --reload --port 8000

Environment variables:
    PRIVATE_KEY_PATH   path to private_key.pem  (default: private_key.pem)
    DB_PATH            path to seats.db          (default: seats.db)
    ADMIN_TOKEN        bearer token for /admin/* endpoints

Production notes:
    - Put behind HTTPS (nginx / caddy) — never run plain HTTP in prod.
    - ADMIN_TOKEN must be a strong random secret (e.g. openssl rand -hex 32).
    - DB_PATH should point to a persistent volume.
    - private_key.pem must NEVER be committed to the repo; inject via secret.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

try:
    from fastapi import FastAPI, HTTPException, Header, Depends
    from pydantic import BaseModel
except ImportError as e:
    raise ImportError(
        "FastAPI and pydantic are required for the activation server. "
        "Install with: uv pip install fastapi uvicorn"
    ) from e

from src.issuer import (
    InvalidActivationKeyError,
    SeatCapError,
    _init_db,
    _is_known_machine,
    create_activation_key,
    issue_license_for_activation,
)

app = FastAPI(title="OneMachine Activation Server", version="1.0.0")

_PRIVATE_KEY_PATH = Path(os.environ.get("PRIVATE_KEY_PATH", "private_key.pem"))
_DB_PATH          = Path(os.environ.get("DB_PATH",          "seats.db"))
_ADMIN_TOKEN      = os.environ.get("ADMIN_TOKEN",      "change-me-in-production")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ActivateRequest(BaseModel):
    activation_key:      str
    machine_fingerprint: str


class ActivateResponse(BaseModel):
    license: dict


class HeartbeatRequest(BaseModel):
    license_id:          str
    machine_fingerprint: str
    activation_key:      str


class HeartbeatResponse(BaseModel):
    valid:   bool
    license: Optional[dict] = None
    reason:  Optional[str]  = None


class CreateKeyRequest(BaseModel):
    activation_key:  str
    customer_id:     str
    customer_name:   str
    max_seats:       int        = 2
    features:        List[str]  = ["rag_chat"]
    minutes_valid:   float      = 525600.0  # 365 days default; use small values for testing


class CreateKeyResponse(BaseModel):
    activation_key: str
    customer_id:    str
    customer_name:  str
    max_seats:      int
    features:       List[str]
    minutes_valid:  float


# ---------------------------------------------------------------------------
# Auth dependency for admin endpoints
# ---------------------------------------------------------------------------

def _require_admin(authorization: str = Header(...)) -> None:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required.")
    token = authorization.removeprefix("Bearer ").strip()
    if token != _ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token.")


# ---------------------------------------------------------------------------
# POST /activate
# ---------------------------------------------------------------------------

@app.post("/activate", response_model=ActivateResponse)
def activate(req: ActivateRequest) -> ActivateResponse:
    """Client calls this on first run to obtain a signed license.

    1. Validates the activation key exists and hasn't expired.
    2. Checks seat count for that key.
    3. Signs and returns license.json payload.
    """
    try:
        lic = issue_license_for_activation(
            activation_key=req.activation_key,
            machine_fingerprint=req.machine_fingerprint,
            private_key_path=_PRIVATE_KEY_PATH,
            db_path=_DB_PATH,
        )
        return ActivateResponse(license=lic)
    except InvalidActivationKeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except SeatCapError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Activation failed: {e}")


# ---------------------------------------------------------------------------
# POST /heartbeat
# ---------------------------------------------------------------------------

@app.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(req: HeartbeatRequest) -> HeartbeatResponse:
    """Client calls this periodically to renew the license.

    - If the activation key is still valid and machine is known: re-sign and return.
    - If revoked / expired: return {valid: false} — binary stops working at expiry.
    """
    conn = _init_db(_DB_PATH)

    if not _is_known_machine(conn, req.machine_fingerprint):
        return HeartbeatResponse(valid=False, reason="Machine not registered.")

    row = conn.execute(
        "SELECT customer_id, customer_name, max_seats, features, minutes_valid, expires_at "
        "FROM activation_keys WHERE activation_key = ?",
        (req.activation_key,),
    ).fetchone()
    if row is None:
        return HeartbeatResponse(valid=False, reason="Activation key not found.")

    _, _, _, _, minutes_valid, expires_at = row
    now = datetime.now(timezone.utc)
    if expires_at:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if now > exp_dt:
            return HeartbeatResponse(
                valid=False,
                reason=f"License expired at {expires_at}. Please renew your subscription.",
            )

    try:
        lic = issue_license_for_activation(
            activation_key=req.activation_key,
            machine_fingerprint=req.machine_fingerprint,
            private_key_path=_PRIVATE_KEY_PATH,
            db_path=_DB_PATH,
            now=now,
        )
        return HeartbeatResponse(valid=True, license=lic)
    except Exception as e:
        return HeartbeatResponse(valid=False, reason=str(e))


# ---------------------------------------------------------------------------
# POST /admin/create-key  (protected)
# ---------------------------------------------------------------------------

@app.post("/admin/create-key", response_model=CreateKeyResponse,
          dependencies=[Depends(_require_admin)])
def admin_create_key(req: CreateKeyRequest) -> CreateKeyResponse:
    """Vendor portal calls this when a company purchases a license."""
    create_activation_key(
        activation_key=req.activation_key,
        customer_id=req.customer_id,
        customer_name=req.customer_name,
        max_seats=req.max_seats,
        features=req.features,
        minutes_valid=req.minutes_valid,
        db_path=_DB_PATH,
    )
    return CreateKeyResponse(
        activation_key=req.activation_key,
        customer_id=req.customer_id,
        customer_name=req.customer_name,
        max_seats=req.max_seats,
        features=req.features,
        minutes_valid=req.minutes_valid,
    )


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
