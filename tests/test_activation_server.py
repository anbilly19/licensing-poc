"""Tests for the FastAPI activation server endpoints.

Uses httpx.AsyncClient / FastAPI TestClient to exercise all routes.
All DB and key operations use tmp_path so nothing touches the real filesystem.
"""
import json
import os
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.keygen import generate_keypair
from src.issuer import create_activation_key, _init_db
from src.activation_server import app

ADMIN_TOKEN = "test-admin-secret"
FINGERPRINT = "a" * 64
ACT_KEY     = "TEST-KEY-0001"
CUST_ID     = "cust-001"
CUST_NAME   = "Acme Corp"


@pytest.fixture()
def server_env(tmp_path):
    """Provision keys + DB, patch server module-level paths + ADMIN_TOKEN."""
    priv = tmp_path / "private_key.pem"
    pub  = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    db_path = tmp_path / "seats.db"

    create_activation_key(
        activation_key=ACT_KEY,
        customer_id=CUST_ID,
        customer_name=CUST_NAME,
        max_seats=2,
        features=["rag_chat"],
        minutes_valid=525600.0,
        db_path=db_path,
    )

    with patch("src.activation_server._PRIVATE_KEY_PATH", priv), \
         patch("src.activation_server._DB_PATH",          db_path), \
         patch("src.activation_server._ADMIN_TOKEN",      ADMIN_TOKEN):
        yield {"priv": priv, "pub": pub, "db": db_path, "tmp": tmp_path}


@pytest.fixture()
def client(server_env):
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# POST /activate
# ---------------------------------------------------------------------------

def test_activate_success(client):
    r = client.post("/activate", json={
        "activation_key": ACT_KEY,
        "machine_fingerprint": FINGERPRINT,
    })
    assert r.status_code == 200
    body = r.json()
    assert "license" in body
    assert body["license"]["payload"]["machine_fingerprint"] == FINGERPRINT


def test_activate_invalid_key_returns_E1001(client):
    r = client.post("/activate", json={
        "activation_key": "INVALID-KEY",
        "machine_fingerprint": FINGERPRINT,
    })
    assert r.status_code == 422
    assert r.json()["detail"] == "E1001"


def test_activate_seat_cap_returns_E1002(client, server_env):
    """Exceed seat cap (max_seats=2): activate 2 distinct machines, then a 3rd -> E1002."""
    # Activate two unique machines to fill all seats
    for fp in ["b" * 64, "c" * 64]:
        r = client.post("/activate", json={
            "activation_key": ACT_KEY,
            "machine_fingerprint": fp,
        })
        assert r.status_code == 200
    # Third unique machine must be rejected
    r = client.post("/activate", json={
        "activation_key": ACT_KEY,
        "machine_fingerprint": "d" * 64,
    })
    assert r.status_code == 422
    assert r.json()["detail"] == "E1002"


# ---------------------------------------------------------------------------
# POST /heartbeat
# ---------------------------------------------------------------------------

def test_heartbeat_valid(client):
    """Machine activated then heartbeat -> valid=True with renewed license."""
    client.post("/activate", json={
        "activation_key": ACT_KEY,
        "machine_fingerprint": FINGERPRINT,
    })
    r = client.post("/heartbeat", json={
        "license_id": "L-0001",
        "machine_fingerprint": FINGERPRINT,
        "activation_key": ACT_KEY,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["license"] is not None


def test_heartbeat_unknown_machine_returns_E2001(client):
    r = client.post("/heartbeat", json={
        "license_id": "L-0001",
        "machine_fingerprint": "z" * 64,
        "activation_key": ACT_KEY,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False
    assert body["code"] == "E2001"


def test_heartbeat_unknown_key_returns_E2002(client):
    """Machine is known (activated first) but activation key is wrong."""
    client.post("/activate", json={
        "activation_key": ACT_KEY,
        "machine_fingerprint": FINGERPRINT,
    })
    r = client.post("/heartbeat", json={
        "license_id": "L-0001",
        "machine_fingerprint": FINGERPRINT,
        "activation_key": "WRONG-KEY",
    })
    assert r.status_code == 200
    assert r.json()["code"] == "E2002"


def test_heartbeat_expired_key_returns_E2003(client, server_env):
    """Activation key expired -> E2003."""
    exp_key = "EXP-KEY-9999"
    create_activation_key(
        activation_key=exp_key,
        customer_id="cust-exp",
        customer_name="Expired Corp",
        max_seats=1,
        features=["rag_chat"],
        minutes_valid=-1.0,   # already expired
        db_path=server_env["db"],
    )
    # Seed the machine directly into issued_licenses so heartbeat sees it as known
    conn = _init_db(server_env["db"])
    conn.execute(
        """
        INSERT OR IGNORE INTO issued_licenses
            (license_id, machine_fingerprint, customer_id, activation_key, issued_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        ("L-exp", FINGERPRINT, "cust-exp", exp_key, "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    r = client.post("/heartbeat", json={
        "license_id": "L-exp",
        "machine_fingerprint": FINGERPRINT,
        "activation_key": exp_key,
    })
    assert r.status_code == 200
    assert r.json()["code"] == "E2003"


# ---------------------------------------------------------------------------
# POST /admin/create-key
# ---------------------------------------------------------------------------

def test_admin_create_key_success(client):
    r = client.post(
        "/admin/create-key",
        json={
            "activation_key": "NEW-KEY-0002",
            "customer_id":    "cust-002",
            "customer_name":  "Beta Corp",
            "max_seats":      5,
            "features":       ["rag_chat", "transcriber"],
            "minutes_valid":  525600.0,
        },
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["activation_key"] == "NEW-KEY-0002"
    assert body["max_seats"] == 5


def test_admin_create_key_no_token_returns_E3001(client):
    r = client.post(
        "/admin/create-key",
        json={
            "activation_key": "KEY-X",
            "customer_id":    "x",
            "customer_name":  "X",
        },
    )
    assert r.status_code == 422  # missing Header -> FastAPI 422 before our logic


def test_admin_create_key_wrong_token_returns_E3002(client):
    r = client.post(
        "/admin/create-key",
        json={
            "activation_key": "KEY-X",
            "customer_id":    "x",
            "customer_name":  "X",
        },
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "E3002"


def test_admin_create_key_malformed_bearer_returns_E3001(client):
    r = client.post(
        "/admin/create-key",
        json={
            "activation_key": "KEY-X",
            "customer_id":    "x",
            "customer_name":  "X",
        },
        headers={"Authorization": "NotBearer token"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "E3001"


# ---------------------------------------------------------------------------
# Activated key can immediately be re-activated on same machine (idempotent)
# ---------------------------------------------------------------------------

def test_activate_same_machine_twice_is_idempotent(client):
    """Same machine activating twice with same key should succeed both times."""
    for _ in range(2):
        r = client.post("/activate", json={
            "activation_key": ACT_KEY,
            "machine_fingerprint": FINGERPRINT,
        })
        assert r.status_code == 200
