import base64
import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.keygen import generate_keypair
from src.issuer import issue_license
from src.license_core import load_and_verify_license, LicenseError

FINGERPRINT = "a" * 64
FEATURES = ["rag_chat", "transcriber"]
NOW = datetime(2026, 5, 22, 15, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def env(tmp_path):
    priv = tmp_path / "private_key.pem"
    pub = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    db = tmp_path / "seats.db"
    lic_obj = issue_license(FINGERPRINT, FEATURES, priv, db, minutes_valid=10, now=NOW)
    lic_path = tmp_path / "license.json"
    lic_path.write_text(json.dumps(lic_obj))
    last_seen = tmp_path / "last_seen.json"
    return {"pub": pub, "lic": lic_path, "last_seen": last_seen, "tmp": tmp_path}


def test_valid_license_loads(env):
    lic = load_and_verify_license(env["lic"], env["pub"], FINGERPRINT, env["last_seen"], now=NOW)
    assert lic.license_id == "L-0001"
    assert "rag_chat" in lic.features


def test_expired_license_raises(env):
    future = NOW + timedelta(hours=2)
    with pytest.raises(LicenseError, match="expired"):
        load_and_verify_license(env["lic"], env["pub"], FINGERPRINT, env["last_seen"], now=future)


def test_wrong_machine_raises(env):
    with pytest.raises(LicenseError, match="not issued for this machine"):
        load_and_verify_license(env["lic"], env["pub"], "b" * 64, env["last_seen"], now=NOW)


def test_tampered_payload_raises(env):
    data = json.loads(env["lic"].read_text())
    data["payload"]["customer"] = "HACKED"
    env["lic"].write_text(json.dumps(data))
    with pytest.raises(LicenseError, match="Invalid signature"):
        load_and_verify_license(env["lic"], env["pub"], FINGERPRINT, env["last_seen"], now=NOW)


def test_clock_rollback_raises(env):
    load_and_verify_license(env["lic"], env["pub"], FINGERPRINT, env["last_seen"], now=NOW)
    earlier = NOW - timedelta(minutes=5)
    with pytest.raises(LicenseError, match="Clock rollback"):
        load_and_verify_license(env["lic"], env["pub"], FINGERPRINT, env["last_seen"], now=earlier)


def test_missing_license_file_raises(env):
    env["lic"].unlink()
    with pytest.raises(LicenseError, match="not found"):
        load_and_verify_license(env["lic"], env["pub"], FINGERPRINT, env["last_seen"], now=NOW)
