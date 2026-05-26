import base64
import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src.keygen import generate_keypair
from src.issuer import issue_license
from src.license_core import load_and_verify_license, LicenseError

FINGERPRINT = "a" * 64
FEATURES = ["rag_chat", "transcriber"]
NOW = datetime(2026, 5, 22, 15, 0, 0, tzinfo=timezone.utc)
LICENSE_START = NOW - timedelta(minutes=10)


@pytest.fixture()
def env(tmp_path):
    priv = tmp_path / "private_key.pem"
    pub = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    db = tmp_path / "seats.db"
    lic_obj = issue_license(FINGERPRINT, FEATURES, priv, db, minutes_valid=30, now=LICENSE_START)
    lic_path = tmp_path / "license.json"
    lic_path.write_text(json.dumps(lic_obj))
    last_seen = tmp_path / "last_seen.json"
    return {"pub": pub, "lic": lic_path, "last_seen": last_seen, "tmp": tmp_path}


def _load(env, fingerprint=FINGERPRINT, now=NOW):
    """Call load_and_verify_license with the test-generated public key patched in."""
    pub_bytes = env["pub"].read_bytes()
    with patch("src.license_core._get_vendor_public_key", return_value=pub_bytes):
        return load_and_verify_license(
            license_path=env["lic"],
            expected_fingerprint=fingerprint,
            last_seen_path=env["last_seen"],
            now=now,
        )


def test_valid_license_loads(env):
    lic = _load(env)
    assert lic.license_id == "L-0001"
    assert "rag_chat" in lic.features


def test_expired_license_raises(env):
    future = NOW + timedelta(hours=2)
    with pytest.raises(LicenseError, match="expired"):
        _load(env, now=future)


def test_wrong_machine_raises(env):
    with pytest.raises(LicenseError, match="not issued for this machine"):
        _load(env, fingerprint="b" * 64)


def test_tampered_payload_raises(env):
    data = json.loads(env["lic"].read_text())
    data["payload"]["customer"] = "HACKED"
    env["lic"].write_text(json.dumps(data))
    with pytest.raises(LicenseError, match="Invalid signature"):
        _load(env)


def test_clock_rollback_raises(env):
    # First call at NOW sets last_seen
    _load(env, now=NOW)
    # Second call 5 min earlier — still inside validity window, but behind last_seen
    earlier = NOW - timedelta(minutes=5)
    with pytest.raises(LicenseError, match="Clock rollback"):
        _load(env, now=earlier)


def test_missing_license_file_raises(env):
    env["lic"].unlink()
    with pytest.raises(LicenseError, match="not found"):
        _load(env)
