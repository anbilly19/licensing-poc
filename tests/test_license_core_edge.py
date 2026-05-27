"""Edge-case tests for license_core not covered by test_license_core.py."""
import json
import os
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.keygen import generate_keypair
from src.issuer import issue_license
from src.license_core import load_and_verify_license, LicenseError

FINGERPRINT = "a" * 64
FEATURES    = ["rag_chat"]
NOW         = datetime(2026, 5, 22, 15, 0, 0, tzinfo=timezone.utc)
START       = NOW - timedelta(minutes=10)


@pytest.fixture()
def env(tmp_path):
    priv = tmp_path / "private_key.pem"
    pub  = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    db = tmp_path / "seats.db"
    lic_obj = issue_license(FINGERPRINT, FEATURES, priv, db, minutes_valid=60, now=START)
    lic_path = tmp_path / "license.json"
    lic_path.write_text(json.dumps(lic_obj))
    last_seen = tmp_path / "last_seen.json"
    return {"pub": pub, "lic": lic_path, "last_seen": last_seen, "tmp": tmp_path}


def _load(env, fingerprint=FINGERPRINT, now=NOW):
    pub_bytes = env["pub"].read_bytes()
    with patch("src.license_core._get_vendor_public_key", return_value=pub_bytes):
        return load_and_verify_license(
            license_path=env["lic"],
            expected_fingerprint=fingerprint,
            last_seen_path=env["last_seen"],
            now=now,
        )


def test_vendor_public_key_missing_raises_E0001(env):
    """_get_vendor_public_key finds neither embedded bytes nor dev file -> E0001."""
    # Must NOT use _load() here — that helper patches _get_vendor_public_key to
    # return valid bytes, which would override the intent of this test.
    # Call load_and_verify_license directly with both key sources absent.
    with patch("src.license_core._VENDOR_PUBLIC_KEY_PEM", None), \
         patch("src.license_core._VENDOR_PUBLIC_KEY_FILE",
               env["tmp"] / "nonexistent_pub.pem"):
        with pytest.raises(LicenseError, match="E0001"):
            load_and_verify_license(
                license_path=env["lic"],
                expected_fingerprint=FINGERPRINT,
                last_seen_path=env["last_seen"],
                now=NOW,
            )


def test_multiple_sequential_loads_succeed(env):
    """Three loads advancing time should all succeed."""
    for delta in [0, 5, 10]:
        t = NOW + timedelta(minutes=delta)
        lic = _load(env, now=t)
        assert lic.customer is not None


def test_license_fields_are_correct(env):
    lic = _load(env, now=NOW)
    assert lic.machine_fingerprint == FINGERPRINT
    assert "rag_chat" in lic.features
    assert lic.not_before <= NOW <= lic.not_after
    assert lic.issued_at is not None


def test_signature_covers_all_payload_fields(env):
    """Tampering any payload field (not just customer) triggers E0041."""
    for field, value in [("machine_fingerprint", "z" * 64), ("max_version", "0.0.0")]:
        data = json.loads(env["lic"].read_text())
        data["payload"][field] = value
        env["lic"].write_text(json.dumps(data))
        with pytest.raises(LicenseError, match="E0041"):
            _load(env, now=NOW)
        # Restore for next iteration
        import src.issuer as issuer
        from src.keygen import generate_keypair as gkp
        priv, pub = env["pub"].parent / "private_key.pem", env["pub"]
        db = env["tmp"] / "seats.db"
        lic_obj = issuer.issue_license(FINGERPRINT, FEATURES, priv, db, minutes_valid=60, now=START)
        env["lic"].write_text(json.dumps(lic_obj))
        env["last_seen"].unlink(missing_ok=True)


def test_license_just_before_expiry_passes(env):
    """Load at not_after - 1s should succeed."""
    lic_data = json.loads(env["lic"].read_text())
    from src.license_core import _parse_iso
    not_after = _parse_iso(lic_data["payload"]["not_after"])
    just_before = not_after - timedelta(seconds=1)
    # Advance last_seen first so rollback check passes
    _load(env, now=NOW)
    env["last_seen"].unlink(missing_ok=True)
    mirror = env["tmp"] / "mirror_last_seen.json"
    mirror.unlink(missing_ok=True)
    lic = _load(env, now=just_before)
    assert lic is not None


def test_license_exactly_at_expiry_raises_E0044(env):
    """Load at not_after raises E0044."""
    lic_data = json.loads(env["lic"].read_text())
    from src.license_core import _parse_iso
    not_after = _parse_iso(lic_data["payload"]["not_after"])
    with pytest.raises(LicenseError, match="E0044"):
        _load(env, now=not_after)
