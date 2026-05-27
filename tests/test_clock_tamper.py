"""Tests for clock sanity, mirror/anchor tamper detection, and last_seen chain integrity.

The conftest autouse fixtures already patch:
  - _ntp_time          -> None
  - _boot_time_estimate-> None
  - _get_mirror_path   -> tmp_path / mirror_last_seen.json
  - _anchor_read       -> None
  - _anchor_write      -> no-op
  - _boot_anchor_write -> no-op
  - _boot_anchor_read  -> None

Each test that needs to exercise anchor or NTP logic overrides those patches
locally with its own `with patch(...)` context.
"""
import json
import hmac
import hashlib
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src.keygen import generate_keypair
from src.issuer import issue_license
from src.license_core import (
    load_and_verify_license,
    LicenseError,
    _sign_entry,
    _sign_anchor,
    _last_seen_hmac_key,
    _anchor_hmac_key,
)

FINGERPRINT = "a" * 64
FEATURES = ["rag_chat"]
NOW = datetime(2026, 5, 22, 15, 0, 0, tzinfo=timezone.utc)
START = NOW - timedelta(minutes=10)


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


# ---------------------------------------------------------------------------
# NTP clock sanity
# ---------------------------------------------------------------------------

def test_ntp_skew_raises_E0010(env):
    """NTP time differs from wall clock by more than tolerance -> E0010."""
    skewed_ntp = NOW + timedelta(minutes=5)
    with patch("src.license_core._ntp_time", return_value=skewed_ntp), \
         patch("src.license_core._boot_time_estimate", return_value=None):
        with pytest.raises(LicenseError, match="E0010"):
            _load(env, now=NOW)


def test_ntp_within_tolerance_passes(env):
    """NTP time within 90s tolerance -> no error."""
    close_ntp = NOW + timedelta(seconds=30)
    with patch("src.license_core._ntp_time", return_value=close_ntp), \
         patch("src.license_core._boot_time_estimate", return_value=None):
        lic = _load(env, now=NOW)
    assert lic.license_id is not None


def test_ntp_unreachable_does_not_raise(env):
    """If NTP and boot estimate are both None, clock sanity passes silently."""
    # conftest already patches both to None; just confirm no exception
    lic = _load(env, now=NOW)
    assert lic.license_id is not None


def test_boot_estimate_skew_raises_E0011(env):
    """Boot-derived time differs from wall clock by more than tolerance -> E0011."""
    skewed_boot = NOW + timedelta(minutes=5)
    with patch("src.license_core._ntp_time", return_value=None), \
         patch("src.license_core._boot_time_estimate", return_value=skewed_boot):
        with pytest.raises(LicenseError, match="E0011"):
            _load(env, now=NOW)


# ---------------------------------------------------------------------------
# license not_before in the future
# ---------------------------------------------------------------------------

def test_not_yet_valid_raises_E0043(tmp_path):
    """License issued in the future raises E0043."""
    priv = tmp_path / "private_key.pem"
    pub  = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    db = tmp_path / "seats.db"
    future_start = NOW + timedelta(hours=1)
    lic_obj = issue_license(FINGERPRINT, FEATURES, priv, db, minutes_valid=60, now=future_start)
    lic_path = tmp_path / "license.json"
    lic_path.write_text(json.dumps(lic_obj))
    last_seen = tmp_path / "last_seen.json"
    pub_bytes = pub.read_bytes()
    with patch("src.license_core._get_vendor_public_key", return_value=pub_bytes):
        with pytest.raises(LicenseError, match="E0043"):
            load_and_verify_license(
                license_path=lic_path,
                expected_fingerprint=FINGERPRINT,
                last_seen_path=last_seen,
                now=NOW,
            )


# ---------------------------------------------------------------------------
# Nuitka env guard
# ---------------------------------------------------------------------------

def test_nuitka_env_guard_raises(env, monkeypatch):
    """NUITKA_ONEFILE_DIRECTORY set -> SystemExit E0002."""
    monkeypatch.setenv("NUITKA_ONEFILE_DIRECTORY", "/tmp/fake")
    with pytest.raises(SystemExit, match="E0002"):
        _load(env, now=NOW)


# ---------------------------------------------------------------------------
# Mirror file tamper / mismatch
# ---------------------------------------------------------------------------

def test_primary_deleted_mirror_intact_raises_E0031(env):
    """Primary last_seen deleted but mirror present -> E0031."""
    _load(env, now=NOW)  # initialise both files
    env["last_seen"].unlink()
    later = NOW + timedelta(minutes=1)
    with pytest.raises(LicenseError, match="E0031"):
        _load(env, now=later)


def test_mirror_deleted_primary_intact_raises_E0032(env):
    """Mirror deleted but primary present -> E0032."""
    mirror_path = env["tmp"] / "mirror_last_seen.json"
    _load(env, now=NOW)  # initialise both files
    mirror_path.unlink()
    later = NOW + timedelta(minutes=1)
    with pytest.raises(LicenseError, match="E0032"):
        _load(env, now=later)


def test_primary_mirror_hash_divergence_raises_E0033(env):
    """Primary and mirror have different chain hashes -> E0033."""
    _load(env, now=NOW)  # write both files consistently
    # Corrupt the mirror by writing a different timestamp
    key = _last_seen_hmac_key()
    mirror_path = env["tmp"] / "mirror_last_seen.json"
    genesis = "0" * 64
    different_ts = (NOW + timedelta(seconds=42)).isoformat().replace("+00:00", "Z")
    sig = _sign_entry(different_ts, genesis, key)
    mirror_path.write_text(json.dumps({"last_seen": different_ts, "prev_hash": genesis, "sig": sig}))
    later = NOW + timedelta(minutes=1)
    with pytest.raises(LicenseError, match="E0033"):
        _load(env, now=later)


# ---------------------------------------------------------------------------
# last_seen.json corruption
# ---------------------------------------------------------------------------

def test_corrupt_last_seen_raises_E0020(env):
    """Malformed JSON in last_seen -> E0020."""
    _load(env, now=NOW)
    env["last_seen"].write_text("not-json{{{")
    # mirror also needs to be invalid to not mask the primary error
    mirror_path = env["tmp"] / "mirror_last_seen.json"
    mirror_path.write_text("not-json{{{")
    later = NOW + timedelta(minutes=1)
    with pytest.raises(LicenseError, match="E002[01]"):
        _load(env, now=later)


def test_hmac_invalid_last_seen_raises_E0021(env):
    """HMAC in last_seen.json doesn't match content -> E0021."""
    _load(env, now=NOW)
    data = json.loads(env["last_seen"].read_text())
    data["sig"] = "deadbeef" * 8  # wrong sig, correct length
    env["last_seen"].write_text(json.dumps(data))
    # keep mirror consistent with same bad sig so E0021 (not E0033) fires
    mirror_path = env["tmp"] / "mirror_last_seen.json"
    mirror_path.write_text(json.dumps(data))
    later = NOW + timedelta(minutes=1)
    with pytest.raises(LicenseError, match="E0021"):
        _load(env, now=later)


# ---------------------------------------------------------------------------
# Anchor tamper detection
# ---------------------------------------------------------------------------

def test_anchor_sig_mismatch_raises_E0034(env):
    """Anchor stores wrong sig (entry was replaced without updating anchor) -> E0034."""
    _load(env, now=NOW)
    # Restore real anchor_read to return a bad sig
    data = json.loads(env["last_seen"].read_text())
    bad_anchor = ("aa" * 32, _sign_anchor("aa" * 32, _anchor_hmac_key()))
    later = NOW + timedelta(minutes=1)
    with patch("src.license_core._anchor_read", return_value=bad_anchor):
        with pytest.raises(LicenseError, match="E0034"):
            _load(env, now=later)


def test_anchor_mac_mismatch_raises_E0035(env):
    """Anchor sig is correct but anchor_mac was tampered -> E0035."""
    _load(env, now=NOW)
    data = json.loads(env["last_seen"].read_text())
    key = _last_seen_hmac_key()
    correct_sig = _sign_entry(data["last_seen"], data["prev_hash"], key)
    bad_mac = "bb" * 32  # correct sig, wrong mac
    later = NOW + timedelta(minutes=1)
    with patch("src.license_core._anchor_read", return_value=(correct_sig, bad_mac)):
        with pytest.raises(LicenseError, match="E0035"):
            _load(env, now=later)


def test_files_deleted_anchor_present_raises_E0030(env):
    """Both files deleted but anchor still present (re-install attack) -> E0030."""
    mirror_path = env["tmp"] / "mirror_last_seen.json"
    # Do NOT call _load first — files never existed, but anchor is present
    fake_anchor = ("cc" * 32, "dd" * 32)
    with patch("src.license_core._anchor_read", return_value=fake_anchor):
        with pytest.raises(LicenseError, match="E0030"):
            _load(env, now=NOW)
