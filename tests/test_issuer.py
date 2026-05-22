import base64
import json
import pytest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from src.keygen import generate_keypair
from src.issuer import issue_license, SeatCapError

FINGERPRINT_A = "a" * 64
FINGERPRINT_B = "b" * 64
FEATURES = ["rag_chat", "transcriber"]


@pytest.fixture()
def keypair(tmp_path):
    priv = tmp_path / "private_key.pem"
    pub = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    return priv, pub


@pytest.fixture()
def db(tmp_path):
    return tmp_path / "seats.db"


def test_license_has_required_fields(keypair, db):
    priv, _ = keypair
    lic = issue_license(FINGERPRINT_A, FEATURES, priv, db)
    for field in ("license_id", "customer", "machine_fingerprint", "not_before", "not_after", "features", "signature"):
        assert field in lic["payload"] or field == "signature" and "signature" in lic


def test_signature_verifies_with_public_key(keypair, db):
    priv, pub = keypair
    lic = issue_license(FINGERPRINT_A, FEATURES, priv, db)
    public_key = serialization.load_pem_public_key(pub.read_bytes())
    payload_bytes = json.dumps(lic["payload"], separators=(",", ":"), sort_keys=True).encode()
    sig = base64.b64decode(lic["signature"])
    public_key.verify(sig, payload_bytes)  # raises InvalidSignature on failure


def test_tampered_payload_fails_verification(keypair, db):
    priv, pub = keypair
    lic = issue_license(FINGERPRINT_A, FEATURES, priv, db)
    lic["payload"]["customer"] = "HACKED"
    public_key = serialization.load_pem_public_key(pub.read_bytes())
    payload_bytes = json.dumps(lic["payload"], separators=(",", ":"), sort_keys=True).encode()
    sig = base64.b64decode(lic["signature"])
    with pytest.raises(InvalidSignature):
        public_key.verify(sig, payload_bytes)


def test_seat_cap_enforced(keypair, db):
    priv, _ = keypair
    issue_license(FINGERPRINT_A, FEATURES, priv, db, max_seats=2)
    issue_license(FINGERPRINT_B, FEATURES, priv, db, max_seats=2)
    with pytest.raises(SeatCapError):
        issue_license("c" * 64, FEATURES, priv, db, max_seats=2)


def test_features_stored_in_license(keypair, db):
    priv, _ = keypair
    lic = issue_license(FINGERPRINT_A, ["rag_chat"], priv, db)
    assert lic["payload"]["features"] == ["rag_chat"]
