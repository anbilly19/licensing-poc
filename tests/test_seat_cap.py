import pytest
from pathlib import Path

from src.keygen import generate_keypair
from src.issuer import issue_license, SeatCapError

FEATURES = ["rag_chat"]


@pytest.fixture()
def keypair(tmp_path):
    priv = tmp_path / "private_key.pem"
    pub = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    return priv, pub


@pytest.fixture()
def db(tmp_path):
    return tmp_path / "seats.db"


def test_first_two_seats_succeed(keypair, db):
    priv, _ = keypair
    issue_license("a" * 64, FEATURES, priv, db, max_seats=2)
    issue_license("b" * 64, FEATURES, priv, db, max_seats=2)


def test_third_seat_raises_seat_cap_error(keypair, db):
    priv, _ = keypair
    issue_license("a" * 64, FEATURES, priv, db, max_seats=2)
    issue_license("b" * 64, FEATURES, priv, db, max_seats=2)
    with pytest.raises(SeatCapError, match="Seat cap reached"):
        issue_license("c" * 64, FEATURES, priv, db, max_seats=2)


def test_seat_cap_of_one(keypair, db):
    priv, _ = keypair
    issue_license("a" * 64, FEATURES, priv, db, max_seats=1)
    with pytest.raises(SeatCapError):
        issue_license("b" * 64, FEATURES, priv, db, max_seats=1)


def test_different_dbs_are_independent(tmp_path):
    priv = tmp_path / "private_key.pem"
    pub = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)
    db1 = tmp_path / "seats1.db"
    db2 = tmp_path / "seats2.db"
    issue_license("a" * 64, FEATURES, priv, db1, max_seats=1)
    issue_license("b" * 64, FEATURES, priv, db2, max_seats=1)


def test_error_message_contains_cap_number(keypair, db):
    priv, _ = keypair
    issue_license("a" * 64, FEATURES, priv, db, max_seats=1)
    with pytest.raises(SeatCapError, match="1"):
        issue_license("b" * 64, FEATURES, priv, db, max_seats=1)
