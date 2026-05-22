import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src.keygen import generate_keypair
from src.issuer import issue_license
from src.license_core import load_and_verify_license
from src.demo_app import run_rag, run_transcriber, run_nl_sql, run_reports, FeatureNotEnabledError

FINGERPRINT = "a" * 64
NOW = datetime(2026, 5, 22, 15, 0, 0, tzinfo=timezone.utc)
LICENSE_START = NOW - timedelta(minutes=10)


@pytest.fixture()
def make_license(tmp_path):
    """Factory: returns a verified License object for a given feature list."""
    priv = tmp_path / "private_key.pem"
    pub = tmp_path / "public_key.pem"
    generate_keypair(priv, pub)

    def _make(features):
        db = tmp_path / f"seats_{len(features)}.db"
        lic_obj = issue_license(FINGERPRINT, features, priv, db, minutes_valid=30, now=LICENSE_START)
        lic_path = tmp_path / "license.json"
        lic_path.write_text(json.dumps(lic_obj))
        last_seen = tmp_path / "last_seen.json"
        last_seen.unlink(missing_ok=True)
        with patch("src.license_core.datetime") as mock_dt:
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat = datetime.fromisoformat
        return load_and_verify_license(lic_path, pub, FINGERPRINT, last_seen, now=NOW)

    return _make


def test_enabled_rag_passes(make_license):
    lic = make_license(["rag_chat"])
    assert run_rag(lic) == "[RAG] Query executed."


def test_disabled_rag_raises(make_license):
    lic = make_license(["transcriber"])
    with pytest.raises(FeatureNotEnabledError, match="rag_chat"):
        run_rag(lic)


def test_enabled_transcriber_passes(make_license):
    lic = make_license(["transcriber"])
    assert run_transcriber(lic) == "[Transcriber] Audio transcribed."


def test_disabled_transcriber_raises(make_license):
    lic = make_license(["rag_chat"])
    with pytest.raises(FeatureNotEnabledError, match="transcriber"):
        run_transcriber(lic)


def test_enabled_nl_sql_passes(make_license):
    lic = make_license(["nl_sql"])
    assert run_nl_sql(lic) == "[NL-SQL] Query generated."


def test_disabled_nl_sql_raises(make_license):
    lic = make_license(["rag_chat"])
    with pytest.raises(FeatureNotEnabledError, match="nl_sql"):
        run_nl_sql(lic)


def test_multiple_features_all_pass(make_license):
    lic = make_license(["rag_chat", "transcriber", "nl_sql", "reports"])
    assert run_rag(lic)
    assert run_transcriber(lic)
    assert run_nl_sql(lic)
    assert run_reports(lic)


def test_partial_features_blocks_others(make_license):
    lic = make_license(["rag_chat", "nl_sql"])
    assert run_rag(lic)
    assert run_nl_sql(lic)
    with pytest.raises(FeatureNotEnabledError):
        run_transcriber(lic)
    with pytest.raises(FeatureNotEnabledError):
        run_reports(lic)
