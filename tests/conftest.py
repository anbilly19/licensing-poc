from unittest.mock import patch
from datetime import datetime, timezone
import pytest


@pytest.fixture(autouse=True)
def mock_clock_sources():
    """Patch NTP and boot-time estimate to None so clock sanity checks
    degrade gracefully in CI (no real NTP / uptime available)."""
    with patch("src.license_core._ntp_time", return_value=None), \
         patch("src.license_core._boot_time_estimate", return_value=None):
        yield


@pytest.fixture(autouse=True)
def isolate_mirror(tmp_path):
    """Redirect _get_mirror_path into tmp_path so each test gets a clean,
    isolated mirror file and never touches the real filesystem mirror.
    Also suppresses all anchor reads/writes to avoid keychain/registry side
    effects in CI."""
    mirror_file = tmp_path / "mirror_last_seen.json"
    with patch("src.license_core._get_mirror_path", return_value=mirror_file), \
         patch("src.license_core._anchor_read", return_value=None), \
         patch("src.license_core._anchor_write"), \
         patch("src.license_core._boot_anchor_write"), \
         patch("src.license_core._boot_anchor_read", return_value=None):
        yield
