from unittest.mock import patch
from datetime import datetime, timezone
import pytest


@pytest.fixture(autouse=True)
def mock_clock_sources():
    """Patch NTP and boot-time estimate to match system time so clock sanity
    checks never fail in CI due to the frozen NOW constant used in tests."""
    with patch("src.license_core._ntp_time", return_value=None), \
         patch("src.license_core._boot_time_estimate", return_value=None):
        yield
