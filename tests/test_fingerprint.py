import re
from src.fingerprint import get_machine_fingerprint


def test_fingerprint_is_64_char_hex():
    fp = get_machine_fingerprint()
    assert re.fullmatch(r"[0-9a-f]{64}", fp), f"Expected 64-char hex, got: {fp!r}"


def test_fingerprint_is_stable():
    assert get_machine_fingerprint() == get_machine_fingerprint()


def test_fingerprint_is_non_empty():
    assert len(get_machine_fingerprint()) > 0
