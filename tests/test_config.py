from src.config import assert_no_leakage, FORBIDDEN_COLS, ALLOWED_VULN_COLS
import pytest

def test_allowed_passes():
    assert_no_leakage(ALLOWED_VULN_COLS + ["epss"])

def test_forbidden_raises():
    with pytest.raises(ValueError):
        assert_no_leakage(["cve_id", FORBIDDEN_COLS[0]])
