"""FixNext — shared config. Paths + the leakage rules, in code, so nobody forgets."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "outputs"
OUT.mkdir(exist_ok=True)

# ---- LEAKAGE RULES (master plan §2) ---------------------------------------
# Known at publish time / end of snapshot month → ALLOWED as features
ALLOWED_VULN_COLS = [
    "cve_id", "published", "assigner", "description", "cwe_ids",
    "cvss3_score", "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality_impact", "integrity_impact",
    "availability_impact",
]
# Filled in AFTER attacks (NIST reviews KEV items first) → NEVER features for 2026
FORBIDDEN_COLS = [
    "nvd_status", "n_references", "n_affected_cpes", "last_modified", "cvss3_source",
]
FORBIDDEN_FILES_FOR_2026 = ["references.csv", "affected_products.csv"]

SIGNAL_COLS = ["epss", "exploitdb", "metasploit", "nuclei", "poc_github"]

# Time splits for honest validation
TRAIN_MONTHS = ("2024-01", "2024-12")
VALID_MONTHS = ("2025-01", "2025-06")
KEV_CUTOFF = "2025-12-31"   # last label date available to us


def assert_no_leakage(columns):
    """Raise if a feature frame contains any forbidden column."""
    bad = [c for c in columns if c in FORBIDDEN_COLS]
    if bad:
        raise ValueError(f"LEAKAGE: forbidden columns in features: {bad}")
