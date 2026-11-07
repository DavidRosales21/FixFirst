"""Validate outputs/top500.csv against the submission rules.
Usage: python scripts/check_top500.py [path/to/top500.csv] [path/to/scoreboard_2026.csv]
Exit code 0 = valid.
"""
import sys
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
top = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "outputs" / "top500.csv"
sb = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "data" / "scoreboard_2026.csv"

problems = []
df = pd.read_csv(top, dtype=str)
if list(df.columns) != ["cve_id"]:
    problems.append(f"columns must be exactly ['cve_id'], got {list(df.columns)}")
if len(df) != 500:
    problems.append(f"must have exactly 500 rows, got {len(df)}")
if df["cve_id"].duplicated().any():
    problems.append(f"{df['cve_id'].duplicated().sum()} duplicate cve_ids")
if not df["cve_id"].str.match(r"^CVE-\d{4}-\d{4,}$").all():
    problems.append("some cve_ids are not in CVE-YYYY-NNNN format")
if sb.exists():
    ids = set(pd.read_csv(sb, usecols=["cve_id"], dtype=str)["cve_id"])
    missing = df[~df["cve_id"].isin(ids)]
    if len(missing):
        problems.append(f"{len(missing)} cve_ids are not in scoreboard_2026.csv (e.g. {missing['cve_id'].head(3).tolist()})")
else:
    print(f"(warning) scoreboard not found at {sb}; skipped membership check")

if problems:
    print("top500.csv: PROBLEMS")
    for p in problems:
        print(" -", p)
    sys.exit(1)
print(f"top500.csv: OK ({len(df)} rows, all in scoreboard)")
