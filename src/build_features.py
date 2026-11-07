"""Build one row per CVE (published 2024-01 → 2026-09) with leakage-safe features.

Output: outputs/features.parquet
Columns: cve_id, pub_month, split (train/valid/score), y (label; -1 for 2026),
         + ALLOWED_VULN_COLS + SIGNAL_COLS (at end of publish/snapshot month)

TODO (DEV-ENGINE, MSG-003): implement main() following hq_backtest.py logic.
"""
from .config import DATA, OUT, ALLOWED_VULN_COLS, SIGNAL_COLS, assert_no_leakage


def main():
    raise NotImplementedError("DEV-ENGINE: implement per MSG-003")


if __name__ == "__main__":
    main()
