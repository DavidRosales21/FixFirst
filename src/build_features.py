"""Build one row per CVE (published 2024-01 -> 2026) with leakage-safe features.

Output: outputs/features.parquet
One row per CVE. Columns: cve_id, pub_month, split (train/valid/late/score),
y (label; -1 for 2026), the allowed vulnerability columns, the snapshot-month
signals (epss + exploit flags), and derived text features.

Runnable as `python -m src.build_features`.

MSG-003 (DEV-ENGINE). Logic mirrors claude/hq_backtest.py; leakage rules and
the allowed-column list come from src/config.py (not re-declared here).
"""
import numpy as np
import pandas as pd

from .config import (
    DATA,
    OUT,
    ALLOWED_VULN_COLS,
    SIGNAL_COLS,
    TRAIN_MONTHS,
    VALID_MONTHS,
    assert_no_leakage,
)

# Lowercase substrings -> kw_<name> 0/1 flags on the description (MSG-003 step 5).
KEYWORDS = [
    "microsoft", "windows", "cisco", "apple", "ios", "adobe", "chrome",
    "android", "ivanti", "fortinet", "citrix", "vmware", "oracle", "sap",
    "palo alto", "sonicwall", "wordpress", "plugin", "router", "firewall",
    "vpn", "remote code execution", "unauthenticated", "zero-day",
    "in the wild", "exploited", "authentication bypass", "command injection",
    "deserialization", "path traversal", "buffer overflow",
]

# vendor_guess takes the first of these found in the description (list order),
# else "other". These are the vendor / product-brand keywords from the list
# above; the generic component words (plugin/router/firewall/vpn) and the
# attack-technique phrases are not vendors.
VENDOR_KEYWORDS = [
    "microsoft", "windows", "cisco", "apple", "ios", "adobe", "chrome",
    "android", "ivanti", "fortinet", "citrix", "vmware", "oracle", "sap",
    "palo alto", "sonicwall", "wordpress",
]

CHUNK = 1_000_000
SIG_READ_COLS = ["cve_id", "epss", "in_kev", "exploitdb", "metasploit", "nuclei", "poc_github"]


def _kw_col(kw):
    return "kw_" + kw.replace(" ", "_").replace("-", "_")


def load_vulnerabilities():
    """Allowed columns only, published 2024-01-01 onward, with pub_month."""
    v = pd.read_csv(DATA / "vulnerabilities.csv", usecols=ALLOWED_VULN_COLS, dtype=str)
    v["published"] = pd.to_datetime(v["published"], errors="coerce")
    v = v[v["published"] >= "2024-01-01"].copy()
    v["pub_month"] = v["published"].dt.strftime("%Y-%m")
    return v


def historical_signals(cve_ids):
    """Signal rows for our 2024-25 CVEs, read in chunks from both signal files."""
    keep = set(cve_ids)
    parts = []
    for fname in ("exploit_signals_2024.csv", "exploit_signals_2025.csv"):
        for ch in pd.read_csv(
            DATA / fname, dtype={"cve_id": str, "month": str}, chunksize=CHUNK
        ):
            parts.append(ch[ch["cve_id"].isin(keep)])
    return pd.concat(parts, ignore_index=True)


def build_historical(v):
    """2024-25 rows: signals at the publish month, labels, drop in-KEV rows."""
    hist = v[v["published"].dt.year <= 2025].copy()

    sig = historical_signals(hist["cve_id"])
    sig = sig.merge(hist[["cve_id", "pub_month"]], on="cve_id")
    sig = sig[sig["month"] == sig["pub_month"]][SIG_READ_COLS]
    hist = hist.merge(sig, on="cve_id", how="left")

    hist["epss"] = pd.to_numeric(hist["epss"], errors="coerce")  # missing -> NaN
    for c in ["in_kev", "exploitdb", "metasploit", "nuclei", "poc_github"]:
        hist[c] = pd.to_numeric(hist[c], errors="coerce").fillna(0).astype(int)

    # Drop rows already on KEV at the publish month (mirrors the scoreboard rule).
    hist = hist[hist["in_kev"] == 0].copy()

    kev = pd.read_csv(DATA / "known_exploited.csv", usecols=["cve_id", "date_added"], dtype=str)
    kev["date_added"] = pd.to_datetime(kev["date_added"], errors="coerce")
    hist = hist.merge(kev, on="cve_id", how="left")
    month_end = pd.to_datetime(hist["pub_month"]) + pd.offsets.MonthEnd(0)
    hist["y"] = ((hist["date_added"].notna()) & (hist["date_added"] > month_end)).astype(int)

    return hist.drop(columns=["date_added", "in_kev"])


def build_scoreboard(v):
    """2026 rows: signals from scoreboard, snapshot_month as pub_month, y = -1."""
    sb = pd.read_csv(
        DATA / "scoreboard_2026.csv",
        usecols=["cve_id", "snapshot_month", "epss", "exploitdb", "metasploit", "nuclei", "poc_github"],
        dtype=str,
    )
    score = v[v["published"].dt.year >= 2026].drop(columns=["pub_month"])
    score = score.merge(sb, on="cve_id", how="inner")  # 2026 CVEs not in scoreboard are dropped
    score["pub_month"] = score["snapshot_month"]
    score = score.drop(columns=["snapshot_month"])

    score["epss"] = pd.to_numeric(score["epss"], errors="coerce")
    for c in ["exploitdb", "metasploit", "nuclei", "poc_github"]:
        score[c] = pd.to_numeric(score[c], errors="coerce").fillna(0).astype(int)
    score["y"] = -1
    return score


def add_derived(df):
    desc = df["description"].fillna("")
    desc_lower = desc.str.lower()

    df["desc_len"] = desc.str.len().astype(int)
    df["cwe_primary"] = df["cwe_ids"].fillna("").str.split(";").str[0].replace("", "NONE")

    for kw in KEYWORDS:
        df[_kw_col(kw)] = desc_lower.str.contains(kw, regex=False).astype(int)

    vendor = pd.Series("other", index=df.index)
    for kw in reversed(VENDOR_KEYWORDS):  # reversed so earliest-in-list wins
        vendor = vendor.mask(desc_lower.str.contains(kw, regex=False), kw)
    df["vendor_guess"] = vendor
    return df


def assign_split(df):
    def split_of(m):
        if TRAIN_MONTHS[0] <= m <= TRAIN_MONTHS[1]:
            return "train"
        if VALID_MONTHS[0] <= m <= VALID_MONTHS[1]:
            return "valid"
        if "2025-07" <= m <= "2025-12":
            return "late"
        return "score"

    df["split"] = np.where(df["y"] == -1, "score", df["pub_month"].map(split_of))
    return df


def print_summary(df):
    print(f"saved outputs/features.parquet  rows={len(df)}  cols={df.shape[1]}")
    print("\n{:<8}{:>9}{:>12}{:>16}".format("split", "rows", "positives", "epss_missing%"))
    for s in ["train", "valid", "late", "score"]:
        d = df[df["split"] == s]
        pos = "y=-1" if s == "score" else str(int((d["y"] == 1).sum()))
        miss = 100.0 * d["epss"].isna().mean() if len(d) else 0.0
        print("{:<8}{:>9}{:>12}{:>16.1f}".format(s, len(d), pos, miss))
    print("\ntop 10 vendor_guess:")
    print(df["vendor_guess"].value_counts().head(10).to_string())


def main():
    v = load_vulnerabilities()
    df = pd.concat([build_historical(v), build_scoreboard(v)], ignore_index=True)
    df = add_derived(df)
    df = assign_split(df)

    assert_no_leakage(df.columns)
    OUT.mkdir(exist_ok=True)
    df.to_parquet(OUT / "features.parquet", index=False)

    print_summary(df)


if __name__ == "__main__":
    main()
