"""FixNext - src/history_rates.py
Strictly pre-2024 historical exposure rates, for use as model features without label leakage.
Reads ONLY data/{vulnerabilities,known_exploited}.csv.
Window: CVEs published 2019-01-01 .. 2023-12-31.
Label: on CISA KEV with date_added <= 2023-12-31 (later KEV additions are treated as unknown/future).
Smoothing: rate = (kev + 20*base_rate) / (cves + 20), base_rate = overall KEV rate in the window.
No post-2023 information is used: features are description text, assigner, first CWE, CVSS v3 severity
and attack vector - all known at publish time - and the label is cut off at 2023-12-31.
Run from repo root:  python -m src.history_rates
"""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "outputs" / "history"
OUT.mkdir(parents=True, exist_ok=True)

PRIOR = 20
WIN_START = "2019-01-01"
WIN_END = "2024-01-01"          # exclusive -> includes all of 2023
LABEL_CUTOFF = pd.Timestamp("2023-12-31")

# DEV-ENGINE's VENDOR_KEYWORDS (lowercase substring match; ios/sap as word-boundary regex)
VENDOR_KEYWORDS = ["microsoft", "windows", "cisco", "apple", "ios", "adobe", "chrome",
                   "android", "ivanti", "fortinet", "citrix", "vmware", "oracle", "sap",
                   "palo alto", "sonicwall", "wordpress"]
WORD_BOUNDARY = {"ios", "sap"}


def smooth(kev, cves, base):
    return (kev + PRIOR * base) / (cves + PRIOR)


def main():
    v = pd.read_csv(
        DATA / "vulnerabilities.csv",
        usecols=["cve_id", "published", "assigner", "cwe_ids",
                 "cvss3_severity", "attack_vector", "description"],
        dtype=str,
    )
    v["published"] = pd.to_datetime(v["published"], errors="coerce")
    v = v[(v["published"] >= WIN_START) & (v["published"] < WIN_END)].copy()

    kev = pd.read_csv(DATA / "known_exploited.csv",
                      usecols=["cve_id", "date_added"], dtype=str)
    kev["date_added"] = pd.to_datetime(kev["date_added"], errors="coerce")
    known_set = set(kev.loc[kev["date_added"] <= LABEL_CUTOFF, "cve_id"])
    v = v.merge(kev[["cve_id", "date_added"]], on="cve_id", how="left")
    v["kev"] = v["cve_id"].isin(known_set).astype(int)
    v["lag_days"] = (v["date_added"] - v["published"]).dt.days

    n = len(v)
    total_kev = int(v["kev"].sum())
    base = v["kev"].mean()
    desc = v["description"].fillna("").str.lower()
    v["_assigner"] = v["assigner"].fillna("(none)")

    def grp_rates(key_series, min_cves, key_name):
        t = pd.DataFrame({key_name: key_series.values, "kev": v["kev"].values})
        g = t.groupby(key_name).agg(cves=("kev", "size"), kev=("kev", "sum")).reset_index()
        g = g[g["cves"] >= min_cves].copy()
        g["rate"] = smooth(g["kev"], g["cves"], base)
        return g.sort_values("rate", ascending=False).reset_index(drop=True)

    # a. assigner_rates (>=20 CVEs)
    assigner = grp_rates(v["_assigner"], 20, "assigner")
    assigner.to_csv(OUT / "assigner_rates.csv", index=False)

    # b. cwe_rates (first CWE id, >=20 CVEs)
    cwe_primary = v["cwe_ids"].fillna("").str.split(";").str[0].replace("", "(none)")
    cwe = grp_rates(cwe_primary, 20, "cwe_primary")
    cwe.to_csv(OUT / "cwe_rates.csv", index=False)

    # c. vendor_kw_rates
    rows = []
    for kw in VENDOR_KEYWORDS:
        if kw in WORD_BOUNDARY:
            mask = desc.str.contains(r"\b" + kw + r"\b", regex=True)
        else:
            mask = desc.str.contains(kw, regex=False)
        cv = int(mask.sum())
        kv = int(v.loc[mask, "kev"].sum())
        rows.append({"keyword": kw, "cves": cv, "kev": kv, "rate": smooth(kv, cv, base)})
    pd.DataFrame(rows).to_csv(OUT / "vendor_kw_rates.csv", index=False)

    # d. severity_rates
    sev = v["cvss3_severity"].fillna("(none)")
    sv = grp_rates(sev, 1, "cvss3_severity")
    sv.to_csv(OUT / "severity_rates.csv", index=False)

    # e. attack_vector_rates
    avc = v["attack_vector"].fillna("(none)")
    avr = grp_rates(avc, 1, "attack_vector")
    avr.to_csv(OUT / "attack_vector_rates.csv", index=False)

    # f. speed_by_assigner (KEV CVEs in window, >=5 KEV CVEs, + ALL row)
    kvv = v[(v["kev"] == 1) & (v["lag_days"].notna())]
    sp = kvv.groupby("_assigner").agg(
        n_kev=("lag_days", "size"),
        p25=("lag_days", lambda x: x.quantile(0.25)),
        median=("lag_days", "median"),
        p75=("lag_days", lambda x: x.quantile(0.75)),
    ).reset_index().rename(columns={"_assigner": "assigner"})
    sp = sp[sp["n_kev"] >= 5].sort_values("median").reset_index(drop=True)
    allrow = pd.DataFrame([{
        "assigner": "ALL",
        "n_kev": int(kvv.shape[0]),
        "p25": kvv["lag_days"].quantile(0.25),
        "median": kvv["lag_days"].median(),
        "p75": kvv["lag_days"].quantile(0.75),
    }])
    pd.concat([allrow, sp], ignore_index=True).to_csv(OUT / "speed_by_assigner.csv", index=False)

    # g. README
    L = []
    L.append("# FixNext - historical exposure rates (strictly pre-2024)")
    L.append("")
    L.append("Per-group KEV (exploitation) rates for use as **model features**, built so they cannot")
    L.append("leak any 2024+ training or validation label.")
    L.append("")
    L.append("## Window and label")
    L.append("- CVEs published **%s .. 2023-12-31** (inclusive)." % WIN_START)
    L.append("- Label = on CISA KEV with **date_added <= 2023-12-31**. KEV entries added after that date")
    L.append("  are treated as unknown (label 0): they are 'future' relative to this window.")
    L.append("- Features used: description text, assigner, first CWE id, CVSS v3 severity, attack vector -")
    L.append("  all known at publish time. No EPSS, no exploit flags, no NVD-review fields, nothing dated after 2023.")
    L.append("")
    L.append("## Smoothing")
    L.append("- rate = (kev + %d * base_rate) / (cves + %d)" % (PRIOR, PRIOR))
    L.append("- base_rate (overall KEV rate in window) = **%.4f** (%.2f%%), %d of %d CVEs." % (base, base * 100, total_kev, n))
    L.append("")
    L.append("## Row counts")
    L.append("| table | rows (groups) | min group size |")
    L.append("| --- | --- | --- |")
    L.append("| assigner_rates.csv | %d | >=20 CVEs |" % len(assigner))
    L.append("| cwe_rates.csv | %d | >=20 CVEs |" % len(cwe))
    L.append("| vendor_kw_rates.csv | %d | all keywords |" % len(VENDOR_KEYWORDS))
    L.append("| severity_rates.csv | %d | all |" % len(sv))
    L.append("| attack_vector_rates.csv | %d | all |" % len(avr))
    L.append("| speed_by_assigner.csv | %d | >=5 KEV CVEs (+ALL) |" % (len(sp) + 1))
    (OUT / "history_README.md").write_text("\n".join(L))

    # ---- prints ----
    print("=" * 60)
    print("history_rates - window %s..2023-12-31, label cutoff 2023-12-31" % WIN_START)
    print("=" * 60)
    print("CVEs in window        : %d" % n)
    print("KEV (<=2023-12-31)    : %d" % total_kev)
    print("base_rate             : %.4f  (%.2f%%)" % (base, base * 100))
    print("-" * 60)
    print("rows: assigner=%d  cwe=%d  vendor_kw=%d  severity=%d  attack_vector=%d  speed=%d(+ALL)"
          % (len(assigner), len(cwe), len(VENDOR_KEYWORDS), len(sv), len(avr), len(sp)))
    print("-" * 60)
    print("top 10 assigners by smoothed rate (>=20 CVEs):")
    print(assigner.head(10).to_string(index=False))
    print("=" * 60)


if __name__ == "__main__":
    main()
