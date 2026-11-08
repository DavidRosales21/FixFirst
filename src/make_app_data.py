"""FixNext - src/make_app_data.py
Light data files for the stlite dashboard (fixnext.select), loadable in a browser:
  app/ranked_light.csv  - first 5,000 ranked 2026 CVEs: dashboard-contract columns, description
                          truncated to 400 chars, + similar_cves (top 500) + rationale, + baseline
                          ranks (epss/flags/cvss, computed over all 72,670) + history lifts.
  app/backtest.csv      - method / hits_at_100 / hits_at_500 / positives_available (parsed from backtest.md).
  app/catches.csv       - caught-vs-missed rows the dashboard lists (FixNext only + both).
  app/profile.json      - top-500 vs overall summary stats for the dashboard.
Run from repo root:  python -m src.make_app_data
"""
from pathlib import Path
import re
import json
import pandas as pd

from .config import OUT
from . import results_charts

APP = OUT.parent / "app"
DESC_MAX = 400
N_LIGHT = 5000
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]


def trunc(s):
    s = "" if pd.isna(s) else str(s)
    return s if len(s) <= DESC_MAX else s[:DESC_MAX] + "…"


def parse_positives(path):
    m = re.search(r"positives available:\s*(\d+)", path.read_text())
    return int(m.group(1)) if m else ""


def fmt_sim(row):
    parts = []
    for i in (1, 2, 3):
        c = row.get("neighbour_%d_cve" % i)
        s = row.get("neighbour_%d_sim" % i)
        if pd.notna(c) and str(c).strip():
            try:
                s = "%.2f" % float(s)
            except (TypeError, ValueError):
                s = str(s)
            parts.append("%s (%s)" % (c, s))
    return "; ".join(parts)


def rank_desc(df, col):
    """1-based positional rank by col descending, NaN last (stable)."""
    order = df.sort_values(col, ascending=False, na_position="last", kind="mergesort").index
    return pd.Series(range(1, len(order) + 1), index=order).reindex(df.index)


def base_rate_from_history():
    p = OUT / "history" / "history_README.md"
    if p.exists():
        t = p.read_text()
        m = re.search(r"(\d[\d,]*)\s+of\s+(\d[\d,]*)\s+CVEs", t)
        if m:
            return int(m.group(1).replace(",", "")) / int(m.group(2).replace(",", ""))
        m = re.search(r"base_rate.*?=\s*\*{0,2}([0-9.]+)", t)
        if m:
            return float(m.group(1))
    return 0.0062


def lift_map(fname, key):
    p = OUT / "history" / fname
    if not p.exists():
        return {}
    d = pd.read_csv(p, dtype=str)
    return dict(zip(d[key], pd.to_numeric(d["rate"], errors="coerce")))


def _lift(val, m, base):
    rate = m.get(val)
    if rate is None or pd.isna(rate) or not base:
        return ""
    return round(float(rate) / base, 3)


def main():
    # ---------- a. ranked_light.csv ----------
    r = pd.read_csv(OUT / "ranked_2026.csv", dtype=str)
    contract_cols = list(r.columns)

    # baseline ranks over ALL 72,670 rows
    epss_num = pd.to_numeric(r["epss"], errors="coerce")
    cvss_num = pd.to_numeric(r["cvss3_score"], errors="coerce")
    anyflag = pd.concat([pd.to_numeric(r[c], errors="coerce").fillna(0) for c in FLAGS], axis=1).max(axis=1)
    aux = pd.DataFrame({"epss_": epss_num, "cvss_": cvss_num,
                        "flagscore_": anyflag * 10 + epss_num.fillna(0)}, index=r.index)
    r["epss_rank"] = rank_desc(aux, "epss_").astype(int)
    r["flags_rank"] = rank_desc(aux, "flagscore_").astype(int)
    r["cvss_rank"] = rank_desc(aux, "cvss_").astype(int)

    # history lifts (blank if the assigner / cwe isn't in the pre-2024 table)
    base = base_rate_from_history()
    amap = lift_map("assigner_rates.csv", "assigner")
    cmap = lift_map("cwe_rates.csv", "cwe_primary")
    r["assigner_lift"] = [_lift(a, amap, base) for a in r["assigner"]]
    r["cwe_lift"] = [_lift(c, cmap, base) for c in r["cwe_primary"]]

    light = r.head(N_LIGHT).copy()
    light["description"] = light["description"].map(trunc)

    sim = pd.read_csv(OUT / "similar_exploited.csv", dtype=str)
    sim_map = {row["cve_id"]: fmt_sim(row) for _, row in sim.iterrows()}
    ranks = pd.to_numeric(light["rank"], errors="coerce")
    light["similar_cves"] = [sim_map.get(cid, "") if (rk <= 500) else ""
                             for cid, rk in zip(light["cve_id"], ranks)]

    rat_frames = []
    for name in ("rationales.csv", "rationales_2.csv"):  # rationales_2 overrides on cve_id (last wins)
        p = OUT / name
        if p.exists():
            rat_frames.append(pd.read_csv(p, dtype=str))
    if rat_frames:
        rat = pd.concat(rat_frames, ignore_index=True).drop_duplicates("cve_id", keep="last")
        rmap = dict(zip(rat["cve_id"], rat["rationale"]))
        light["rationale"] = [rmap.get(cid, "" if pd.isna(cur) else cur)
                              for cid, cur in zip(light["cve_id"], light["rationale"])]
        merged_rat = "%d row(s) from %d file(s)" % (len(rat), len(rat_frames))
    else:
        light["rationale"] = light["rationale"].fillna("")
        merged_rat = "none (no rationale file present)"

    out_cols = contract_cols + ["similar_cves", "epss_rank", "flags_rank", "cvss_rank",
                                "assigner_lift", "cwe_lift"]
    APP.mkdir(parents=True, exist_ok=True)
    light[out_cols].to_csv(APP / "ranked_light.csv", index=False)

    # ---------- b. backtest.csv ----------
    metric_cols, table, chosen = results_charts.parse_backtest(OUT / "backtest.md")
    rows = results_charts.pick_rows(table, chosen)
    pos = parse_positives(OUT / "backtest.md")
    c100 = next(c for c in metric_cols if c.lower().endswith("@100"))
    c500 = next(c for c in metric_cols if c.lower().endswith("@500"))
    recs = []
    for label, name in rows:
        method = "FixNext model" if label == "FixNext" else label
        recs.append({"method": method, "hits_at_100": table[name][c100],
                     "hits_at_500": table[name][c500], "positives_available": pos})
    bt = pd.DataFrame(recs, columns=["method", "hits_at_100", "hits_at_500", "positives_available"])
    bt.to_csv(APP / "backtest.csv", index=False)

    # ---------- c. catches.csv ----------
    cvm = pd.read_csv(OUT / "charts" / "caught_vs_missed.csv", dtype=str)
    catch = cvm[cvm["bucket"].isin(["FixNext only", "both"])].copy()
    catch["_r"] = pd.to_numeric(catch["rank_fixnext"], errors="coerce")
    catch = catch.sort_values("_r")
    catch_cols = ["cve_id", "kev_name", "kev_vendor", "cwe_name", "cvss3_score", "epss",
                  "rank_fixnext", "rank_epss", "rank_flags_epss", "lag_days",
                  "known_ransomware_use", "bucket"]
    catch[catch_cols].to_csv(APP / "catches.csv", index=False)
    missed_all = int((cvm["bucket"] == "missed by all").sum())

    # ---------- d. profile.json ----------
    top = r.head(500)
    et = pd.to_numeric(top["epss"], errors="coerce")
    ft = pd.concat([pd.to_numeric(top[c], errors="coerce").fillna(0) for c in FLAGS], axis=1).max(axis=1)
    p1 = lambda x: round(float(x) * 100, 1)
    ts = top["cwe_name"].fillna("(none)").value_counts() / len(top) * 100
    asr = r["cwe_name"].fillna("(none)").value_counts() / len(r) * 100
    top_cwes = [{"name": nm, "pct_top500": round(float(ts.get(nm, 0.0)), 1),
                 "pct_all": round(float(asr.get(nm, 0.0)), 1)} for nm in ts.head(3).index]
    profile = {
        "pct_epss_under_1pct_top500": p1((et.fillna(0) < 0.01).mean()),
        "pct_epss_under_1pct_all": p1((epss_num.fillna(0) < 0.01).mean()),
        "pct_exploit_code_top500": p1((ft > 0).mean()),
        "pct_exploit_code_all": p1((anyflag > 0).mean()),
        "median_epss_top500": round(float(et.median()), 4),
        "top_cwes_top500": top_cwes,
        "pct_critical_top500": p1((top["cvss3_severity"] == "CRITICAL").mean()),
        "pct_critical_all": p1((r["cvss3_severity"] == "CRITICAL").mean()),
    }
    (APP / "profile.json").write_text(json.dumps(profile, indent=2))

    # ---------- e. prints ----------
    def nn(col):
        return int((light[col].astype(str).str.strip() != "").sum())

    lp = APP / "ranked_light.csv"
    print("ranked_light.csv : %d rows, %d cols, %.2f MB  (rationale: %s)"
          % (len(light), len(out_cols), lp.stat().st_size / 1e6, merged_rat))
    print("  new-column non-null (of top %d): epss_rank=%d  flags_rank=%d  cvss_rank=%d  assigner_lift=%d  cwe_lift=%d"
          % (N_LIGHT, nn("epss_rank"), nn("flags_rank"), nn("cvss_rank"), nn("assigner_lift"), nn("cwe_lift")))
    print("backtest.csv     : %d rows" % len(bt))
    print("catches.csv      : %d rows (FixNext only + both)   |   missed-by-all count = %d" % (len(catch), missed_all))
    print("profile.json     :")
    print(json.dumps(profile, indent=2))


if __name__ == "__main__":
    main()
