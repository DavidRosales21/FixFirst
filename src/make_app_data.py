"""FixNext - src/make_app_data.py
Light data files for the stlite dashboard (fixnext.select), loadable in a browser:
  app/ranked_light.csv  - first 5,000 ranked 2026 CVEs, dashboard-contract columns,
                          description truncated to 400 chars, + similar_cves (top 500) + rationale.
  app/backtest.csv      - method / hits_at_100 / hits_at_500 / positives_available,
                          parsed from outputs/backtest.md (3 baselines + the chosen Blend as FixNext).
Run from repo root:  python -m src.make_app_data
"""
from pathlib import Path
import re
import pandas as pd

from .config import OUT
from . import results_charts

APP = OUT.parent / "app"
DESC_MAX = 400
N_LIGHT = 5000


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


def main():
    # ---------- a. ranked_light.csv ----------
    r = pd.read_csv(OUT / "ranked_2026.csv", dtype=str)
    contract_cols = list(r.columns)
    light = r.head(N_LIGHT).copy()
    light["description"] = light["description"].map(trunc)

    sim = pd.read_csv(OUT / "similar_exploited.csv", dtype=str)
    sim_map = {row["cve_id"]: fmt_sim(row) for _, row in sim.iterrows()}
    ranks = pd.to_numeric(light["rank"], errors="coerce")
    light["similar_cves"] = [sim_map.get(cid, "") if (rk <= 500) else ""
                             for cid, rk in zip(light["cve_id"], ranks)]

    rat_path = OUT / "rationales.csv"
    if rat_path.exists():
        rat = pd.read_csv(rat_path, dtype=str)
        rmap = dict(zip(rat["cve_id"], rat["rationale"]))
        light["rationale"] = [rmap.get(cid, "" if pd.isna(cur) else cur)
                              for cid, cur in zip(light["cve_id"], light["rationale"])]
        merged_rat = True
    else:
        light["rationale"] = light["rationale"].fillna("")
        merged_rat = False

    out_cols = contract_cols + ["similar_cves"]
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
        recs.append({"method": method,
                     "hits_at_100": table[name][c100],
                     "hits_at_500": table[name][c500],
                     "positives_available": pos})
    bt = pd.DataFrame(recs, columns=["method", "hits_at_100", "hits_at_500", "positives_available"])
    bt.to_csv(APP / "backtest.csv", index=False)

    # ---------- c. prints ----------
    lp = APP / "ranked_light.csv"
    bp = APP / "backtest.csv"
    print("ranked_light.csv : %d rows, %d cols, %.2f MB  (similar_cves on top 500, rationale %s)"
          % (len(light), len(out_cols), lp.stat().st_size / 1e6,
             "merged from rationales.csv" if merged_rat else "empty - rationales.csv absent"))
    print("backtest.csv     : %d rows, %d bytes" % (len(bt), bp.stat().st_size))
    print(bt.to_string(index=False))


if __name__ == "__main__":
    main()
