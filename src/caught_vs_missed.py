"""FixNext - src/caught_vs_missed.py
The human story behind the back-test number: of the 39 CVEs in the 2025-H1 valid split
that were later exploited, which did FixNext (blend) catch that the industry scores
missed, and which did everyone miss.

Imports the model from src.train (build_X / fit_model / flags_then_epss) - does NOT
reimplement it - and mirrors train.py's validation back-test exactly so the counts
reconcile with outputs/backtest.md.

Run from repo root:  python -m src.caught_vs_missed
"""
from pathlib import Path
import numpy as np
import pandas as pd
import plotly.graph_objects as go

from . import train
from .config import DATA, OUT

ACCENT = "#0F62FE"
GREY = "#8D8D8D"
CHARTS = OUT / "charts"
CHARTS.mkdir(parents=True, exist_ok=True)
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]

BUCKET_COLORS = {
    "FixNext only": "#0F62FE",
    "both": "#24A148",
    "baseline only": "#FF832B",
    "missed by all": "#DA1E28",
}
EXPECTED = {"fixnext": 19, "flags_epss": 17, "epss": 11, "cvss": 6}


def rank_and_in500(frame, col):
    """1-based rank by col desc (NaN last, stable), matching train.hits_at_k ordering."""
    order = frame.sort_values(col, ascending=False, na_position="last", kind="mergesort").index
    rank = pd.Series(np.arange(1, len(order) + 1), index=order).reindex(frame.index)
    return rank, rank <= 500


def short_name(name):
    if not isinstance(name, str) or not name:
        return ""
    if "('" in name and "')" in name:
        return name[name.index("('") + 2: name.index("')")]
    return name if len(name) <= 34 else name[:32] + ".."


def short_label(vendor, product):
    v = "" if pd.isna(vendor) else str(vendor)
    p = "" if pd.isna(product) else str(product)
    s = (v + " " + p).strip()
    return s[:20]


def fmt_epss(e):
    return "blank" if pd.isna(e) else "%.3f" % e


def fmt_cvss(c):
    return "n/a" if pd.isna(c) else "%.1f" % c


def md_table(rows, headers):
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out)


def main():
    df = pd.read_parquet(OUT / "features.parquet")
    df["y"] = pd.to_numeric(df["y"], errors="coerce").astype(int)

    # ---- mirror train.py's validation back-test exactly ----
    ev_df = df[df["split"].isin(["train", "valid"])].copy().reset_index(drop=True)
    Xev, cats = train.build_X(ev_df, (ev_df["split"] == "train").values)
    tr = (ev_df["split"] == "train").values
    va = (ev_df["split"] == "valid").values
    model = train.fit_model(Xev[tr], ev_df["y"].values[tr], cats)
    p_va = model.predict_proba(Xev[va])[:, 1]
    Xva = Xev[va]

    V = pd.DataFrame({
        "y": ev_df["y"].values[va],
        "model": p_va,
        "epss_first": Xva["epss"].values,
        "flags_then_epss": train.flags_then_epss(Xva).values,
        "cvss_first": Xva["cvss3_score"].values,
    }).reset_index(drop=True)
    V["blend"] = V["model"].rank(pct=True) + V["flags_then_epss"].rank(pct=True)

    V["rank_fixnext"], V["in500_fixnext"] = rank_and_in500(V, "blend")
    V["rank_epss"], V["in500_epss"] = rank_and_in500(V, "epss_first")
    V["rank_flags_epss"], V["in500_flags"] = rank_and_in500(V, "flags_then_epss")
    V["rank_cvss"], V["in500_cvss"] = rank_and_in500(V, "cvss_first")

    totals = {
        "fixnext": int(V.loc[V["y"] == 1, "in500_fixnext"].sum()),
        "epss": int(V.loc[V["y"] == 1, "in500_epss"].sum()),
        "flags_epss": int(V.loc[V["y"] == 1, "in500_flags"].sum()),
        "cvss": int(V.loc[V["y"] == 1, "in500_cvss"].sum()),
    }
    reconc = all(totals[k] == EXPECTED[k] for k in EXPECTED)

    # ---- the 39 positives + metadata ----
    pos = V.loc[V["y"] == 1].copy()
    meta = ev_df[va].reset_index(drop=True)
    pm = meta.loc[pos.index]
    pos["cve_id"] = pm["cve_id"].values
    pos["published_dt"] = pd.to_datetime(pm["published"].values, errors="coerce")
    pos["assigner"] = pm["assigner"].values
    pos["cwe_primary"] = pm["cwe_primary"].values
    pos["vendor_guess"] = pm["vendor_guess"].values
    pos["cvss3_score"] = pd.to_numeric(pm["cvss3_score"].values, errors="coerce")
    pos["epss"] = pd.to_numeric(pm["epss"].values, errors="coerce")
    for c in FLAGS:
        pos[c] = np.nan_to_num(pd.to_numeric(pm[c].values, errors="coerce")).astype(int)

    kev = pd.read_csv(DATA / "known_exploited.csv",
                      usecols=["cve_id", "vendor", "product", "name",
                               "date_added", "known_ransomware_use"], dtype=str)
    pos = pos.merge(kev, on="cve_id", how="left")
    pos["date_added_dt"] = pd.to_datetime(pos["date_added"], errors="coerce")
    pos["lag_days"] = (pos["date_added_dt"] - pos["published_dt"]).dt.days

    wk = pd.read_csv(DATA / "weakness_types.csv", usecols=["cwe_id", "name"], dtype=str)
    name_map = dict(zip(wk["cwe_id"], wk["name"]))
    pos["cwe_name"] = pos["cwe_primary"].map(name_map).fillna(pos["cwe_primary"])

    fn = pos["in500_fixnext"].astype(bool)
    bl = pos["in500_flags"].astype(bool)
    pos["bucket"] = np.select(
        [fn & ~bl, fn & bl, ~fn & bl, ~fn & ~bl],
        ["FixNext only", "both", "baseline only", "missed by all"], default="?")

    pos = pos.rename(columns={"name": "kev_name", "vendor": "kev_vendor", "product": "kev_product"})
    pos["published"] = pos["published_dt"].dt.strftime("%Y-%m-%d")
    pos["date_added"] = pos["date_added_dt"].dt.strftime("%Y-%m-%d")
    pos["label"] = [short_label(v, p) for v, p in zip(pos["kev_vendor"], pos["kev_product"])]
    for c in ["rank_fixnext", "rank_epss", "rank_flags_epss", "rank_cvss"]:
        pos[c] = pos[c].astype(int)
    pos = pos.sort_values("rank_fixnext").reset_index(drop=True)

    # ---- CSV ----
    cols = ["cve_id", "kev_name", "kev_vendor", "kev_product", "published", "date_added",
            "lag_days", "known_ransomware_use", "assigner", "cwe_name", "cvss3_score", "epss",
            "exploitdb", "metasploit", "nuclei", "poc_github",
            "rank_fixnext", "rank_epss", "rank_flags_epss", "rank_cvss",
            "in500_fixnext", "in500_epss", "in500_flags", "in500_cvss", "bucket"]
    pos[cols].to_csv(CHARTS / "caught_vs_missed.csv", index=False)

    # ---- 2x2 counts ----
    def two_by_two(base_col):
        b = pos[base_col].astype(bool)
        f = pos["in500_fixnext"].astype(bool)
        return {"FixNext only": int((f & ~b).sum()), "both": int((f & b).sum()),
                "baseline only": int((~f & b).sum()), "missed by all": int((~f & ~b).sum())}

    bb_flags = two_by_two("in500_flags")
    bb_epss = two_by_two("in500_epss")

    # ---- markdown ----
    def hard_note(r):
        why = []
        if pd.isna(r["epss"]):
            why.append("EPSS blank")
        elif r["epss"] < 0.05:
            why.append("low EPSS (%.3f)" % r["epss"])
        if pd.isna(r["cvss3_score"]):
            why.append("no CVSS")
        elif r["cvss3_score"] < 7:
            why.append("only MEDIUM/LOW severity")
        if r["vendor_guess"] == "other":
            why.append("not a high-exposure vendor")
        if int(r[["exploitdb", "metasploit", "nuclei", "poc_github"]].max()) == 0:
            why.append("no public exploit code at publish")
        return "; ".join(why) if why else "no obvious tell"

    L = []
    L.append("# FixNext - caught vs missed (2025-H1 valid split, 39 exploited CVEs)")
    L.append("")
    L.append("Reconciliation with outputs/backtest.md (hits@500): "
             "FixNext=%d (exp 19), flags-then-EPSS=%d (exp 17), EPSS=%d (exp 11), CVSS=%d (exp 6) - %s."
             % (totals["fixnext"], totals["flags_epss"], totals["epss"], totals["cvss"],
                "MATCH" if reconc else "MISMATCH, see note below"))
    L.append("")
    L.append("## FixNext vs the baseline (flags-then-EPSS), top 500")
    L.append(md_table(
        [["caught by FixNext", bb_flags["both"], bb_flags["FixNext only"]],
         ["missed by FixNext", bb_flags["baseline only"], bb_flags["missed by all"]]],
        ["", "caught by baseline", "missed by baseline"]))
    L.append("")
    L.append("- **FixNext only (we caught, baseline missed): %d**  |  both: %d  |  baseline only: %d  |  missed by all: %d"
             % (bb_flags["FixNext only"], bb_flags["both"], bb_flags["baseline only"], bb_flags["missed by all"]))
    L.append("")
    L.append("## FixNext vs EPSS-first, top 500")
    L.append("- FixNext only: %d  |  both: %d  |  EPSS only: %d  |  missed by both: %d"
             % (bb_epss["FixNext only"], bb_epss["both"], bb_epss["baseline only"], bb_epss["missed by all"]))
    L.append("")
    L.append("## The slide: CVEs FixNext caught that the baseline missed")
    fo = pos[pos["bucket"] == "FixNext only"]
    rows = []
    for _, r in fo.iterrows():
        rows.append([r["cve_id"], short_name(r["kev_name"]), r["kev_vendor"],
                     short_name(r["cwe_name"]), fmt_cvss(r["cvss3_score"]), fmt_epss(r["epss"]),
                     int(r["rank_fixnext"]), int(r["rank_flags_epss"]),
                     "" if pd.isna(r["lag_days"]) else int(r["lag_days"]),
                     "yes" if str(r["known_ransomware_use"]).strip() == "Known" else "no"])
    L.append(md_table(rows, ["CVE", "name", "vendor", "CWE", "CVSS", "EPSS@snapshot",
                             "FixNext rank", "baseline rank", "days to exploit", "ransomware"]))
    L.append("")
    L.append("## Missed by all (FixNext and baseline both missed) - the honest column")
    ma = pos[pos["bucket"] == "missed by all"]
    rows = []
    for _, r in ma.iterrows():
        rows.append([r["cve_id"], short_name(r["kev_name"]), r["kev_vendor"],
                     short_name(r["cwe_name"]), fmt_cvss(r["cvss3_score"]), fmt_epss(r["epss"]),
                     int(r["rank_fixnext"]), hard_note(r)])
    L.append(md_table(rows, ["CVE", "name", "vendor", "CWE", "CVSS", "EPSS@snapshot",
                             "FixNext rank", "why it's hard"]))
    L.append("")
    (CHARTS / "caught_vs_missed.md").write_text("\n".join(L))

    # ---- chart 6 ----
    fig = go.Figure()
    for b, color in BUCKET_COLORS.items():
        sub = pos[pos["bucket"] == b]
        if len(sub) == 0:
            continue
        fig.add_trace(go.Scatter(
            x=sub["rank_epss"], y=sub["rank_fixnext"], mode="markers+text",
            name="%s (%d)" % (b, len(sub)),
            marker=dict(size=12, color=color, line=dict(width=0.6, color="white")),
            text=sub["label"], textposition="top center", textfont=dict(size=9, color="#333333"),
            cliponaxis=False))
    fig.add_vline(x=500, line_dash="dash", line_color=GREY)
    fig.add_hline(y=500, line_dash="dash", line_color=GREY)
    fig.add_annotation(x=500, y=1, yref="paper", showarrow=False, yshift=6,
                       text="top 500 (EPSS)", font=dict(size=12, color=GREY))
    fig.update_xaxes(type="log", title="EPSS-first rank (log, 1 = best)")
    fig.update_yaxes(type="log", title="FixNext rank (log, 1 = best)")
    fig.update_layout(
        template="plotly_white", font=dict(size=14, family="Arial, sans-serif"),
        width=1200, height=700, paper_bgcolor="white", plot_bgcolor="white",
        title=dict(text="The exploited CVEs of 2025: who caught them", font=dict(size=22),
                   x=0.01, xanchor="left"),
        margin=dict(l=90, r=40, t=90, b=90),
        legend=dict(title="bucket", orientation="h", y=-0.16, x=0))
    fig.write_html(str(CHARTS / "6_caught_vs_missed.html"), include_plotlyjs="cdn")
    fig.write_image(str(CHARTS / "6_caught_vs_missed.png"), scale=2)

    # ---- prints ----
    print("=" * 64)
    print("caught vs missed - valid split, %d positives" % int(V["y"].sum()))
    print("=" * 64)
    print("hits@500 reconcile: FixNext=%d(19)  flags_epss=%d(17)  epss=%d(11)  cvss=%d(6)  -> %s"
          % (totals["fixnext"], totals["flags_epss"], totals["epss"], totals["cvss"],
             "MATCH" if reconc else "MISMATCH"))
    print("-" * 64)
    print("FixNext vs baseline (flags-then-EPSS):", bb_flags)
    print("FixNext vs EPSS-first               :", bb_epss)
    print("-" * 64)
    print("FixNext only (caught by us, missed by baseline):")
    show = fo[["cve_id", "kev_vendor", "kev_name", "cvss3_score", "epss",
               "rank_fixnext", "rank_flags_epss", "lag_days", "known_ransomware_use"]].copy()
    print(show.to_string(index=False))
    print("=" * 64)


if __name__ == "__main__":
    main()
