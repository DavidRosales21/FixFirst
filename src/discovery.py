"""FixFirst - src/discovery.py
Reproduce the 5 discovery findings (FINDINGS_v1.md) as tables + Plotly charts.
Reads ONLY data/{vulnerabilities,known_exploited,weakness_types}.csv (historical, 2021-2025).
Window: CVEs published 2021-01-01 .. 2025-12-31 inclusive. Labels: CISA KEV <= 2025-12-31.
Run from repo root:  python -m src.discovery
"""
from pathlib import Path
import pandas as pd
import plotly.graph_objects as go

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "outputs" / "charts"
OUT.mkdir(parents=True, exist_ok=True)

ACCENT = "#0F62FE"
GREY = "#8D8D8D"

PHRASES = [
    "vpn", "firewall", "gateway", "router", "authentication bypass",
    "remote code execution", "unauthenticated", "command injection",
    "deserialization", "use after free", "path traversal", "buffer overflow",
    "privilege escalation", "denial of service", "sql injection",
    "cross-site scripting", "plugin", "wordpress",
]


def lyt(title, xtitle="", ytitle="", left=90):
    return dict(
        template="plotly_white",
        font=dict(size=15, family="Arial, sans-serif"),
        width=1200, height=700,
        title=dict(text=title, font=dict(size=22), x=0.01, xanchor="left"),
        xaxis_title=xtitle, yaxis_title=ytitle,
        margin=dict(l=left, r=80, t=90, b=70),
        bargap=0.25, showlegend=False,
        paper_bgcolor="white", plot_bgcolor="white",
    )


def save(fig, name):
    fig.write_html(str(OUT / (name + ".html")), include_plotlyjs="cdn")
    fig.write_image(str(OUT / (name + ".png")), scale=2)


def pretty(a):
    a = str(a)
    if "@" in a:
        return a.split("@")[-1].split(".")[0]
    return a


def short_cwe(cwe_id, name):
    if not isinstance(name, str) or not name:
        return str(cwe_id)
    if "('" in name and "')" in name:
        return name[name.index("('") + 2: name.index("')")]
    return name if len(name) <= 32 else name[:30] + ".."


def to_md(df, fmt="{:.2f}"):
    cols = list(df.columns)
    lines = ["| " + " | ".join(str(c) for c in cols) + " |",
             "| " + " | ".join("---" for _ in cols) + " |"]
    for _, r in df.iterrows():
        cells = []
        for c in cols:
            x = r[c]
            if isinstance(x, float):
                cells.append(fmt.format(x))
            else:
                cells.append(str(x))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main():
    v = pd.read_csv(
        DATA / "vulnerabilities.csv",
        usecols=["cve_id", "published", "assigner", "cwe_ids",
                 "cvss3_score", "cvss3_severity", "description"],
        dtype=str,
    )
    v["published"] = pd.to_datetime(v["published"], errors="coerce")
    v = v[(v["published"] >= "2021-01-01") & (v["published"] < "2026-01-01")].copy()

    kev = pd.read_csv(DATA / "known_exploited.csv",
                      usecols=["cve_id", "date_added"], dtype=str)
    kev["date_added"] = pd.to_datetime(kev["date_added"], errors="coerce")
    kevset = set(kev["cve_id"])
    v["kev"] = v["cve_id"].isin(kevset).astype(int)
    v = v.merge(kev, on="cve_id", how="left")
    v["lag_days"] = (v["date_added"] - v["published"]).dt.days

    n = len(v)
    total_kev = int(v["kev"].sum())
    base = v["kev"].mean()
    desc = v["description"].fillna("").str.lower()
    v["_assigner"] = v["assigner"].fillna("(none)")

    # a. assigner_exposure (assigners with >= 200 CVEs, top 20 by kev)
    g = v.groupby("_assigner").agg(cves=("kev", "size"), kev=("kev", "sum")).reset_index()
    g = g[g["cves"] >= 200].copy()
    g["kev_rate_pct"] = g["kev"] / g["cves"] * 100
    g["share_of_all_kev_pct"] = g["kev"] / total_kev * 100
    g["lift_vs_base"] = (g["kev_rate_pct"] / 100) / base
    g["assigner_label"] = g["_assigner"].map(pretty)
    assigner_tbl = g.sort_values("kev", ascending=False).head(20).reset_index(drop=True)
    assigner_tbl = assigner_tbl[["_assigner", "assigner_label", "cves", "kev",
                                 "kev_rate_pct", "share_of_all_kev_pct", "lift_vs_base"]]
    assigner_tbl.to_csv(OUT / "assigner_exposure.csv", index=False)

    ms = v[v["_assigner"].str.contains("microsoft", case=False, na=False)]
    ms_kev = int(ms["kev"].sum())
    ms_share = ms_kev / total_kev * 100 if total_kev else 0.0

    # b. severity_exposure (per cvss3_severity)
    sv = v.copy()
    sv["cvss3_severity"] = sv["cvss3_severity"].fillna("(none)")
    s = sv.groupby("cvss3_severity").agg(cves=("kev", "size"), kev=("kev", "sum")).reset_index()
    s["rate_pct"] = s["kev"] / s["cves"] * 100
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "(none)": 5}
    s["_o"] = s["cvss3_severity"].map(order).fillna(99)
    s = s.sort_values("_o").drop(columns="_o").reset_index(drop=True)
    s.to_csv(OUT / "severity_exposure.csv", index=False)
    crit = s[s["cvss3_severity"] == "CRITICAL"]
    crit_rate = float(crit["rate_pct"].iloc[0]) if len(crit) else float("nan")

    # c. cwe_exposure (first CWE id with >= 300 CVEs)
    v["_cwe"] = v["cwe_ids"].fillna("").str.split(";").str[0].replace("", "(none)")
    c = v.groupby("_cwe").agg(cves=("kev", "size"), kev=("kev", "sum")).reset_index()
    c = c[c["cves"] >= 300].copy()
    c["rate_pct"] = c["kev"] / c["cves"] * 100
    c["lift"] = (c["rate_pct"] / 100) / base
    wt = pd.read_csv(DATA / "weakness_types.csv", usecols=["cwe_id", "name"], dtype=str)
    c = c.merge(wt, left_on="_cwe", right_on="cwe_id", how="left")
    c["cwe_id"] = c["_cwe"]
    c["short_name"] = [short_cwe(i, nm) for i, nm in zip(c["cwe_id"], c["name"])]
    c = c[["cwe_id", "name", "short_name", "cves", "kev", "rate_pct", "lift"]]
    c = c.sort_values("rate_pct", ascending=False).reset_index(drop=True)
    c.to_csv(OUT / "cwe_exposure.csv", index=False)
    best8 = c.head(8).copy()
    worst6 = c[c["cves"] >= 1000].sort_values("rate_pct").head(6).copy()
    xss = c[c["cwe_id"] == "CWE-79"]
    xss_cves = int(xss["cves"].iloc[0]) if len(xss) else -1
    xss_kev = int(xss["kev"].iloc[0]) if len(xss) else -1

    # d. speed (lag quantiles overall + median lag per top-8 assigner)
    lag_kev = v.loc[v["kev"] == 1, "lag_days"].dropna()
    qs = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0]
    qv = lag_kev.quantile(qs)
    overall = pd.DataFrame({"assigner": "ALL_KEV",
                            "metric": ["q%d" % int(p * 100) for p in qs],
                            "lag_days": [qv.loc[p] for p in qs]})
    top8 = assigner_tbl.head(8)["_assigner"].tolist()
    rows = []
    for a in top8:
        med = v.loc[(v["_assigner"] == a) & (v["kev"] == 1), "lag_days"].median()
        rows.append({"assigner": pretty(a), "metric": "median_lag", "lag_days": med})
    speed = pd.concat([overall, pd.DataFrame(rows)], ignore_index=True)
    speed.to_csv(OUT / "speed.csv", index=False)
    median_lag = float(lag_kev.median())

    # e. phrase_exposure (lowercase substring in description)
    prows = []
    for p in PHRASES:
        mask = desc.str.contains(p, regex=False)
        cv = int(mask.sum())
        kv = int(v.loc[mask, "kev"].sum())
        rate = kv / cv * 100 if cv else 0.0
        lift = (rate / 100) / base if (cv and base) else 0.0
        prows.append({"phrase": p, "cves": cv, "kev": kv,
                      "kev_rate_pct": rate, "lift": lift})
    ph = pd.DataFrame(prows)
    ph.to_csv(OUT / "phrase_exposure.csv", index=False)
    wp = ph[ph["phrase"] == "wordpress"].iloc[0]

    # ---- headline numbers ----
    print("=" * 64)
    print("FixFirst discovery - headline numbers")
    print("=" * 64)
    print("CVEs in window (2021-2025) : %d" % n)
    print("base_rate                  : %.2f%%   (target 0.50%%)" % (base * 100))
    print("KEV in window              : %d       (target 813)" % total_kev)
    print("Microsoft share of all KEV : %.1f%%   (target 19.6%%)  [ms kev=%d]" % (ms_share, ms_kev))
    print("CRITICAL KEV rate          : %.2f%%   (target 1.32%%)" % crit_rate)
    print("XSS (CWE-79)               : %d of %d  (target 15 of 25,755)" % (xss_kev, xss_cves))
    print("WordPress phrase           : %d of %d  (target 0 of 13,542)" % (int(wp["kev"]), int(wp["cves"])))
    print("median lag to KEV          : %.0f days  (target 28)" % median_lag)
    print("=" * 64)

    # ---- discovery_tables.md ----
    never = 100 - crit_rate
    md = []
    md.append("# FixFirst - Discovery findings (reproduced by src/discovery.py)")
    md.append("")
    md.append("Window: CVEs published 2021-01-01..2025-12-31. Labels: CISA KEV <= 2025-12-31. "
              "Base rate %.2f%% (%d of %d)." % (base * 100, total_kev, n))
    md.append("")
    md.append("## F1. A few security teams account for most exploited CVEs")
    md.append("Headline: **Microsoft alone = %.1f%% of all KEV** - who issued the CVE beats how severe it is. "
              "Top assigners by KEV count (>=200 CVEs):" % ms_share)
    md.append("")
    md.append(to_md(assigner_tbl.drop(columns=["_assigner"]).head(15)))
    md.append("")
    md.append("## F2. Severity is a weak guide")
    md.append("Headline: **%.1f%% of CRITICAL CVEs are never exploited** (CRITICAL KEV rate %.2f%%)." % (never, crit_rate))
    md.append("")
    md.append(to_md(s))
    md.append("")
    md.append("## F3. Attackers ignore the most common bug types")
    md.append("Headline: **XSS (CWE-79): %d of %d exploited.** Top 8 and bottom 6 (>=1000 CVEs) weakness types:" % (xss_kev, xss_cves))
    md.append("")
    md.append(to_md(pd.concat([best8, worst6])[["cwe_id", "short_name", "cves", "kev", "rate_pct", "lift"]]))
    md.append("")
    md.append("## F4. Exploitation is fast")
    md.append("Headline: **median %.0f days from publish to KEV.** Lag quantiles and per-assigner medians:" % median_lag)
    md.append("")
    md.append(to_md(speed))
    md.append("")
    md.append("## F5. The attacker's vocabulary")
    md.append("Headline: **internet-edge + auth-bypass + RCE words raise the odds; XSS/WordPress near zero.** "
              "Description phrases by lift vs base:")
    md.append("")
    md.append(to_md(ph.sort_values("lift", ascending=False)))
    md.append("")
    (OUT / "discovery_tables.md").write_text("\n".join(md))

    # ---- charts ----
    # 1 - assigner lift
    a12 = assigner_tbl.head(12).sort_values("kev_rate_pct")  # top 12 by KEV count, ordered by rate (highest at top)
    fig = go.Figure(go.Bar(y=a12["assigner_label"], x=a12["kev_rate_pct"], orientation="h",
                           marker_color=ACCENT,
                           text=["%.1f%%" % r for r in a12["kev_rate_pct"]],
                           textposition="outside", cliponaxis=False))
    fig.add_vline(x=base * 100, line_dash="dash", line_color=GREY)
    fig.add_annotation(x=base * 100, y=1.02, yref="paper", showarrow=False,
                       text="base %.2f%%" % (base * 100), font=dict(size=13, color=GREY))
    fig.update_layout(**lyt("Who issued the CVE matters more than its severity",
                            "KEV rate (%)", "", left=150))
    save(fig, "1_assigner_lift")

    # 2 - severity
    s4 = s[s["cvss3_severity"].isin(["CRITICAL", "HIGH", "MEDIUM", "LOW"])].copy()
    s4["_o"] = s4["cvss3_severity"].map({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3})
    s4 = s4.sort_values("_o")
    fig = go.Figure(go.Bar(x=s4["cvss3_severity"], y=s4["rate_pct"], marker_color=ACCENT,
                           text=["%.2f%%" % r for r in s4["rate_pct"]],
                           textposition="outside", cliponaxis=False))
    fig.add_annotation(x="CRITICAL", y=crit_rate,
                       text="%.1f%% never exploited" % never,
                       showarrow=True, arrowhead=2, ax=70, ay=-45, font=dict(size=15))
    fig.update_layout(**lyt("Severity barely predicts exploitation",
                            "CVSS v3 severity", "KEV rate (%)", left=90))
    save(fig, "2_severity")

    # 3 - cwe best/worst
    best8 = best8.assign(grp="top")
    worst6 = worst6.assign(grp="bottom")
    cc = pd.concat([worst6, best8]).sort_values("rate_pct").reset_index(drop=True)
    colors = [ACCENT if grp == "top" else GREY for grp in cc["grp"]]
    labels = [sn + " (" + ci + ")" for sn, ci in zip(cc["short_name"], cc["cwe_id"])]
    fig = go.Figure(go.Bar(y=labels, x=cc["rate_pct"], orientation="h",
                           marker_color=colors,
                           text=["%.2f%%" % r for r in cc["rate_pct"]],
                           textposition="outside", cliponaxis=False))
    fig.update_layout(**lyt("Attackers ignore the most common bugs",
                            "KEV rate (%)  -  blue = highest, grey = lowest (>=1000 CVEs)", "", left=240))
    save(fig, "3_cwe_best_worst")

    # 4 - speed histogram
    h = lag_kev[(lag_kev >= 0) & (lag_kev <= 365)]
    fig = go.Figure(go.Histogram(x=h, xbins=dict(start=0, end=365, size=7),
                                 marker_color=ACCENT))
    meds = []
    for nm, sub in [("Apple", "apple"), ("Chrome", "chrome"), ("Microsoft", "microsoft"),
                    ("Cisco", "cisco"), ("Apache", "apache")]:
        m = v.loc[(v["_assigner"].str.contains(sub, case=False, na=False)) & (v["kev"] == 1), "lag_days"].median()
        meds.append("%s: %s" % (nm, ("%.0f d" % m) if pd.notna(m) else "n/a"))
    fig.add_annotation(xref="paper", yref="paper", x=0.98, y=0.98, align="left",
                       showarrow=False, bordercolor=GREY, borderwidth=1, bgcolor="white",
                       font=dict(size=14),
                       text="<b>Median days to KEV</b><br>" + "<br>".join(meds))
    fig.update_layout(**lyt("Exploitation is fast - most KEV within weeks of publish",
                            "Days from publish to KEV (7-day bins, 0-365)", "CVEs", left=90))
    save(fig, "4_speed")

    # 5 - phrases
    pp = ph.sort_values("lift")
    colors = [ACCENT if l > 1 else GREY for l in pp["lift"]]
    fig = go.Figure(go.Bar(y=pp["phrase"], x=pp["lift"], orientation="h",
                           marker_color=colors,
                           text=["%.1fx" % l for l in pp["lift"]],
                           textposition="outside", cliponaxis=False))
    fig.add_vline(x=1.0, line_dash="dash", line_color="#333333")
    fig.update_layout(**lyt("The attacker's vocabulary",
                            "KEV-rate lift vs base (x)", "", left=170))
    save(fig, "5_phrases")

    print("wrote 5 CSVs + discovery_tables.md + 5 charts (.html/.png) to", OUT)


if __name__ == "__main__":
    main()
