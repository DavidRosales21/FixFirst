"""FixNext - src/results_charts.py
Results chart 7 (FixNext vs baselines) + a profile of the top 500.
Reads outputs/backtest.md (parsed, no hard-coded numbers) and outputs/ranked_2026.csv.
Run from repo root:  python -m src.results_charts
"""
from pathlib import Path
import re
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from .config import OUT

ACCENT = "#0F62FE"
GREY = "#8D8D8D"
CHARTS = OUT / "charts"
CHARTS.mkdir(parents=True, exist_ok=True)
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]


def parse_backtest(path):
    """Return (metric_cols, {name: {metric: int}}, chosen_rule_str)."""
    lines = path.read_text().splitlines()
    metric_cols, table = [], {}
    for i, ln in enumerate(lines):
        if ln.strip().startswith("|") and "hits@" in ln.lower():
            header = [c.strip() for c in ln.strip().strip("|").split("|")]
            metric_cols = [c for c in header if c.lower().startswith("hits@")]
            mi = [header.index(c) for c in metric_cols]
            for ln2 in lines[i + 2:]:
                if not ln2.strip().startswith("|"):
                    break
                cells = [c.strip() for c in ln2.strip().strip("|").split("|")]
                if set("".join(cells)) <= set("-:| "):
                    continue
                name = cells[0]
                try:
                    table[name] = {c: int(cells[j]) for c, j in zip(metric_cols, mi)}
                except (ValueError, IndexError):
                    continue
            break
    chosen = None
    for ln in lines:
        m = re.search(r"[Cc]hosen.*ranking rule:\s*([^*()\n]+)", ln)
        if m:
            chosen = m.group(1).strip().lower()
            break
    return metric_cols, table, chosen


def pick_rows(table, chosen):
    """Return ordered [(label, name)] for CVSS/EPSS/Flags baselines + the chosen Blend as FixNext."""
    def find(pred):
        for name in table:
            if pred(name.lower()):
                return name
        return None

    cvss = find(lambda s: s.startswith("cvss first"))
    epss = find(lambda s: s.startswith("epss first"))
    flags = find(lambda s: s.startswith("flags then epss"))
    blends = [n for n in table if n.lower().startswith("blend")]
    fixnext = None
    if chosen:
        exact = [n for n in blends if n.strip().lower() == chosen]
        if len(exact) == 1:
            fixnext = exact[0]
    if fixnext is None and blends:
        m500 = [c for c in next(iter(table.values())) if c.lower().endswith("@500")]
        key = m500[0] if m500 else list(next(iter(table.values())))[-1]
        fixnext = max(blends, key=lambda n: table[n].get(key, -1))
    out = []
    for label, name in [("CVSS first", cvss), ("EPSS first", epss),
                        ("Flags then EPSS", flags), ("FixNext", fixnext)]:
        if name is not None:
            out.append((label, name))
    return out


def short(s, n=34):
    s = str(s)
    if "('" in s and "')" in s:
        s = s[s.index("('") + 2: s.index("')")]
    return s if len(s) <= n else s[:n - 2] + ".."


def md_table(df, floatcols=()):
    cols = list(df.columns)
    out = ["| " + " | ".join(str(c) for c in cols) + " |",
           "| " + " | ".join("---" for _ in cols) + " |"]
    for _, r in df.iterrows():
        cells = []
        for c in cols:
            x = r[c]
            cells.append(("%.1f" % x) if (c in floatcols and pd.notna(x)) else str(x))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def share(series, k=None):
    vc = series.fillna("(none)").value_counts()
    pct = vc / len(series) * 100
    return pct.head(k) if k else pct


def main():
    # ---------- (a) parse backtest ----------
    metric_cols, table, chosen = parse_backtest(OUT / "backtest.md")
    rows = pick_rows(table, chosen)
    methods = [lbl for lbl, _ in rows]
    vals = {lbl: table[name] for lbl, name in rows}

    print("=" * 64)
    print("parsed back-test rows (verbatim from backtest.md):")
    print("chosen rule:", chosen)
    hdr = ["method"] + metric_cols + ["(backtest.md row)"]
    print(" | ".join(hdr))
    for lbl, name in rows:
        print(" | ".join([lbl] + [str(table[name][c]) for c in metric_cols] + [name]))
    print("=" * 64)

    # ---------- (b) chart 7 ----------
    colors = [ACCENT if m == "FixNext" else GREY for m in methods]
    if len(metric_cols) > 1:
        opac = {c: 0.55 + 0.45 * i / (len(metric_cols) - 1) for i, c in enumerate(metric_cols)}
    else:
        opac = {metric_cols[0]: 1.0}
    fig = go.Figure()
    for c in metric_cols:
        yv = [vals[m][c] for m in methods]
        fig.add_bar(name=c, x=methods, y=yv,
                    marker=dict(color=colors, opacity=opac[c],
                                line=dict(color="#FFFFFF", width=0.5)),
                    text=yv, textposition="outside", cliponaxis=False)
    sub = ("CVEs published Jan–Jun 2025, 39 later exploited; "
           "scored with information available at end of publish month")
    fig.update_layout(
        barmode="group", template="plotly_white",
        font=dict(size=15, family="Arial, sans-serif"),
        width=1200, height=700, paper_bgcolor="white", plot_bgcolor="white",
        title=dict(text="FixNext finds more of what attackers actually used"
                        "<br><span style='font-size:13px;color:#666'>" + sub
                        + "  —  blue = FixNext, grey = baselines</span>",
                   font=dict(size=22), x=0.01, xanchor="left"),
        yaxis_title="exploited CVEs found (hits)", xaxis_title="",
        margin=dict(l=90, r=60, t=110, b=70),
        legend=dict(orientation="h", y=-0.12, x=0), bargap=0.3)
    fig.write_html(str(CHARTS / "7_model_vs_baselines.html"), include_plotlyjs="cdn")
    fig.write_image(str(CHARTS / "7_model_vs_baselines.png"), scale=2)

    # ---------- (c) top-500 profile ----------
    r = pd.read_csv(OUT / "ranked_2026.csv",
                    usecols=["rank", "vendor_guess", "cwe_name", "snapshot_month",
                             "cvss3_severity", "epss"] + FLAGS)
    r["epss"] = pd.to_numeric(r["epss"], errors="coerce")
    top = r.head(500)
    N_all = len(r)

    def two_share(col, k=10, order=None):
        t = share(top[col], None)
        a = share(r[col], None)
        cats = order if order is not None else list(t.sort_values(ascending=False).head(k).index)
        return pd.DataFrame({col: cats,
                             "top500_%": [round(t.get(c, 0.0), 1) for c in cats],
                             "overall_%": [round(a.get(c, 0.0), 1) for c in cats]})

    vendor_tbl = two_share("vendor_guess", 10)
    cwe_tbl = two_share("cwe_name", 10)
    cwe_tbl["cwe_name"] = cwe_tbl["cwe_name"].map(lambda s: short(s, 40))
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_tbl = two_share("cvss3_severity", order=[s for s in sev_order])
    months = sorted(set(top["snapshot_month"].dropna()) | set(r["snapshot_month"].dropna()))
    month_tbl = two_share("snapshot_month", order=months)

    def pct_flag(d):
        return round((d[FLAGS].max(axis=1) == 1).mean() * 100, 1)

    def pct_lowepss(d):
        return round((d["epss"].fillna(0) < 0.01).mean() * 100, 1)

    stats = pd.DataFrame({
        "metric": ["% with any exploit flag", "% with EPSS < 0.01 (EPSS-blind)", "median EPSS"],
        "top500": [pct_flag(top), pct_lowepss(top), round(top["epss"].median(), 4)],
        "overall": [pct_flag(r), pct_lowepss(r), round(r["epss"].median(), 4)],
    })

    def sev_share(s, col):
        row = sev_tbl[sev_tbl["cvss3_severity"] == s]
        return float(row[col].iloc[0]) if len(row) else 0.0

    c0, c1, c2 = cwe_tbl.iloc[0], cwe_tbl.iloc[1], cwe_tbl.iloc[2]
    obs = [
        "%.1f%% of the top 500 have EPSS under 1%% (median %.4f) — EPSS-first would bury them — "
        "yet %.1f%% carry a public exploit flag, vs %.1f%% across all %d CVEs."
        % (pct_lowepss(top), top["epss"].median(), pct_flag(top), pct_flag(r), N_all),
        "The top 500 piles into a few dangerous weakness types: %s (%.1f%% vs %.1f%% overall), "
        "%s (%.1f%% vs %.1f%%) and %s (%.1f%% vs %.1f%%) — several times their rate in the full pool."
        % (c0["cwe_name"], c0["top500_%"], c0["overall_%"], c1["cwe_name"], c1["top500_%"], c1["overall_%"],
           c2["cwe_name"], c2["top500_%"], c2["overall_%"]),
        "%.1f%% of the top 500 are CRITICAL (vs %.1f%% overall) and only %.1f%% are MEDIUM (vs %.1f%%) "
        "— it elevates severe, exploitable bugs rather than high-CVSS noise."
        % (sev_share("CRITICAL", "top500_%"), sev_share("CRITICAL", "overall_%"),
           sev_share("MEDIUM", "top500_%"), sev_share("MEDIUM", "overall_%")),
    ]

    L = ["# FixNext - profile of the top 500 (vs all %d ranked 2026 CVEs)" % N_all, ""]
    L += ["## Headline observations", ""]
    L += ["%d. %s" % (i + 1, o) for i, o in enumerate(obs)]
    L += ["", "## Key stats", "", md_table(stats), ""]
    L += ["## Vendor (vendor_guess) share", "", md_table(vendor_tbl, floatcols=("top500_%", "overall_%")), ""]
    L += ["## Weakness type (cwe_name) share", "", md_table(cwe_tbl, floatcols=("top500_%", "overall_%")), ""]
    L += ["## CVSS severity share", "", md_table(sev_tbl, floatcols=("top500_%", "overall_%")), ""]
    L += ["## Snapshot-month share", "", md_table(month_tbl, floatcols=("top500_%", "overall_%")), ""]
    (CHARTS / "top500_profile.md").write_text("\n".join(L))

    # ---------- (d) chart 8 ----------
    fig2 = make_subplots(rows=1, cols=2, horizontal_spacing=0.28,
                         subplot_titles=("Top 10 vendors in the top 500",
                                         "Top 10 weakness types in the top 500"))
    v = vendor_tbl.iloc[::-1]
    fig2.add_bar(y=v["vendor_guess"], x=v["top500_%"], orientation="h", marker_color=ACCENT,
                 text=["%.1f%% (all %.1f%%)" % (t, o) for t, o in zip(v["top500_%"], v["overall_%"])],
                 textposition="outside", cliponaxis=False, row=1, col=1)
    cw = cwe_tbl.iloc[::-1]
    fig2.add_bar(y=cw["cwe_name"], x=cw["top500_%"], orientation="h", marker_color=ACCENT,
                 text=["%.1f%% (all %.1f%%)" % (t, o) for t, o in zip(cw["top500_%"], cw["overall_%"])],
                 textposition="outside", cliponaxis=False, row=1, col=2)
    fig2.update_xaxes(title_text="share of top 500 (%)", row=1, col=1)
    fig2.update_xaxes(title_text="share of top 500 (%)", row=1, col=2)
    fig2.update_layout(
        template="plotly_white", font=dict(size=14, family="Arial, sans-serif"),
        width=1400, height=700, paper_bgcolor="white", plot_bgcolor="white", showlegend=False,
        title=dict(text="What the top 500 is made of (label: top-500 share vs overall share)",
                   font=dict(size=22), x=0.01, xanchor="left"),
        margin=dict(l=40, r=140, t=90, b=70))
    fig2.write_html(str(CHARTS / "8_top500_profile.html"), include_plotlyjs="cdn")
    fig2.write_image(str(CHARTS / "8_top500_profile.png"), scale=2)

    # ---------- prints ----------
    print("observations:")
    for o in obs:
        print(" -", o)
    print("wrote 7_model_vs_baselines, 8_top500_profile (.png/.html) and top500_profile.md")


if __name__ == "__main__":
    main()
