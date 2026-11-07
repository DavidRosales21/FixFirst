# app/app.py — FixNext dashboard (Streamlit + Plotly) · fixnext.select
#
# Run from the repo root:   streamlit run app/app.py
#
# Reads only the two CSVs of the data contract (app/sample_ranked_2026.csv and
# app/sample_backtest.csv). Point it at the real model output with the
# FIXNEXT_RANKED / FIXNEXT_BACKTEST environment variables (the older FIXFIRST_* names
# from the task doc still work); no code changes.
# Theme (light / dark / system) and fonts live in app/.streamlit/config.toml and app/static/.

import html
import os
import random

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="FixNext — Before the Breach", page_icon="🛡️", layout="wide")

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = HERE  # the sample CSVs sit next to this file
RANKED_PATH = (os.environ.get("FIXNEXT_RANKED") or os.environ.get("FIXFIRST_RANKED")
               or os.path.join(DATA_DIR, "sample_ranked_2026.csv"))
BACKTEST_PATH = (os.environ.get("FIXNEXT_BACKTEST") or os.environ.get("FIXFIRST_BACKTEST")
                 or os.path.join(DATA_DIR, "sample_backtest.csv"))
USING_SAMPLE = os.path.basename(RANKED_PATH).startswith("sample_")

PAGES = ["Overview", "Fix-Next List", "CVE Detail", "Methodology"]
FLAGS = {"exploitdb": "Exploit-DB", "metasploit": "Metasploit", "nuclei": "Nuclei", "poc_github": "GitHub PoC"}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FILTER_KEYS = ["f_vendor", "f_cwe", "f_month", "f_sev", "f_exploit", "f_query"]

# Chart colors: IBM Carbon steps checked for contrast on both the light and the dark surface.
BLUE, TEAL, PURPLE, GRAY = "#4589FF", "#009D9A", "#A56EFF", "#8D8D8D"
YES, NO = "✓", "–"


# ---------------------------------------------------------------- data

@st.cache_data
def load_ranked(path):
    df = pd.read_csv(path, dtype={"cve_id": str, "rationale": str, "top_reasons": str, "description": str})
    for col in ["rationale", "top_reasons", "description", "assigner"]:
        df[col] = df[col].fillna("")
    df["vendor_guess"] = df["vendor_guess"].fillna("other")
    df["cwe_name"] = df["cwe_name"].fillna("Unknown")
    for col in ["rank", "score", "cvss3_score", "epss"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in FLAGS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
    df["has_exploit"] = df[list(FLAGS)].max(axis=1) == 1
    return df.sort_values("rank").reset_index(drop=True)


@st.cache_data
def load_backtest(path):
    return pd.read_csv(path)


ranked = load_ranked(RANKED_PATH)
backtest = load_backtest(BACKTEST_PATH)


# ---------------------------------------------------------------- small helpers

def esc(value):
    """Escape any CSV text before it goes into HTML."""
    return html.escape("" if value is None else str(value))


def is_blank(value):
    return value is None or (isinstance(value, float) and pd.isna(value)) or str(value).strip() == ""


def fmt(value, pattern="{:.2f}"):
    return NO if is_blank(value) else pattern.format(value)


def short(text, limit=40):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def cwe_label(name, cwe_id):
    """Readable, unique label: the common name in brackets if there is one, plus the CWE id."""
    name = str(name)
    if "('" in name and name.endswith("')"):
        name = name[name.index("('") + 2 : -2]
    name = short(name, 40)
    return f"{name} · {cwe_id}" if not is_blank(cwe_id) else name


def reasons(row):
    return [r.strip() for r in str(row["top_reasons"]).split(";") if r.strip()]


def main_reason(row):
    """The first reason that isn't the EPSS number (EPSS already shows elsewhere)."""
    rs = reasons(row)
    others = [r for r in rs if not r.upper().startswith("EPSS")]
    return (others or rs or [""])[0]


def flag_text(row):
    return " · ".join(f"{label} {YES if row[col] == 1 else NO}" for col, label in FLAGS.items())


def severity_html(row):
    sev = "" if is_blank(row["cvss3_severity"]) else str(row["cvss3_severity"]).upper()
    if is_blank(row["cvss3_score"]):
        return '<span>CVSS –</span>'
    css = {"CRITICAL": "ff-crit", "HIGH": "ff-high"}.get(sev, "")
    return f'<span class="{css}">CVSS {row["cvss3_score"]:.1f} {esc(sev)}</span>'


# ---------------------------------------------------------------- navigation callbacks

def open_detail(cve_id):
    st.session_state["page"] = "CVE Detail"
    st.session_state["detail_cve"] = cve_id


def open_page(name):
    st.session_state["page"] = name


def clear_filters():
    for key in FILTER_KEYS:
        st.session_state.pop(key, None)


# Keep filter values when a page that doesn't show the filters is open
# (Streamlit forgets a widget's value when the widget isn't drawn).
for _key in FILTER_KEYS:
    if _key in st.session_state:
        st.session_state[_key] = st.session_state[_key]


# ---------------------------------------------------------------- styles

CSS = """
<style class="ff-css">
:root{
  --ff-layer: color-mix(in srgb, currentColor 5%, transparent);
  --ff-line: color-mix(in srgb, currentColor 16%, transparent);
  --ff-muted: color-mix(in srgb, currentColor 70%, transparent);
  --ff-accent: color-mix(in srgb, #4589FF 72%, currentColor);
  --ff-ease: cubic-bezier(.4,.14,.3,1);
}
@property --p{syntax:'<number>';inherits:false;initial-value:0}
@keyframes ff-fill{from{--p:0}}
@keyframes ff-ring{0%{transform:scale(.92);opacity:.7}100%{transform:scale(1.45);opacity:0}}
@keyframes ff-rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes ff-reveal{from{clip-path:inset(0 100% 0 0)}to{clip-path:inset(0 0 0 0)}}
@keyframes ff-tick{from{transform:translateX(0)}to{transform:translateX(-50%)}}
@keyframes ff-blink{0%,100%{opacity:1}50%{opacity:.25}}
@keyframes ff-lit{0%{opacity:0;transform:scale(.4)}60%{opacity:1;transform:scale(1.15)}100%{opacity:1;transform:none}}
@keyframes ff-pulse{0%,100%{opacity:1}50%{opacity:.45}}
@keyframes ff-scan{from{transform:translateX(-10%)}to{transform:translateX(1000%)}}

.ff-mono{font-family:'IBM Plex Mono',monospace}
.ff-muted{color:var(--ff-muted)}
.ff-eyebrow{margin:0 0 8px;font-size:12px;letter-spacing:.32px;color:var(--ff-muted)}
.ff-h2{margin:0;font-size:16px;font-weight:400}
.ff-sub{margin:4px 0 8px;font-size:12px;color:var(--ff-muted)}

.ff-top{display:flex;flex-wrap:wrap;align-items:center;gap:6px 16px;padding:0 0 12px;border-bottom:1px solid var(--ff-line)}
.ff-top b{font-weight:600}
.ff-spacer{flex-grow:1}
.ff-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#42BE65;margin-right:8px;animation:ff-blink 1.6s ease-in-out infinite}

.ff-ticker{display:flex;align-items:center;height:44px;background:var(--ff-layer);overflow:hidden}
.ff-ticker-label{flex:0 0 auto;height:100%;display:flex;align-items:center;padding:0 16px;background:#0F62FE;color:#fff;font-size:13px;font-weight:600;letter-spacing:.32px}
.ff-ticker-window{flex:1 1 auto;min-width:0;overflow:hidden}
.ff-track{display:flex;width:max-content;animation:ff-tick 48s linear infinite}
.ff-ticker:hover .ff-track{animation-play-state:paused}
.ff-item{display:inline-flex;align-items:baseline;gap:10px;padding:0 28px;border-right:1px solid var(--ff-line);font-size:13px;white-space:nowrap}
.ff-item .ff-score{color:var(--ff-accent)}

.ff-hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:28px;align-items:center;background:var(--ff-layer);padding:28px;animation:ff-rise 700ms var(--ff-ease) both}
.ff-hero h1{margin:0;padding:0;font-weight:300;font-size:clamp(28px,2.8vw,40px);line-height:1.15}
.ff-hero h1 span{color:var(--ff-accent)}
.ff-hero p.ff-note{margin:16px 0 0;font-size:14px;line-height:1.5;color:var(--ff-muted);max-width:30em}
.ff-field{position:relative;overflow:hidden;background:#121212;padding:18px;border:1px solid var(--ff-line)}
.ff-grid{display:grid;grid-template-columns:repeat(32,minmax(0,1fr));gap:4px}
.ff-px{display:block;aspect-ratio:1;background:#393939}
.ff-px.lb,.ff-px.lp{animation:ff-lit 600ms var(--ff-ease) both,ff-pulse 3.2s ease-in-out 2s infinite}
.ff-px.lb{background:#4589FF}.ff-px.lp{background:#A56EFF}
.ff-px.d0{animation-delay:300ms,2s}.ff-px.d1{animation-delay:700ms,2.4s}.ff-px.d2{animation-delay:1100ms,2.8s}
.ff-px.d3{animation-delay:1500ms,3.2s}.ff-px.d4{animation-delay:1900ms,3.6s}.ff-px.d5{animation-delay:2300ms,4s}
.ff-scan{position:absolute;top:0;bottom:0;left:0;width:10%;background:linear-gradient(90deg,rgba(69,137,255,0),rgba(69,137,255,.28));border-right:2px solid #4589FF;pointer-events:none;animation:ff-scan 5s linear infinite}

.ff-card{background:var(--ff-layer);padding:24px;display:flex;flex-wrap:wrap;gap:28px;align-items:center;animation:ff-rise 700ms var(--ff-ease) 120ms both}
.ff-gauge-wrap{position:relative;width:150px;height:150px;flex:0 0 auto}
.ff-ring{position:absolute;inset:0;border-radius:50%;border:1px solid #4589FF;animation:ff-ring 2.6s cubic-bezier(.2,0,.38,.9) infinite}
.ff-ring.two{animation-delay:1.3s}
.ff-gauge{position:absolute;inset:0;border-radius:50%;background:conic-gradient(#4589FF calc(var(--p) * 1%),var(--ff-line) 0);
  -webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 12px),#000 calc(100% - 11px));
  mask:radial-gradient(farthest-side,transparent calc(100% - 12px),#000 calc(100% - 11px));
  animation:ff-fill 1.8s var(--ff-ease) .3s both}
.ff-gauge-num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ff-gauge-num b{font-family:'IBM Plex Mono',monospace;font-size:30px;font-weight:500}
.ff-gauge-num span{font-size:12px;color:var(--ff-muted)}
.ff-card-body{flex:1 1 260px;min-width:0}
.ff-cve{margin:0;font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:500;word-break:break-word}
.ff-card-meta{margin:6px 0 12px;font-size:14px;line-height:1.4;color:var(--ff-muted)}
.ff-pills{display:flex;flex-wrap:wrap;gap:8px}
.ff-pill{font-size:12px;padding:4px 10px;border-radius:24px;background:color-mix(in srgb,#4589FF 16%,transparent);color:var(--ff-accent)}
.ff-signals{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:14px;font-size:13px;color:var(--ff-muted)}
.ff-crit{color:color-mix(in srgb,#FA4D56 65%,currentColor)}
.ff-high{color:color-mix(in srgb,#FF832B 65%,currentColor)}
.ff-yes{color:color-mix(in srgb,#42BE65 60%,currentColor)}

.ff-box{background:var(--ff-layer);padding:20px 24px;animation:ff-rise 700ms var(--ff-ease) 200ms both}
.ff-box h2{margin:0 0 8px;font-size:16px;font-weight:600}
.ff-box p{margin:0;line-height:1.6;white-space:pre-line}
.ff-pending{color:var(--ff-muted);font-style:italic}
.ff-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:8px}
.ff-tile{background:var(--ff-layer);padding:14px 16px}
.ff-tile span{display:block;font-size:12px;color:var(--ff-muted);margin-bottom:10px}
.ff-tile b{font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:500}
.ff-empty{background:var(--ff-layer);padding:28px}
.ff-empty h2{margin:0 0 6px;font-size:18px;font-weight:400}
.ff-empty p{margin:0;color:var(--ff-muted)}

[data-testid="stMetric"]{background:var(--ff-layer);padding:16px 16px 20px;animation:ff-rise 700ms var(--ff-ease) 200ms both;
  min-height:148px;box-sizing:border-box;display:flex;flex-direction:column}
[data-testid="stMetric"] > div{flex:1 1 auto;display:flex;flex-direction:column}
[data-testid="stMetricValue"]{font-family:'IBM Plex Mono',monospace;margin-top:auto;padding-top:12px}
[data-testid="stHorizontalBlock"]:has([data-testid="stMetric"]){align-items:stretch}
[data-testid="stColumn"]:has([data-testid="stMetric"]) [data-testid="stVerticalBlock"],
[data-testid="stColumn"]:has([data-testid="stMetric"]) [data-testid="stElementContainer"],
[data-testid="stColumn"]:has([data-testid="stMetric"]) [data-testid="stMetric"]{height:100%}
@media (max-width:640px){[data-testid="stMetric"]{min-height:0}}
[data-testid="stMetricLabel"] *{white-space:normal !important;overflow:visible !important;text-overflow:clip !important}
[class*="st-key-ffcard"]{background:var(--ff-layer);padding:20px;animation:ff-rise 700ms var(--ff-ease) 240ms backwards}
[data-testid="stPlotlyChart"]{animation:ff-reveal 1.1s var(--ff-ease) .35s backwards}

@media (prefers-reduced-motion:reduce){
  .ff-dot,.ff-track,.ff-hero,.ff-px.lb,.ff-px.lp,.ff-card,.ff-gauge,.ff-ring,.ff-box,
  [data-testid="stMetric"],[class*="st-key-ffcard"],[data-testid="stPlotlyChart"]{animation:none !important}
  .ff-scan,.ff-ring{display:none}
  .ff-ticker-window{overflow-x:auto}
}
[data-testid="stElementContainer"]:has(style.ff-css){display:none}
</style>
"""
# st.html sanitizes away <style> tags, so the CSS goes in through st.markdown.
# Its (empty) block is hidden by the last rule above; the styles still apply.


# ---------------------------------------------------------------- page pieces

def top_bar():
    months = ranked["snapshot_month"].dropna().nunique()
    tag = f"{months} snapshot months" + (" · sample data, placeholder scores" if USING_SAMPLE else "")
    st.markdown(CSS, unsafe_allow_html=True)
    st.html(
        f'<div class="ff-top"><b>FixNext</b><span class="ff-muted">Before the Breach</span>'
        f'<span class="ff-spacer"></span><span class="ff-muted" style="font-size:12px">'
        f'<span class="ff-dot" aria-hidden="true"></span>{esc(tag)}</span></div>'
    )


def ticker(df):
    """Top 10 of the current view, scrolling. Pauses on hover; still with reduced motion."""
    top = df.head(10)
    if top.empty:
        return
    items = "".join(
        f'<span class="ff-item"><span class="ff-muted">#{int(r["rank"])}</span>'
        f'<span class="ff-mono">{esc(r["cve_id"])}</span>'
        f'<span class="ff-mono ff-score">{fmt(r["score"])}</span>'
        f'<span class="ff-muted">{esc(main_reason(r))}</span></span>'
        for _, r in top.iterrows()
    )
    st.html(
        '<div class="ff-ticker" role="region" aria-label="Top 10 to fix next">'
        '<span class="ff-ticker-label">FIX NEXT</span><div class="ff-ticker-window">'
        f'<div class="ff-track"><span style="display:flex">{items}</span>'
        f'<span style="display:flex" aria-hidden="true">{items}</span></div></div></div>'
    )


@st.cache_data
def field_cells():
    """416 squares; about 6% light up blue or purple. Fixed seed, so it looks the same every run."""
    rng = random.Random(7)
    cells = []
    for i in range(416):
        r = rng.random()
        cls = f"lb d{i % 6}" if r < 0.035 else f"lp d{(i + 3) % 6}" if r < 0.06 else ""
        cells.append(f'<span class="ff-px {cls}"></span>')
    return "".join(cells)


def hero(total):
    st.html(
        '<section class="ff-hero" aria-label="Scan">'
        '<div><p class="ff-eyebrow">SHERIDAN DATATHON 2026 · IBM TRACK</p>'
        f'<h1>{total:,} CVEs scanned.<br><span>The lit ones are next.</span></h1>'
        '<p class="ff-note">As the model scans 2026\'s CVEs, the riskiest light up and move '
        'to the top of the list.</p></div>'
        f'<div class="ff-field" aria-hidden="true"><div class="ff-grid">{field_cells()}</div>'
        '<span class="ff-scan"></span></div></section>'
    )


def cve_card(row, eyebrow, with_signals=True):
    """The gauge card: rank, CVE id, score ring, reasons and (optionally) the signals line."""
    score = 0.0 if is_blank(row["score"]) else float(row["score"])
    meta = " · ".join(x for x in [cwe_label(row["cwe_name"], row["cwe_primary"]), row["assigner"]] if x)
    pills = "".join(f'<span class="ff-pill">{esc(r)}</span>' for r in reasons(row))
    flags = "".join(
        f'<span>{label} <span class="ff-yes">{YES}</span></span>' if row[col] == 1 else f"<span>{label} {NO}</span>"
        for col, label in FLAGS.items()
    )
    signals = f'<div class="ff-signals">{severity_html(row)}{flags}</div>' if with_signals else ""
    st.html(
        '<section class="ff-card">'
        '<div class="ff-gauge-wrap"><span class="ff-ring" aria-hidden="true"></span>'
        '<span class="ff-ring two" aria-hidden="true"></span>'
        f'<div class="ff-gauge" style="--p:{score * 100:.1f}" role="img" aria-label="Score {score:.2f} out of 1"></div>'
        f'<div class="ff-gauge-num" aria-hidden="true"><b>{score:.2f}</b><span>model score</span></div></div>'
        f'<div class="ff-card-body"><p class="ff-eyebrow">{esc(eyebrow)}</p>'
        f'<p class="ff-cve">{esc(row["cve_id"])}</p><p class="ff-card-meta">{esc(meta)}</p>'
        f'<div class="ff-pills">{pills}</div>{signals}</div></section>'
    )


def empty_state(title, body, show_clear=True):
    st.html(f'<div class="ff-empty"><h2>{esc(title)}</h2><p>{esc(body)}</p></div>')
    if show_clear:
        st.button("Clear filters", on_click=clear_filters)


def chart_heading(title, subtitle):
    st.html(f'<h2 class="ff-h2">{esc(title)}</h2><p class="ff-sub">{esc(subtitle)}</p>')


def bar_chart(labels, values, colors, hovers, height=340, bargap=0.35):
    fig = go.Figure(
        go.Bar(
            x=values, y=labels, orientation="h",
            marker=dict(color=colors, cornerradius=4),
            text=values, textposition="outside", cliponaxis=False,
            customdata=hovers, hovertemplate="%{customdata}<extra></extra>",
        )
    )
    fig.update_layout(
        height=height, margin=dict(l=0, r=40, t=4, b=4), bargap=bargap, showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="IBM Plex Sans, Helvetica Neue, Arial, sans-serif", size=13),
    )
    fig.update_xaxes(visible=False)
    fig.update_yaxes(autorange="reversed", automargin=True, showgrid=False, ticks="", title=None)
    st.plotly_chart(fig, theme="streamlit", width="stretch", config={"displayModeBar": False})


def table_view(df):
    out = df[["rank", "cve_id", "score", "vendor_guess", "cwe_name", "cvss3_score", "epss"]].copy()
    for col, label in FLAGS.items():
        out[label] = df[col].eq(1).map({True: YES, False: NO})
    return out


TABLE_COLUMNS = {
    "rank": st.column_config.NumberColumn("Rank", format="%d", width="small"),
    "cve_id": st.column_config.TextColumn("CVE"),
    "score": st.column_config.ProgressColumn("Score", min_value=0.0, max_value=1.0, format="%.2f"),
    "vendor_guess": st.column_config.TextColumn("Vendor"),
    "cwe_name": st.column_config.TextColumn("Weakness type", width="medium"),
    "cvss3_score": st.column_config.NumberColumn("CVSS", format="%.1f", width="small"),
    "epss": st.column_config.NumberColumn("EPSS", format="%.2f", width="small"),
    **{label: st.column_config.TextColumn(label, width="small") for label in FLAGS.values()},
}


# ---------------------------------------------------------------- sidebar

st.sidebar.markdown("**FixNext**  \nBefore the Breach")
page = st.sidebar.radio("Page", PAGES, key="page")


def sidebar_filters(df):
    """Global filters for Overview and the list. An empty box means 'all'."""
    st.sidebar.markdown("**Filters**")
    sev_values = [s for s in SEVERITY_ORDER if s in set(df["cvss3_severity"].dropna())]
    sev_values += sorted(set(df["cvss3_severity"].dropna()) - set(sev_values))
    vendors = st.sidebar.multiselect("Vendor", sorted(df["vendor_guess"].unique()), key="f_vendor", placeholder="All vendors")
    cwes = st.sidebar.multiselect("Weakness type", sorted(df["cwe_name"].unique()), key="f_cwe", placeholder="All weakness types")
    months = st.sidebar.multiselect("Snapshot month", sorted(df["snapshot_month"].dropna().unique()), key="f_month", placeholder="All months")
    sevs = st.sidebar.multiselect("Severity", sev_values, key="f_sev", placeholder="All severities")
    only_exploit = st.sidebar.checkbox("Only CVEs with public exploit code", key="f_exploit")
    query = st.sidebar.text_input("Search", key="f_query", placeholder="CVE id or words in the description")

    mask = pd.Series(True, index=df.index)
    if vendors:
        mask &= df["vendor_guess"].isin(vendors)
    if cwes:
        mask &= df["cwe_name"].isin(cwes)
    if months:
        mask &= df["snapshot_month"].isin(months)
    if sevs:
        mask &= df["cvss3_severity"].isin(sevs)
    if only_exploit:
        mask &= df["has_exploit"]
    q = (query or "").strip()
    if q:
        mask &= df["cve_id"].str.contains(q, case=False, regex=False, na=False) | df["description"].str.contains(
            q, case=False, regex=False, na=False
        )
    return df[mask]


filtered = sidebar_filters(ranked) if page in ("Overview", "Fix-Next List") else ranked
st.sidebar.caption("Theme: open the ⋮ menu (top right) and pick System, Light or Dark.")


# ---------------------------------------------------------------- pages

top_bar()

if page == "Overview":
    ticker(filtered)
    hero(len(ranked))

    if filtered.empty:
        empty_state("No CVEs match these filters", "Clear a filter in the sidebar to see results.")
    else:
        top500 = filtered[filtered["rank"] <= 500]
        cutoff = ranked.head(500)["score"].iloc[-1]
        first = filtered.iloc[0]

        # Four KPI tiles in one row: same height, numbers aligned at the bottom.
        a, b, c, d = st.columns(4, gap="small")
        a.metric("CVEs scored", f"{len(filtered):,}")
        b.metric("Score cut-off for rank 500", f"{cutoff:.3f}", help="Score of the CVE ranked 500th in the full ranking.")
        pct = f"{top500['has_exploit'].mean():.0%}" if len(top500) else NO
        c.metric("Top 500 with public exploit code", pct)
        d.metric("Distinct vendors in top 500", f"{top500['vendor_guess'].nunique():,}")

        eyebrow = "RANK #1 · FIX THIS NEXT" if int(first["rank"]) == 1 else f"RANK #{int(first['rank'])} · TOP OF YOUR FILTERS"
        cve_card(first, eyebrow)
        st.button("Open in CVE Detail →", on_click=open_detail, args=(first["cve_id"],))

        col1, col2 = st.columns(2, gap="medium")
        with col1:
            with st.container(key="ffcard_backtest"):
                positives = int(backtest["positives_available"].max())
                chart_heading("Exploited CVEs found in top 500", f"2025 hold-out, {positives} positives available")
                # Our row is highlighted. The team renamed FixFirst to FixNext; older CSVs still say
                # "FixFirst model", so match both and always show the new name.
                ours_pattern = r"fix\s*-?\s*(?:first|next)"
                is_ours = backtest["method"].str.contains(ours_pattern, case=False, regex=True, na=False)
                methods = [("FixNext model" if ours else m) for m, ours in zip(backtest["method"], is_ours)]
                bar_chart(
                    methods,
                    backtest["hits_at_500"].tolist(),
                    [BLUE if ours else GRAY for ours in is_ours],
                    [f"{m}: {h} of {positives} exploited CVEs in its top 500" for m, h in zip(methods, backtest["hits_at_500"])],
                    bargap=0.45,
                )
        with col2:
            with st.container(key="ffcard_vendors"):
                chart_heading("Top vendors in the top 500", "Top 10 by number of CVEs")
                if top500.empty:
                    st.caption("None of the filtered CVEs are in the top 500.")
                else:
                    counts = top500["vendor_guess"].value_counts().head(10)
                    bar_chart(counts.index.tolist(), counts.tolist(), TEAL,
                              [f"{v}: {n} CVEs in the top 500" for v, n in counts.items()])
        # Full width: weakness names are long, a third of the page cuts them off.
        with st.container(key="ffcard_cwe"):
            chart_heading("Top weakness types in the top 500", "Top 10, names shortened to 40 characters")
            if top500.empty:
                st.caption("None of the filtered CVEs are in the top 500.")
            else:
                counts = top500.groupby(["cwe_name", "cwe_primary"], dropna=False).size().sort_values(ascending=False).head(10)
                labels = [cwe_label(name, cid) for name, cid in counts.index]
                hovers = [f"{name}: {n} CVEs in the top 500" for (name, _), n in counts.items()]
                bar_chart(labels, counts.tolist(), PURPLE, hovers)

        with st.container(key="ffcard_top5"):
            chart_heading("Top of the fix-next list", "The 5 highest-ranked CVEs that match your filters")
            st.dataframe(table_view(filtered.head(5)), hide_index=True, width="stretch", column_config=TABLE_COLUMNS)
            st.button("Open the full list →", on_click=open_page, args=("Fix-Next List",))

elif page == "Fix-Next List":
    st.title("Fix-Next List")
    ticker(filtered)
    top_n = st.slider("Show top N", min_value=50, max_value=500, value=100, step=10)
    if filtered.empty:
        empty_state("No CVEs match these filters", "Clear a filter in the sidebar to see results.")
    else:
        shown = filtered.head(top_n)
        st.caption(f"{len(filtered):,} CVEs match your filters. Showing the top {len(shown):,}.")
        st.dataframe(table_view(shown), hide_index=True, width="stretch", height=560, column_config=TABLE_COLUMNS)

    # The submission file: always the first 500 of the FULL ranking, one column, filters ignored.
    submission = ranked.head(500)[["cve_id"]].to_csv(index=False)
    st.download_button("Download top500.csv", data=submission, file_name="top500.csv", mime="text/csv")
    st.caption("Our submission format: the first 500 CVEs of the full ranking, one column (cve_id). Filters don't change it.")

elif page == "CVE Detail":
    st.title("CVE Detail")
    options = ranked["cve_id"].tolist()
    if st.session_state.get("detail_cve") not in options:
        st.session_state["detail_cve"] = options[0]
    cve = st.selectbox("CVE", options, key="detail_cve", help="Type to search. Ordered by rank.")
    row = ranked.loc[ranked["cve_id"] == cve].iloc[0]

    cve_card(row, f"RANK #{int(row['rank'])} · SCORE {fmt(row['score'])}", with_signals=False)

    rationale = str(row["rationale"]).strip()
    body = esc(rationale) if rationale else '<span class="ff-pending">Granite rationale pending for this CVE</span>'
    st.html(f'<div class="ff-box"><h2>Why fix this next</h2><p>{body}</p></div>')

    sev = "" if is_blank(row["cvss3_severity"]) else f" {row['cvss3_severity']}"
    tiles = [
        ("EPSS", fmt(row["epss"])),
        ("CVSS", fmt(row["cvss3_score"], "{:.1f}") + (sev if not is_blank(row["cvss3_score"]) else "")),
        ("Attack vector", NO if is_blank(row["attack_vector"]) else str(row["attack_vector"]).replace("_", " ")),
    ] + [(label, YES if row[col] == 1 else NO) for col, label in FLAGS.items()]
    st.html(
        '<h2 class="ff-h2" style="margin:8px 0 10px">Signals</h2><div class="ff-tiles">'
        + "".join(f'<div class="ff-tile"><span>{esc(k)}</span><b>{esc(v)}</b></div>' for k, v in tiles)
        + "</div>"
    )

    st.subheader("Description")
    st.write(row["description"] or "No description.")
    st.markdown(f"[View {cve} on the NVD website ↗](https://nvd.nist.gov/vuln/detail/{cve})")

else:
    st.title("Methodology")
    st.markdown(
        """
FixNext ranks 2026's vulnerabilities by how likely attackers are to use them.
Everything it looks at was already known when the CVE was published or at the end of its snapshot month.

### What the model uses
- **The CVE description**, turned into numbers with IBM Granite embeddings (`granite-embedding-small-english-r2`).
- **The weakness type** (CWE).
- **Who issued the CVE** (the assigner, usually the vendor's security team).
- **The CVSS vector**: the score and its parts, such as the attack vector.
- **Public exploit signals at the snapshot month**: EPSS, Exploit-DB, Metasploit, Nuclei templates and GitHub proof-of-concept code.

The top 50 also get a two-line "why fix this next" written by IBM Granite (`granite-3.3-2b-instruct`).

### What it deliberately does not use
`nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, `references.csv` and `affected_products.csv`.
NIST fills these in after attacks happen, so they leak the answer.

### Keeping it fair — columns used
Allowed (known at publish / end of snapshot month): `description`, `assigner`, `published`, `cwe_ids`, CVSS v3 score and vector components, and the scoreboard's `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github`. Labels come from `known_exploited.csv` (≤ 2025-12-31) for training only.

**Not used for 2026 features:** `nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, `cvss3_source`, `references.csv`, `affected_products.csv` — NIST fills these in after attacks, so they leak the answer. `src/config.py::assert_no_leakage` enforces this.
"""
    )
