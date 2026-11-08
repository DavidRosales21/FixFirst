# app/app.py — FixNext dashboard (Streamlit + Plotly) · fixnext.select
#
# Run from the repo root:   streamlit run app/app.py
#
# Reads only the two CSVs of the data contract. Which ones, first match wins:
#   1. the FIXNEXT_RANKED / FIXNEXT_BACKTEST environment variables (the older FIXFIRST_*
#      names from the task doc still work), e.g. the full ranking for the local demo;
#   2. app/ranked_light.csv and app/backtest.csv, the model's drop-in files, when present;
#   3. app/sample_ranked_2026.csv and app/sample_backtest.csv (placeholder scores).
# Theme (light / dark / system) and fonts live in app/.streamlit/config.toml and app/static/.

import html
import os
import random
import re

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="FixNext — Before the Breach", page_icon="🛡️", layout="wide")

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = HERE  # the CSVs sit next to this file


def first_existing(*names):
    """The first of these files in DATA_DIR that exists (the last one if none do)."""
    paths = [os.path.join(DATA_DIR, n) for n in names]
    return next((p for p in paths if os.path.exists(p)), paths[-1])


RANKED_PATH = (os.environ.get("FIXNEXT_RANKED") or os.environ.get("FIXFIRST_RANKED")
               or first_existing("ranked_light.csv", "sample_ranked_2026.csv"))
BACKTEST_PATH = (os.environ.get("FIXNEXT_BACKTEST") or os.environ.get("FIXFIRST_BACKTEST")
                 or first_existing("backtest.csv", "sample_backtest.csv"))
USING_SAMPLE = os.path.basename(RANKED_PATH).startswith("sample_")

PAGES = ["Overview", "Fix-Next List", "CVE Detail", "Methodology"]
FLAGS = {"exploitdb": "Exploit-DB", "metasploit": "Metasploit", "nuclei": "Nuclei", "poc_github": "GitHub PoC"}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FILTER_KEYS = ["f_vendor", "f_cwe", "f_month", "f_sev", "f_exploit", "f_query"]

# Chart colors: IBM Carbon steps checked for contrast on both the light and the dark surface.
BLUE, TEAL, PURPLE, GRAY = "#4589FF", "#009D9A", "#A56EFF", "#8D8D8D"
YES, NO = "✓", "–"

# Colors that carry meaning, used the same way on every page (and explained in a legend):
#   CVSS severity -> red / orange / yellow / green, EPSS -> purple (stronger = likelier),
#   public exploit code -> magenta. Tints are see-through so they read on light and dark.
SEV_COLOR = {"CRITICAL": "#FA4D56", "HIGH": "#FF832B", "MEDIUM": "#F1C21B", "LOW": "#42BE65"}
SEV_MD = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "yellow", "LOW": "green"}
EPSS_RGB, EXPLOIT_RGB = (165, 110, 255), (238, 83, 150)


def rgba(color, alpha):
    if isinstance(color, str):
        color = tuple(int(color[i : i + 2], 16) for i in (1, 3, 5))
    return f"rgba({color[0]},{color[1]},{color[2]},{alpha:.2f})"


def epss_alpha(value):
    return 0.10 + 0.55 * min(max(float(value), 0.0), 1.0)


# ---------------------------------------------------------------- data

def neighbours_text(df):
    """'CVE-a (0.92); CVE-b (0.91)' per row from neighbour_N_cve / neighbour_N_sim columns ('' if none)."""
    pairs = []
    n = 1
    while f"neighbour_{n}_cve" in df:
        sim = pd.to_numeric(df.get(f"neighbour_{n}_sim"), errors="coerce") if f"neighbour_{n}_sim" in df else None
        pairs.append((df[f"neighbour_{n}_cve"], sim))
        n += 1
    if not pairs:
        return ""

    def row_text(i):
        parts = []
        for cves, sims in pairs:
            cve = cves.iat[i]
            if pd.isna(cve) or not str(cve).strip():
                continue
            s = None if sims is None else sims.iat[i]
            parts.append(f"{str(cve).strip()} ({s:.2f})" if s is not None and not pd.isna(s) else str(cve).strip())
        return "; ".join(parts)

    return [row_text(i) for i in range(len(df))]


@st.cache_data
def load_ranked(path):
    df = pd.read_csv(path, dtype={"cve_id": str, "rationale": str, "top_reasons": str, "description": str})
    for col in ["rationale", "top_reasons", "description", "assigner"]:
        df[col] = df[col].fillna("")
    # Optional (Granite neighbours): a similar_cves text column, "CVE-2024-1234 (0.93); CVE-2025-…",
    # or the engine's wide columns neighbour_1_cve / neighbour_1_sim … (similar_exploited.csv).
    if "similar_cves" in df:
        df["similar_cves"] = df["similar_cves"].fillna("").astype(str)
    else:
        df["similar_cves"] = neighbours_text(df)
    df["vendor_guess"] = df["vendor_guess"].fillna("other")
    df["cwe_name"] = df["cwe_name"].fillna("Unknown")
    for col in ["rank", "score", "cvss3_score", "epss", "epss_rank", "flags_rank", "cvss_rank", "assigner_lift", "cwe_lift"]:
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in FLAGS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
    df["has_exploit"] = df[list(FLAGS)].max(axis=1) == 1
    return df.sort_values("rank").reset_index(drop=True)


@st.cache_data
def load_backtest(path):
    return pd.read_csv(path)


@st.cache_data
def load_catches(path):
    """The exploited CVEs of the 2025 hold-out that FixNext put in its top 500 (optional file)."""
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path, dtype={"cve_id": str})
    for col in ["rank_fixnext", "rank_epss", "rank_flags_epss", "lag_days", "cvss3_score", "epss"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


@st.cache_data
def load_profile(path):
    """How the top 500 differs from all 72,670 (optional file)."""
    if not os.path.exists(path):
        return None
    import json
    with open(path) as f:
        return json.load(f)


ranked = load_ranked(RANKED_PATH)
backtest = load_backtest(BACKTEST_PATH)
catches = load_catches(os.path.join(HERE, "catches.csv"))
profile = load_profile(os.path.join(HERE, "profile.json"))
CHART_DIR = os.path.join(HERE, "..", "outputs", "charts")


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


def cwe_label(name, cwe_id, limit=40):
    """Readable, unique label: the common name in brackets if there is one, plus the CWE id."""
    name = str(name)
    if "('" in name and name.endswith("')"):
        name = name[name.index("('") + 2 : -2]
    name = short(name, limit)
    real_id = not is_blank(cwe_id) and str(cwe_id).upper().startswith("CWE-")
    return f"{name} · {cwe_id}" if real_id else name


def reason_kind(text):
    """Which color a reason pill gets: EPSS, exploit code, exposure or vendor."""
    t = text.lower()
    if t.startswith("epss"):
        return "epss"
    if any(w in t for w in ("poc", "nuclei", "metasploit", "exploit")):
        return "exploit"
    if "vendor" in t:
        return "vendor"
    return "net"


def reasons(row):
    return [r.strip() for r in str(row["top_reasons"]).split(";") if r.strip()]


def similar_cves(row):
    """[(cve_id, similarity)] from 'CVE-2024-1234 (0.93); CVE-2025-…'. Empty or missing -> []."""
    out = []
    for part in str(row.get("similar_cves", "") or "").split(";"):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"(CVE-\d{4}-\d+)\s*(?:\(\s*([^)]*?)\s*\))?", part, re.I)
        out.append((m.group(1).upper(), m.group(2) or "") if m else (part, ""))
    return out


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
        return '<span class="ff-tag">CVSS –</span>'
    color = SEV_COLOR.get(sev, GRAY)
    return (f'<span class="ff-tag" style="background:{rgba(color, .22)}">'
            f'<i style="background:{color}"></i>CVSS {row["cvss3_score"]:.1f} {esc(sev.title())}</span>')


# ---------------------------------------------------------------- navigation callbacks

def open_detail(cve_id):
    st.session_state["page"] = st.session_state["_last_page"] = "CVE Detail"
    st.session_state["detail_cve"] = cve_id


def open_page(name):
    st.session_state["page"] = st.session_state["_last_page"] = name


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
.ff-pill.epss{background:rgba(165,110,255,.18);color:color-mix(in srgb,#A56EFF 72%,currentColor)}
.ff-pill.exploit{background:rgba(238,83,150,.18);color:color-mix(in srgb,#EE5396 72%,currentColor)}
.ff-pill.vendor{background:rgba(0,157,154,.18);color:color-mix(in srgb,#009D9A 75%,currentColor)}
.ff-similar{margin:12px 0 0;font-size:13px;line-height:2}
.ff-sim{font-family:'IBM Plex Mono',monospace;font-size:12px;padding:3px 8px;margin-right:2px;background:var(--ff-line);white-space:nowrap}
.ff-sim i{font-style:normal;color:var(--ff-muted);margin-left:2px}
.ff-signals{display:flex;flex-wrap:wrap;gap:6px 8px;margin-top:14px;font-size:13px;color:var(--ff-muted);align-items:center}
.ff-tag{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;font-size:12px;color:inherit;background:var(--ff-layer);white-space:nowrap}
.ff-tag i{display:inline-block;width:8px;height:8px;flex:0 0 auto}
.ff-tag.off{background:none;color:var(--ff-muted)}

/* Active filters: a fixed-height box under the header, one chip per filter value. When the chips
   don't fit, the box scrolls and shows a blue scroll bar, so it's clear there is more inside. */
.ff-active{display:flex;flex-direction:column;gap:6px}
.ff-active-head{margin:0;font-size:13px}
.ff-active-head b{font-weight:600}
.ff-active-box{display:flex;flex-wrap:wrap;align-content:flex-start;gap:6px;max-height:88px;overflow-y:auto;overscroll-behavior:contain;
  padding:8px 6px 8px 10px;border:1px solid var(--ff-line);background:var(--ff-layer);font-size:13px;line-height:1.4}
.ff-active-box:focus-visible{outline:2px solid #4589FF;outline-offset:2px}
.ff-active-none{color:var(--ff-muted)}
/* Streamlit makes every scroll bar transparent until hover; this one always shows (blue thumb, gray track). */
.ff-active-box{scrollbar-width:auto !important;scrollbar-color:#4589FF var(--ff-line) !important}
/* Older Safari, which ignores scrollbar-color */
.ff-active-box::-webkit-scrollbar{width:12px}
.ff-active-box::-webkit-scrollbar-track{background:var(--ff-line)}
.ff-active-box::-webkit-scrollbar-thumb{min-height:24px;background:#4589FF;background-clip:padding-box;border:3px solid transparent;border-radius:12px}
.ff-chip{display:inline-flex;align-items:center;gap:6px;max-width:100%;padding:2px 10px;border-radius:12px;
  border:1px solid var(--ff-line);background:var(--ff-layer);color:inherit;overflow-wrap:anywhere}
.ff-chip-k{color:var(--ff-muted);white-space:nowrap}
.ff-chip-dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.ff-legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--ff-muted);margin:0}
.ff-legend span{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.ff-legend i{display:inline-block;width:10px;height:10px}

/* Header: project name · page tabs · theme switch (wraps onto two lines on narrow screens) */
.st-key-ffheader{border-bottom:1px solid var(--ff-line);padding-bottom:4px}
.st-key-ffheader [data-testid="stHorizontalBlock"]{flex-wrap:wrap;row-gap:4px;align-items:center}
.st-key-ffheader [data-testid="stColumn"]{width:auto !important;min-width:0 !important}
.st-key-ffheader [data-testid="stColumn"]{flex:0 0 auto !important}
.st-key-ffheader [data-testid="stColumn"]:nth-child(2){flex:1 1 auto !important;min-width:max-content !important}
.st-key-ffheader [data-testid="stColumn"]:nth-child(3){margin-left:auto}
.st-key-fftools{flex-wrap:nowrap !important;width:auto !important}
.st-key-fftools > div{width:auto !important;flex:0 0 auto !important}

/* Filters: an obvious button in the header, opening a wide pop-up panel with an X */
.st-key-fffilters button{min-height:40px;padding:0 16px !important;font-weight:600;border:1px solid #4589FF !important;border-radius:0 !important}
.st-key-fffilters button [data-testid="stIconMaterial"]{font-size:22px}
[data-testid="stPopoverBody"]{width:min(720px,calc(100vw - 32px)) !important;max-width:calc(100vw - 32px) !important;border-radius:0 !important}
.ff-pop-head{display:flex;align-items:center;justify-content:space-between;gap:12px;font-size:16px;
  border-bottom:1px solid var(--ff-line);padding-bottom:8px;margin-bottom:4px}
.ff-x{display:grid;place-items:center;width:40px;height:40px;padding:0;background:transparent;border:0;color:inherit;cursor:pointer}
.ff-x:focus-visible{outline:2px solid #4589FF;outline-offset:-2px}
@media (hover:hover){.ff-x:hover{background:var(--ff-layer)}}
.ff-brand{display:flex;flex-direction:column;line-height:1.25;padding-right:12px}
.ff-brand b{font-size:20px;font-weight:600;letter-spacing:.2px}
.ff-brand span{font-size:12px;color:var(--ff-muted);white-space:nowrap}
.st-key-page [data-testid="stButtonGroup"]{gap:0;flex-wrap:wrap}
.st-key-page button{background:transparent !important;border:0 !important;border-radius:0 !important;min-height:44px;
  padding:0 12px !important;color:var(--ff-muted) !important;box-shadow:inset 0 -2px 0 transparent !important}
.st-key-page button[aria-checked="true"]{color:inherit !important;font-weight:600;box-shadow:inset 0 -3px 0 #4589FF !important}
.st-key-page button:focus-visible{outline:2px solid #4589FF;outline-offset:-2px}
@media (hover:hover){.st-key-page button:hover{background:var(--ff-layer) !important;color:inherit !important}}

.ff-ico{font-family:'Material Symbols Rounded';font-size:20px;line-height:1;font-weight:normal;font-style:normal;
  letter-spacing:normal;text-transform:none;white-space:nowrap;font-feature-settings:'liga';-webkit-font-smoothing:antialiased}
.ff-theme{display:inline-flex;border:1px solid var(--ff-line)}
.ff-theme button,.ff-rail button{position:relative;display:grid;place-items:center;width:40px;height:40px;padding:0;margin:0;
  background:transparent;border:0;border-radius:0;color:var(--ff-muted);cursor:pointer;font:inherit}
.ff-theme button[aria-pressed="true"],.ff-rail button[aria-pressed="true"]{background:color-mix(in srgb,currentColor 14%,transparent);color:inherit}
.ff-theme button:focus-visible,.ff-rail button:focus-visible{outline:2px solid #4589FF;outline-offset:-2px}
@media (hover:hover){.ff-theme button:hover,.ff-rail button:hover{background:var(--ff-layer);color:inherit}}
.ff-theme button[aria-pressed="true"]{color:var(--ff-accent)}

/* Mini side menu of tools, fixed on the right edge */
.ff-rail{position:fixed;right:10px;top:50%;transform:translateY(-50%);z-index:999990;display:flex;flex-direction:column;gap:2px;
  padding:4px;background:var(--ff-bg,Canvas);border:1px solid var(--ff-line);box-shadow:0 2px 10px rgba(0,0,0,.18)}
.ff-rail button[hidden]{display:none}
.ff-rail button[aria-pressed="true"]{color:var(--ff-accent)}
/* Phones: the four tabs need ~380px in one row, wider than the screen, so they become a 2 x 2 grid
   (otherwise the whole page scrolls sideways and Methodology is cut off); legend lines may wrap too */
@media (max-width:520px){
  .st-key-ffheader [data-testid="stColumn"]:nth-child(2){flex:1 1 100% !important;min-width:0 !important}
  .st-key-page,.st-key-page [data-testid="stButtonGroup"]{width:100% !important}
  .st-key-page [role="radiogroup"]{display:grid !important;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 !important;overflow:visible !important}
  .st-key-page button{width:100% !important;min-width:0 !important;justify-content:center}
  .ff-legend span{white-space:normal}
}
.ff-theme button[data-tip]::after,.ff-rail button[data-tip]::after{content:attr(data-tip);position:absolute;white-space:nowrap;
  font-size:12px;padding:4px 8px;background:#393939;color:#F4F4F4;pointer-events:none;opacity:0;transition:opacity 120ms;z-index:2}
.ff-rail button[data-tip]::after{right:calc(100% + 8px);top:50%;transform:translateY(-50%)}
.ff-theme button[data-tip]::after{top:calc(100% + 6px);left:50%;transform:translateX(-50%)}
.ff-theme button:focus-visible::after,.ff-rail button:focus-visible::after{opacity:1}
/* Guide strip: what each page is for (Overview only) */
.ff-guide{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));gap:10px;margin:14px 0 0}
.ff-guide-item{padding:12px 14px;background:var(--ff-layer);border-left:3px solid var(--ff-line)}
.ff-guide-item.on{border-left-color:#4589FF}
.ff-guide-item b{display:block;font-size:13px;font-weight:600;margin-bottom:3px}
.ff-guide-item span{display:block;font-size:12px;line-height:1.45;color:var(--ff-muted)}
/* Three facts about the top 500 */
.ff-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,250px),1fr));gap:12px;margin:12px 0 4px}
.ff-fact{background:var(--ff-layer);padding:16px 18px;border-top:3px solid #A56EFF}
.ff-fact b{display:block;font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:500;line-height:1.1}
.ff-fact span{display:block;margin-top:6px;font-size:13px;line-height:1.45;color:var(--ff-muted)}
.ff-fact em{font-style:normal;color:inherit}
/* Caught-vs-missed cards */
.ff-catches{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));gap:12px;margin-top:10px}
.ff-catch{background:var(--ff-layer);padding:16px;border-left:3px solid #4589FF}
.ff-catch .ff-cve2{font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ff-muted)}
.ff-catch h4{margin:4px 0 10px;font-size:14px;font-weight:600;line-height:1.3}
.ff-catch .ff-ranks{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12px;color:var(--ff-muted)}
.ff-catch .ff-ranks b{display:block;font-family:'IBM Plex Mono',monospace;font-size:18px;font-weight:500;color:inherit}
.ff-catch .ff-ranks .me b{color:var(--ff-accent)}
.ff-catch p{margin:10px 0 0;font-size:12px;color:var(--ff-muted);line-height:1.4}
/* CVE Detail: where the standard scores put it, and how the model reads it */
.ff-vs{display:flex;flex-wrap:wrap;gap:10px;margin:6px 0 14px}
.ff-vs div{flex:1 1 150px;padding:10px 14px;background:var(--ff-layer);font-size:12px;color:var(--ff-muted)}
.ff-vs div b{display:block;font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:500;color:inherit;margin-top:2px}
.ff-vs div.me{border-top:3px solid #4589FF}
.ff-vs div.me b{color:var(--ff-accent)}
.ff-how{margin:8px 0 0;padding:0;list-style:none;display:grid;gap:8px}
.ff-how li{display:grid;grid-template-columns:auto 1fr;gap:12px;align-items:start;padding:10px 14px;background:var(--ff-layer);font-size:14px;line-height:1.45}
.ff-how li i{font-style:normal;font-family:'IBM Plex Mono',monospace;font-size:11px;padding:3px 8px;background:var(--ff-line);white-space:nowrap;margin-top:1px}
.ff-pagenote{margin:-6px 0 10px;font-size:13px;color:var(--ff-muted)}
@media (hover:hover){.ff-theme button:hover::after,.ff-rail button:hover::after{opacity:1}}
.stMainBlockContainer{padding-right:72px}
@media (max-width:640px){.stMainBlockContainer{padding-right:60px}}

/* Streamlit's own menu stays (the rail and the theme buttons use it) but out of sight */
[data-testid="stMainMenu"]{visibility:hidden}
[data-testid="stAppDeployButton"]{display:none}
html.ff-driving [data-testid="stMainMenuPopover"]{opacity:0 !important;pointer-events:none !important}

.ff-footer{display:flex;flex-wrap:wrap;gap:6px 20px;justify-content:space-between;margin-top:32px;padding:16px 0 4px;
  border-top:1px solid var(--ff-line);font-size:12px;color:var(--ff-muted)}
.ff-footer b{font-weight:600}

/* Rows that wrap instead of squeezing: KPI tiles (min 200px) and chart cards (min 360px) */
.st-key-ffkpis [data-testid="stHorizontalBlock"],.st-key-ffrow [data-testid="stHorizontalBlock"]{flex-wrap:wrap;row-gap:1rem}
.st-key-ffkpis [data-testid="stColumn"]{flex:1 1 200px !important;min-width:min(100%,200px) !important;width:auto !important}
.st-key-ffrow [data-testid="stColumn"]{flex:1 1 360px !important;min-width:min(100%,360px) !important;width:auto !important}

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
[data-testid="stMetricLabel"] *,[data-testid="stMetricValue"] *{white-space:normal !important;overflow:visible !important;text-overflow:clip !important}
[data-testid="stMetric"]{box-shadow:inset 0 3px 0 #4589FF}
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

def icon(name):
    """A Material Symbols icon. The font ships with Streamlit (no network); st.html strips <svg>."""
    return f'<span class="ff-ico" aria-hidden="true">{name}</span>'


ICONS = {
    "Light": icon("light_mode"),
    "Dark": icon("dark_mode"),
    "System": icon("contrast"),
    "rerun": icon("refresh"),
    "autoRerun": icon("autorenew"),
    "clearCache": icon("delete_sweep"),
    "print": icon("print"),
    "recordScreencast": icon("radio_button_checked"),
}
THEME_BUTTONS = [("Light", "Light theme"), ("Dark", "Dark theme"), ("System", "Use the system theme")]
RAIL_BUTTONS = [("rerun", "Rerun"), ("autoRerun", "Auto rerun"), ("clearCache", "Clear cache"),
                ("print", "Print"), ("recordScreencast", "Record screen")]

# The header theme buttons and the side rail drive Streamlit's own main menu (hidden), so the
# native theme, rerun, cache, print and screen-recording features keep working exactly as before.
UI_SCRIPT = """
<script>
(function () {
  if (window.__ffUi) { window.__ffUi.sync(); return; }
  var doc = document, state = { auto: false, items: {}, probed: false };
  function q(s) { return doc.querySelector(s); }
  function qa(s) { return Array.prototype.slice.call(doc.querySelectorAll(s)); }
  function themeNow() {
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (k.indexOf('stActiveTheme-') === 0) return JSON.parse(localStorage.getItem(k));
      }
    } catch (e) {}
    return 'System';
  }
  function sync() {
    var t = themeNow();
    qa('[data-ff-theme]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-ff-theme') === t)); });
    qa('[data-ff-action]').forEach(function (b) {
      var id = b.getAttribute('data-ff-action');
      if (state.probed) b.hidden = !state.items[id];
      if (id === 'autoRerun') b.setAttribute('aria-pressed', String(state.auto));
    });
    var app = q('.stApp');
    if (app) doc.documentElement.style.setProperty('--ff-bg', getComputedStyle(app).backgroundColor);
  }
  function withMenu(fn) {
    var btn = q('[data-testid="stMainMenuButton"]');
    if (!btn) return;
    doc.documentElement.classList.add('ff-driving');
    if (!q('[data-testid="stMainMenuList"]')) btn.click();
    var tries = 0;
    (function wait() {
      if (q('[data-testid="stMainMenuList"]')) {
        try { fn(); } catch (e) {}
        setTimeout(function () {
          if (q('[data-testid="stMainMenuList"]')) btn.click();
          doc.documentElement.classList.remove('ff-driving');
          setTimeout(sync, 150);
        }, 60);
      } else if (tries++ < 40) { setTimeout(wait, 25); }
      else { doc.documentElement.classList.remove('ff-driving'); }
    })();
  }
  doc.addEventListener('click', function (e) {
    var closer = e.target && e.target.closest ? e.target.closest('[data-ff-close]') : null;
    if (closer) {
      // The X of a popup panel: same as clicking its button again (or pressing Escape).
      var open = q('.st-key-fffilters button[aria-expanded="true"], [data-testid="stPopover"] button[aria-expanded="true"]');
      if (open) open.click();
      else doc.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      return;
    }
    var t = e.target && e.target.closest ? e.target.closest('[data-ff-theme],[data-ff-action]') : null;
    if (!t) return;
    var theme = t.getAttribute('data-ff-theme'), action = t.getAttribute('data-ff-action');
    withMenu(function () {
      var item = q('[data-testid="stMainMenuItem-' + (theme ? 'theme-' + theme : action) + '"]');
      if (item) item.click();
      if (action === 'autoRerun') state.auto = !state.auto;
    });
  });
  window.__ffUi = { sync: sync };
  var queued = false;
  new MutationObserver(function () {
    if (queued) return; queued = true;
    setTimeout(function () { queued = false; sync(); }, 150);
  }).observe(doc.body, { childList: true, subtree: true });
  setTimeout(function () {
    withMenu(function () {
      ['rerun', 'autoRerun', 'clearCache', 'print', 'recordScreencast'].forEach(function (id) {
        state.items[id] = !!q('[data-testid="stMainMenuItem-' + id + '"]');
      });
      var a = q('[data-testid="stMainMenuItem-autoRerun"]');
      state.auto = !!a && (a.getAttribute('aria-checked') === 'true' || !!a.querySelector('input:checked'));
      state.probed = true;
    });
  }, 500);
  sync();
})();
</script>
"""


def remember_page():
    """The page tabs always keep one page selected (clicking the active tab doesn't clear it)."""
    if st.session_state.get("page") is None:
        st.session_state["page"] = st.session_state.get("_last_page", PAGES[0])
    st.session_state["_last_page"] = st.session_state["page"]


def header():
    """Project name, page tabs, a slot for the Filters button, the theme switch and the side rail
    of tools. Returns the open page and the slot where the Filters button goes."""
    st.markdown(CSS, unsafe_allow_html=True)
    st.session_state.setdefault("page", PAGES[0])
    tag = "Sample data, placeholder scores" if USING_SAMPLE else "Before the Breach"
    theme = "".join(
        f'<button type="button" data-ff-theme="{name}" aria-label="{label}" data-tip="{name}">{ICONS[name]}</button>'
        for name, label in THEME_BUTTONS
    )
    rail = "".join(
        f'<button type="button" data-ff-action="{action}" aria-label="{label}" data-tip="{label}">{ICONS[action]}</button>'
        for action, label in RAIL_BUTTONS
    )
    with st.container(key="ffheader"):
        brand, nav, tools = st.columns([1, 3, 1], vertical_alignment="center", gap="small")
        brand.html(f'<div class="ff-brand"><b>FixNext</b><span>{esc(tag)}</span></div>')
        nav.segmented_control("Page", PAGES, key="page", label_visibility="collapsed", on_change=remember_page)
        # Filters button + theme switch stay together as one group (and wrap together).
        with tools.container(horizontal=True, key="fftools", gap="small", vertical_alignment="center"):
            filters_slot = st.container()
            st.html(
                f'<div class="ff-theme" role="group" aria-label="Theme">{theme}</div>'
                f'<nav class="ff-rail" aria-label="App tools">{rail}</nav>' + UI_SCRIPT,
                unsafe_allow_javascript=True,
            )
    return st.session_state.get("page") or PAGES[0], filters_slot


def footer():
    st.html(
        '<footer class="ff-footer"><span><b>FixNext</b> · fixnext.select</span>'
        '<span>Sheridan Datathon 2026 · IBM track</span>'
        f'<span>Made with Streamlit {esc(st.__version__)}</span></footer>'
    )


def month_label(month):
    try:
        return pd.Timestamp(f"{month}-01").strftime("%b %Y")
    except (ValueError, TypeError):
        return str(month)


def filter_summary(df):
    """Under the Filters button: how many CVEs are shown, then a box with every active filter,
    one chip per value. The box keeps a fixed height and scrolls, with a visible scroll bar,
    when there are more filters than fit."""
    s = st.session_state
    chips = []

    def chip(group, value, dot=None):
        mark = f'<i class="ff-chip-dot" style="background:{dot}"></i>' if dot else ""
        chips.append(f'<span class="ff-chip">{mark}<span class="ff-chip-k">{group}</span>{value}</span>')

    query = (s.get("f_query") or "").strip()
    if query:
        chip("Search", f"“{esc(query)}”")
    for v in s.get("f_sev") or []:
        chip("Severity", esc(str(v).title()), SEV_COLOR.get(str(v).upper(), GRAY))
    if s.get("f_exploit"):
        chip("Exploit code", "public only")
    for v in s.get("f_vendor") or []:
        chip("Vendor", esc(v))
    if s.get("f_cwe"):
        cwe_ids = ranked.drop_duplicates("cwe_name").set_index("cwe_name")["cwe_primary"]
        for n in s["f_cwe"]:
            chip("Weakness", esc(cwe_label(n, cwe_ids.get(n), limit=40)))
    for m in s.get("f_month") or []:
        chip("Month", esc(month_label(m)))

    count = f"{len(chips)} active filter{'s' if len(chips) != 1 else ''}" if chips else "No active filters"
    lead = (f'<span class="ff-muted">Showing</span> <b>{len(df):,}</b> <span class="ff-muted">of {len(ranked):,} CVEs'
            f' · {count}</span>')
    if chips:
        box = (f'<div class="ff-active-box" role="region" aria-label="Active filters" tabindex="0">'
               f'{"".join(chips)}</div>')
    else:
        box = ('<div class="ff-active-box ff-active-none">All CVEs are shown. '
               'Open Filters at the top to narrow the list.</div>')
    st.html(f'<div class="ff-active"><p class="ff-active-head">{lead}</p>{box}</div>')


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


SCORED_TOTAL = 72_670   # every CVE in the 2026 benchmark is ranked; the dashboard loads the top 5,000


def backtest_summary(bt):
    """Our hits vs the best baseline, read from backtest.csv (never hard-coded)."""
    ours_pattern = r"fix\s*-?\s*(?:first|next)"
    is_ours = bt["method"].str.contains(ours_pattern, case=False, regex=True, na=False)
    ours, base = bt[is_ours], bt[~is_ours]
    cols = [c for c in ("hits_at_100", "hits_at_500") if c in bt]
    out = {"positives": int(bt["positives_available"].max())}
    for c in cols:
        out[c] = (int(ours[c].max()) if len(ours) else 0, int(base[c].max()) if len(base) else 0)
    return out


def hero(bt):
    s = backtest_summary(bt)
    ours500, base500 = s.get("hits_at_500", (0, 0))
    ours100, base100 = s.get("hits_at_100", (0, 0))
    note = (
        f"Tested on 2025: {ours500} of the {s['positives']} later-exploited CVEs land in our top 500 — "
        f"the best industry ranking finds {base500}. In the top 100: {ours100} vs {base100}."
    )
    st.html(
        '<section class="ff-hero" aria-label="Scan">'
        '<div><p class="ff-eyebrow">SHERIDAN DATATHON 2026 · IBM TRACK</p>'
        f'<h1>{SCORED_TOTAL:,} CVEs scored.<br><span>500 to fix next.</span></h1>'
        f'<p class="ff-note">{esc(note)}</p></div>'
        f'<div class="ff-field" aria-hidden="true"><div class="ff-grid">{field_cells()}</div>'
        '<span class="ff-scan"></span></div></section>'
    )


PAGE_GUIDE = [
    ("Overview", "The result and the shape of the top 500: how FixNext compares to the standard scores, which exploited CVEs it caught, who and what dominates the list."),
    ("Fix-Next List", "The ranked list. Filter by vendor, weakness type or month, see where EPSS would have put each CVE, and download top500.csv."),
    ("CVE Detail", "One CVE: why it ranks here, the exploited CVEs it resembles, the signals, the Granite rationale, and the link to NVD."),
    ("Methodology", "How the model was tested, what it uses, and what it refuses to use so the result is fair."),
]


def guide_strip(current):
    items = "".join(
        f'<div class="ff-guide-item{" on" if name == current else ""}"><b>{esc(name)}</b><span>{esc(text)}</span></div>'
        for name, text in PAGE_GUIDE
    )
    st.html(f'<div class="ff-guide" aria-label="Where to find what">{items}</div>')


def page_note(current):
    text = dict(PAGE_GUIDE).get(current, "")
    if text:
        st.html(f'<p class="ff-pagenote">{esc(text)}</p>')


def facts_strip(pr):
    """Three facts that say why these 500, from profile.json."""
    if not pr:
        return
    cwes = pr.get("top_cwes_top500", [])[:3]
    def short_cwe(name):
        import re as _re
        m = _re.search(r"\('([^']+)'\)", name)   # "Improper … ('OS Command Injection')" → OS Command Injection
        return m.group(1) if m else short(name, 34)
    others = " and ".join(short_cwe(c["name"]) for c in cwes[1:3])
    facts = [
        (f"{pr['pct_epss_under_1pct_top500']:.0f}%",
         f"of our top 500 have an EPSS under 1% — <em>EPSS-first would never surface them</em>. Across all 72,670 CVEs that share is {pr['pct_epss_under_1pct_all']:.0f}%."),
        (f"{pr['pct_exploit_code_top500']:.0f}%",
         f"of our top 500 already have public exploit code, against <em>{pr['pct_exploit_code_all']:.1f}%</em> of all CVEs."),
        (f"{cwes[0]['pct_top500']:.0f}%" if cwes else "—",
         f"of the top 500 are <em>{short_cwe(cwes[0]['name'])}</em> alone ({cwes[0]['pct_all']:.1f}% of all CVEs), with {others} next — the bug types attackers actually use." if cwes else ""),
    ]
    st.html('<div class="ff-facts">' + "".join(f'<div class="ff-fact"><b>{esc(n)}</b><span>{t}</span></div>' for n, t in facts) + "</div>")


def catches_section(df, missed_by_all=18):
    """The 2025 exploited CVEs the standard scores buried and FixNext caught."""
    if df is None or df.empty:
        return
    only = df[df["bucket"] == "FixNext only"].sort_values("rank_fixnext")
    both = int((df["bucket"] == "both").sum())
    chart_heading("Caught before the breach", "Exploited CVEs of 2025 that FixNext put in its top 500 and the exploit-code-then-EPSS baseline did not")
    cards = []
    for _, r in only.iterrows():
        name = str(r["kev_name"]).replace(" Vulnerability", "")
        ransom = " · used in ransomware" if str(r.get("known_ransomware_use", "")).lower() == "known" else ""
        cards.append(
            f'<div class="ff-catch"><span class="ff-cve2">{esc(r["cve_id"])}</span><h4>{esc(name)}</h4>'
            f'<div class="ff-ranks"><span class="me">FixNext rank<b>#{int(r["rank_fixnext"]):,}</b></span>'
            f'<span>EPSS rank<b>#{int(r["rank_epss"]):,}</b></span>'
            f'<span>Exploit code → EPSS<b>#{int(r["rank_flags_epss"]):,}</b></span></div>'
            f'<p>EPSS {fmt(r["epss"], "{:.3f}")} · CVSS {fmt(r["cvss3_score"], "{:.1f}")} · exploited {int(r["lag_days"])} days after publish{esc(ransom)}</p></div>'
        )
    st.html('<div class="ff-catches">' + "".join(cards) + "</div>")
    st.caption(f"{both} more were caught by both FixNext and the baseline. {missed_by_all} were missed by every ranking — listed in outputs/charts/caught_vs_missed.md.")
    img = os.path.join(CHART_DIR, "6_caught_vs_missed.png")
    if os.path.exists(img):
        with st.expander("All 39 on one chart — FixNext rank vs EPSS rank"):
            st.image(img, width="stretch")


def vs_strip(row):
    """Where the standard scores rank this CVE, next to ours."""
    cells = [("FixNext rank", row["rank"], True), ("EPSS rank", row.get("epss_rank"), False),
             ("Exploit code → EPSS rank", row.get("flags_rank"), False), ("CVSS rank", row.get("cvss_rank"), False)]
    html = "".join(
        f'<div class="{"me" if me else ""}">{esc(k)}<b>{"#" + format(int(v), ",") if not is_blank(v) else NO}</b></div>'
        for k, v, me in cells
    )
    st.html(f'<h2 class="ff-h2" style="margin:14px 0 6px">Where each ranking puts it</h2><p class="ff-sub">Out of {SCORED_TOTAL:,} CVEs · 1 = fix first</p><div class="ff-vs">{html}</div>')


def how_model_sees(row):
    """The model's view in plain sentences, each tagged with the signal behind it."""
    items = []
    lift = row.get("assigner_lift")
    if not is_blank(lift) and row["assigner"]:
        rel = "above" if float(lift) >= 1.2 else ("below" if float(lift) <= 0.8 else "about")
        items.append(("issuer", f"Issued by {row['assigner']} — CVEs from this issuer were exploited at {float(lift):.1f}× the average rate in 2019–2023 ({rel} average)."))
    lift = row.get("cwe_lift")
    if not is_blank(lift):
        rel = "above" if float(lift) >= 1.2 else ("below" if float(lift) <= 0.8 else "about")
        items.append(("weakness", f"{row['cwe_name']} — this weakness type was exploited at {float(lift):.1f}× the average rate in 2019–2023 ({rel} average)."))
    sims = similar_cves(row)
    if sims:
        c, sim = sims[0]
        items.append(("Granite", f"Its description closely resembles {c}, a CVE attackers already used (similarity {sim})."))
    flags = [label for col, label in FLAGS.items() if row[col] == 1]
    if flags:
        items.append(("exploit code", "Public exploit code exists: " + ", ".join(flags) + "."))
    if not is_blank(row["epss"]):
        e = float(row["epss"])
        items.append(("EPSS", f"EPSS {e:.3f} — " + ("high; the industry score agrees." if e >= 0.05 else "low; EPSS alone would not have flagged it.")))
    if not items:
        return
    st.html('<h2 class="ff-h2" style="margin:14px 0 6px">How the model sees it</h2><ul class="ff-how">'
            + "".join(f"<li><i>{esc(tag)}</i><span>{esc(text)}</span></li>" for tag, text in items) + "</ul>")


# ---------------------------------------------------------------- Ask FixNext (Gemini)

GEMINI_MODELS = ["gemini-3.8-flash", "gemini-2.5-flash", "gemini-2.0-flash"]


def gemini_key():
    """The key lives in Streamlit Cloud secrets or an environment variable — never in the repo.
    fixnext.select runs in the browser and has no secrets, so the feature hides itself there."""
    try:
        if "GEMINI_API_KEY" in st.secrets:
            return str(st.secrets["GEMINI_API_KEY"])
    except Exception:
        pass
    return os.environ.get("GEMINI_API_KEY", "")


def project_context():
    """Everything Gemini is allowed to know: our own numbers, nothing else."""
    lines = ["FixNext — Sheridan Datathon 2026, IBM track. A model that ranks the 72,670 CVEs published Jan–Sep 2026 "
             "by how likely attackers are to actually use them (defined as later being added to CISA KEV).",
             f"Dashboard shows the top {len(ranked):,} of the 72,670."]
    s_bt = backtest_summary(backtest)
    lines.append("Back-test (train on 2024, predict Jan–Jun 2025, %d later-exploited CVEs). Hits in top 100 / top 500: " % s_bt["positives"]
                 + "; ".join(f"{m}: {int(a)}/{int(b)}" for m, a, b in zip(backtest["method"], backtest["hits_at_100"], backtest["hits_at_500"])))
    if profile:
        lines.append(f"Top-500 profile: {profile['pct_epss_under_1pct_top500']:.0f}% have EPSS under 1% (vs {profile['pct_epss_under_1pct_all']:.0f}% of all CVEs); "
                     f"{profile['pct_exploit_code_top500']:.0f}% have public exploit code (vs {profile['pct_exploit_code_all']:.1f}%); "
                     f"{profile['pct_critical_top500']:.0f}% are CVSS Critical (vs {profile['pct_critical_all']:.0f}%); median EPSS {profile['median_epss_top500']}. "
                     "Top weakness types: " + "; ".join(f"{c['name']} {c['pct_top500']:.0f}% (vs {c['pct_all']:.1f}% overall)" for c in profile.get("top_cwes_top500", [])))
    top500 = ranked[ranked["rank"] <= 500]
    vend = top500["vendor_guess"].value_counts()
    lines.append("Top-500 vendors (keyword in description): " + ", ".join(f"{k} {v}" for k, v in vend.head(12).items()))
    lines.append("Top 10 ranked CVEs: " + "; ".join(f"#{int(r['rank'])} {r['cve_id']} ({r['vendor_guess']}, {r['cwe_name']}, EPSS {fmt(r['epss'])})" for _, r in ranked.head(10).iterrows()))
    if catches is not None:
        only = catches[catches["bucket"] == "FixNext only"]
        lines.append("2025 exploited CVEs FixNext caught in its top 500 that the exploit-code-then-EPSS baseline missed: "
                     + "; ".join(f"{r['cve_id']} {r['kev_name']} (FixNext rank {int(r['rank_fixnext'])}, EPSS rank {int(r['rank_epss'])}, EPSS {fmt(r['epss'], '{:.3f}')})" for _, r in only.iterrows())
                     + f". {int((catches['bucket'] == 'both').sum())} caught by both; 18 missed by every ranking.")
    lines.append("Model: LightGBM on assigner, CWE, CVSS vector, exploit signals at snapshot month, TF-IDF text, and IBM Granite "
                 "nearest-known-exploited-CVE similarity (granite-embedding-small-english-r2; #4 feature), blended with the exploit-code-then-EPSS "
                 "ranking. Rationales by granite-3.3-2b-instruct. Not used (leakage): nvd_status, n_references, n_affected_cpes, last_modified, "
                 "cvss3_source, references.csv, affected_products.csv, live 2026 KEV. Five discovery findings: 15 issuers = 72% of exploited CVEs; "
                 "98.7% of CRITICAL CVEs never exploited; XSS 15 of 25,755 exploited, WordPress 0 of 13,542; median 28 days publish→KEV "
                 "(Apple 2, Chrome 4, Microsoft 6, Apache 113); words vpn/firewall/gateway/auth bypass/RCE raise odds, XSS/plugin/wordpress near zero.")
    return "\n".join(lines)


def cve_context(row):
    sims = "; ".join(f"{c} (similarity {s})" for c, s in similar_cves(row)) or "none"
    flags = ", ".join(label for col, label in FLAGS.items() if row[col] == 1) or "none"
    return (f"Selected CVE: {row['cve_id']} — FixNext rank {int(row['rank'])} of 72,670, score {fmt(row['score'])}. "
            f"EPSS {fmt(row['epss'], '{:.3f}')} (EPSS-first rank {'#' + format(int(row['epss_rank']), ',') if not is_blank(row.get('epss_rank')) else 'n/a'}); "
            f"exploit-code-then-EPSS rank {'#' + format(int(row['flags_rank']), ',') if not is_blank(row.get('flags_rank')) else 'n/a'}; "
            f"CVSS {fmt(row['cvss3_score'], '{:.1f}')} {row['cvss3_severity'] or ''} (CVSS rank {'#' + format(int(row['cvss_rank']), ',') if not is_blank(row.get('cvss_rank')) else 'n/a'}). "
            f"Vendor keyword: {row['vendor_guess']}. Weakness: {row['cwe_name']} ({row['cwe_primary']}). Issuer: {row['assigner']}. "
            f"Attack vector: {row['attack_vector'] or 'n/a'}. Public exploit code: {flags}. "
            f"Issuer historical exploitation lift: {fmt(row.get('assigner_lift'), '{:.1f}')}×; weakness lift: {fmt(row.get('cwe_lift'), '{:.1f}')}×. "
            f"Looks like these exploited CVEs: {sims}. Granite rationale: {row['rationale'] or 'none'}. "
            f"Description: {row['description']}")


SYSTEM_RULES = (
    "You are 'Ask FixNext', the assistant inside the FixNext dashboard at a datathon. Answer the question using ONLY the "
    "context below — our model's own numbers and findings. Be concrete and short (2–5 sentences, plain words). If the answer "
    "is not in the context, say 'That isn't in FixNext's data' and suggest where in the dashboard to look (Overview, Fix-Next List, "
    "CVE Detail, Methodology). Never claim a CVE is being actively exploited unless the context says it is on KEV. Never invent numbers."
)


def ask_gemini(question, context):
    key = gemini_key()
    if not key:
        return None
    try:
        from google import genai
        from google.genai import types
    except Exception:
        return "The google-genai package isn't installed on this host."
    client = genai.Client(api_key=key)
    last = None
    for model in GEMINI_MODELS:
        try:
            r = client.models.generate_content(
                model=model,
                contents=f"CONTEXT:\n{context}\n\nQUESTION: {question}",
                config=types.GenerateContentConfig(system_instruction=SYSTEM_RULES, temperature=0.2, max_output_tokens=400),
            )
            text = (r.text or "").strip()
            if text:
                return text + f"\n\n*{model}*"
        except Exception as e:  # try the next model name
            last = e
    return f"Gemini didn't answer ({type(last).__name__ if last else 'no response'})."


def ask_panel(key, context_fn, placeholder, examples):
    """A question box backed by Gemini. Hidden (with a short note) when no key is configured."""
    st.html('<h2 class="ff-h2" style="margin:18px 0 2px">Ask FixNext</h2>'
            '<p class="ff-sub">Questions answered by Google Gemini from FixNext\'s own numbers — nothing outside the project.</p>')
    if not gemini_key():
        st.caption("Ask FixNext runs on the hosted app (fixnext.streamlit.app) and locally with GEMINI_API_KEY set; "
                   "the in-browser version at fixnext.select has no API key.")
        return
    cols = st.columns(len(examples))
    for col, ex in zip(cols, examples):
        if col.button(ex, key=f"{key}_ex_{abs(hash(ex)) % 10_000}", width="stretch"):
            st.session_state[f"{key}_q"] = ex
    q = st.text_input("Your question", key=f"{key}_q", placeholder=placeholder, label_visibility="collapsed")
    if q:
        with st.spinner("Asking Gemini…"):
            answer = ask_gemini(q, context_fn())
        if answer:
            st.markdown(answer)


def cve_card(row, eyebrow, with_signals=True, with_similar=False):
    """The gauge card: rank, CVE id, score ring, reasons and (optionally) the signals line
    and the "looks like these exploited CVEs" line (hidden when there are none)."""
    score = 0.0 if is_blank(row["score"]) else float(row["score"])
    meta = " · ".join(x for x in [cwe_label(row["cwe_name"], row["cwe_primary"]), row["assigner"]] if x)
    pills = "".join(f'<span class="ff-pill {reason_kind(r)}">{esc(r)}</span>' for r in reasons(row))
    flags = "".join(
        f'<span class="ff-tag" style="background:{rgba(EXPLOIT_RGB, .22)}"><i style="background:{rgba(EXPLOIT_RGB, 1)}"></i>{label} {YES}</span>'
        if row[col] == 1 else f'<span class="ff-tag off">{label} {NO}</span>'
        for col, label in FLAGS.items()
    )
    signals = f'<div class="ff-signals">{severity_html(row)}{flags}</div>' if with_signals else ""
    sims = similar_cves(row) if with_similar else []
    similar = (
        '<p class="ff-similar"><span class="ff-muted">Looks like these exploited CVEs:</span> '
        + " ".join(f'<span class="ff-sim">{esc(c)}{f" <i>{esc(s)}</i>" if s else ""}</span>' for c, s in sims)
        + "</p>"
    ) if sims else ""
    st.html(
        '<section class="ff-card">'
        '<div class="ff-gauge-wrap"><span class="ff-ring" aria-hidden="true"></span>'
        '<span class="ff-ring two" aria-hidden="true"></span>'
        f'<div class="ff-gauge" style="--p:{score * 100:.1f}" role="img" aria-label="Score {score:.2f} out of 1"></div>'
        f'<div class="ff-gauge-num" aria-hidden="true"><b>{score:.2f}</b><span>model score</span></div></div>'
        f'<div class="ff-card-body"><p class="ff-eyebrow">{esc(eyebrow)}</p>'
        f'<p class="ff-cve">{esc(row["cve_id"])}</p><p class="ff-card-meta">{esc(meta)}</p>'
        f'<div class="ff-pills">{pills}</div>{similar}{signals}</div></section>'
    )


def empty_state(title, body, show_clear=True):
    st.html(f'<div class="ff-empty"><h2>{esc(title)}</h2><p>{esc(body)}</p></div>')
    if show_clear:
        st.button("Clear filters", on_click=clear_filters)


def chart_heading(title, subtitle):
    st.html(f'<h2 class="ff-h2">{esc(title)}</h2><p class="ff-sub">{esc(subtitle)}</p>')


def bar_chart(labels, values, colors, hovers, bold=None, row_px=44):
    """Horizontal bars with each label written above its bar, so long names are never cut
    by the axis, whatever the width of the column."""
    n = len(labels)
    values = [int(v) for v in values]
    fig = go.Figure(
        go.Bar(
            x=values, y=list(range(n)), orientation="h", width=0.4,
            marker=dict(color=colors, cornerradius=4),
            text=[f"{v:,}" for v in values], textposition="outside", cliponaxis=False,
            customdata=hovers, hovertemplate="%{customdata}<extra></extra>",
        )
    )
    for i, label in enumerate(labels):
        text = str(label).replace("<", "&lt;").replace(">", "&gt;")
        if bold and bold[i]:
            text = f"<b>{text}</b>"
        fig.add_annotation(x=0, y=i, xref="x", yref="y", text=text, showarrow=False,
                           xanchor="left", yanchor="bottom", yshift=10, font=dict(size=12))
    fig.update_layout(
        height=n * row_px + 20, margin=dict(l=0, r=8, t=20, b=0), showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="IBM Plex Sans, Helvetica Neue, Arial, sans-serif", size=13),
    )
    fig.update_xaxes(visible=False, range=[0, (max(values) if values else 1) * 1.15])
    fig.update_yaxes(visible=False, autorange="reversed")
    st.plotly_chart(fig, theme="streamlit", width="stretch", config={"displayModeBar": False})


def grouped_bar_chart(methods, bt, is_ours, positives, row_px=78):
    """Two thin bars per ranking — hits in its top 100 and in its top 500 — with the method name
    written above the pair. Ours is blue, the baselines grey; the top-100 bar is the lighter shade."""
    n = len(methods)
    series = [("top 100", "hits_at_100", 0.55), ("top 500", "hits_at_500", 1.0)]
    series = [s for s in series if s[1] in bt]
    k = len(series)
    fig = go.Figure()
    for j, (name, col, alpha) in enumerate(series):
        vals = [int(v) for v in bt[col].tolist()]
        offs = (j - (k - 1) / 2) * 0.34
        fig.add_trace(go.Bar(
            name=name, x=vals, y=[i + offs for i in range(n)], orientation="h", width=0.3,
            marker=dict(color=[rgba(BLUE, alpha) if o else rgba(GRAY, alpha) for o in is_ours], cornerradius=4),
            text=[f"{v}" for v in vals], textposition="outside", cliponaxis=False,
            customdata=[f"{m}: {v} of {positives} later-exploited CVEs in its {name}" for m, v in zip(methods, vals)],
            hovertemplate="%{customdata}<extra></extra>",
        ))
    for i, label in enumerate(methods):
        text = str(label).replace("<", "&lt;").replace(">", "&gt;")
        if is_ours[i]:
            text = f"<b>{text}</b>"
        fig.add_annotation(x=0, y=i - 0.5, xref="x", yref="y", text=text, showarrow=False,
                           xanchor="left", yanchor="middle", yshift=-4, font=dict(size=12))
    xmax = max(int(bt[c].max()) for _, c, _ in series) if series else 1
    fig.update_layout(
        height=n * row_px + 56, margin=dict(l=0, r=8, t=4, b=36), barmode="overlay",
        legend=dict(orientation="h", x=0, y=-0.16, yanchor="top", font=dict(size=12), title=None),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="IBM Plex Sans, Helvetica Neue, Arial, sans-serif", size=13),
    )
    fig.update_xaxes(visible=False, range=[0, xmax * 1.15])
    fig.update_yaxes(visible=False, range=[n - 0.5, -0.8])
    st.plotly_chart(fig, theme="streamlit", width="stretch", config={"displayModeBar": False})


def table_view(df):
    cols = ["rank", "cve_id", "score", "vendor_guess", "cwe_name", "cvss3_score", "epss"] + (["epss_rank"] if "epss_rank" in df else [])
    out = df[cols].copy()
    # Short weakness names ("OS Command Injection · CWE-78"): the full name is on CVE Detail.
    out["cwe_name"] = [cwe_label(n, c, limit=24) for n, c in zip(df["cwe_name"], df["cwe_primary"])]
    for col, label in FLAGS.items():
        out[label] = df[col].eq(1).map({True: YES, False: NO})
    return out


def styled_table(df):
    """The table with meaning in color: CVSS by severity, EPSS by strength, exploit code in magenta."""
    view = table_view(df)
    severity = df["cvss3_severity"].fillna("").astype(str).str.upper()

    def cvss_css(col):
        return [f"background-color: {rgba(SEV_COLOR[s], .26)}" if s in SEV_COLOR else "" for s in severity.loc[col.index]]

    def epss_css(col):
        return ["" if pd.isna(v) else f"background-color: {rgba(EPSS_RGB, epss_alpha(v))}" for v in col]

    def flag_css(col):
        return [f"background-color: {rgba(EXPLOIT_RGB, .26)}" if v == YES else "" for v in col]

    return (
        view.style
        .format({"rank": "{:,.0f}", "score": "{:.2f}", "cvss3_score": "{:.1f}", "epss": "{:.2f}", "epss_rank": "#{:,.0f}"}, na_rep=NO)
        .apply(cvss_css, subset=["cvss3_score"])
        .apply(epss_css, subset=["epss"])
        .apply(flag_css, subset=list(FLAGS.values()))
    )


def color_legend():
    sev = "".join(f'<span><i style="background:{c}"></i>{s.title()}</span>' for s, c in SEV_COLOR.items())
    st.html(
        f'<div class="ff-legend"><span><b>CVSS</b></span>{sev}'
        f'<span><i style="background:{rgba(EPSS_RGB, .65)}"></i>EPSS: darker = likelier to be attacked</span>'
        f'<span><i style="background:{rgba(EXPLOIT_RGB, 1)}"></i>Public exploit code</span>'
        '<span>EDB = Exploit-DB · MSF = Metasploit · PoC = GitHub proof of concept</span></div>'
    )


# Fixed widths so the whole row fits on a laptop screen; the exploit columns use short
# headers (full names in the header tooltip and in the legend under the table).
FLAG_HEADERS = {
    "Exploit-DB": ("EDB", "Exploit-DB: a public exploit is listed"),
    "Metasploit": ("MSF", "Metasploit: a module exists"),
    "Nuclei": ("Nuclei", "Nuclei: a detection template exists"),
    "GitHub PoC": ("PoC", "GitHub: public proof-of-concept code"),
}
TABLE_COLUMNS = {
    "rank": st.column_config.NumberColumn("Rank", format="%d", width=56),
    "cve_id": st.column_config.TextColumn("CVE", width=128),
    "score": st.column_config.ProgressColumn("Score", min_value=0.0, max_value=1.0, format="%.2f", width=112),
    "vendor_guess": st.column_config.TextColumn("Vendor", width=88),
    "cwe_name": st.column_config.TextColumn("Weakness type", width=230),
    "cvss3_score": st.column_config.NumberColumn("CVSS", format="%.1f", width=60, help="CVSS v3 base score, colored by severity"),
    "epss": st.column_config.NumberColumn("EPSS", format="%.2f", width=60, help="Chance of an attack in the next 30 days"),
    "epss_rank": st.column_config.TextColumn("EPSS rank", width=84, help="Where an EPSS-first ranking puts this CVE, out of 72,670 (1 = first)"),
    **{label: st.column_config.TextColumn(short_label, width=60, help=tip) for label, (short_label, tip) in FLAG_HEADERS.items()},
}


# ---------------------------------------------------------------- filters

def filter_panel(df):
    """The Filters button in the header and its pop-up panel (closes with X or a click outside).
    Nothing picked means 'all'. Short lists are one-tap chips; long lists are searchable,
    most common first, with counts."""
    active = sum(1 for k in FILTER_KEYS if st.session_state.get(k))
    label = f"Filters · {active}" if active else "Filters"
    with st.popover(label, icon=":material/filter_alt:", type="primary" if active else "secondary", key="fffilters"):
        st.html(
            '<div class="ff-pop-head"><div><b>Filters</b>'
            '<span class="ff-muted"> · for Overview and Fix-Next List</span></div>'
            f'<button type="button" class="ff-x" data-ff-close aria-label="Close filters">{icon("close")}</button></div>'
        )
        query = st.text_input("Search", key="f_query", placeholder="CVE id or keyword", icon=":material/search:")

        sev_values = [s for s in SEVERITY_ORDER if s in set(df["cvss3_severity"].dropna())]
        sev_values += sorted(set(df["cvss3_severity"].dropna()) - set(sev_values))
        left, right = st.columns(2, gap="medium")
        sevs = left.pills(
            "Severity", sev_values, selection_mode="multi", key="f_sev",
            format_func=lambda s: f":{SEV_MD.get(s, 'gray')}[●] {str(s).title()}",
        )
        right.markdown("**Exploit code**")
        only_exploit = right.toggle("Only CVEs with public exploit code", key="f_exploit")

        vendor_counts = df["vendor_guess"].value_counts()
        vendor_options = [v for v in vendor_counts.index if v != "other"] + (["other"] if "other" in vendor_counts else [])
        cwe_counts = df["cwe_name"].value_counts()
        cwe_ids = df.drop_duplicates("cwe_name").set_index("cwe_name")["cwe_primary"]
        left, right = st.columns(2, gap="medium")
        vendors = left.multiselect(
            "Vendor", vendor_options, key="f_vendor", placeholder="All vendors",
            format_func=lambda v: f"{v} ({vendor_counts[v]:,})",
        )
        cwes = right.multiselect(
            "Weakness type", cwe_counts.index.tolist(), key="f_cwe", placeholder="All weakness types",
            format_func=lambda n: f"{cwe_label(n, cwe_ids.get(n), limit=48)} ({cwe_counts[n]:,})",
        )

        month_values = sorted(df["snapshot_month"].dropna().unique())
        months = st.pills(
            "Snapshot month", month_values, selection_mode="multi", key="f_month",
            format_func=lambda m: month_label(m)[:3],
        )

        if active:
            st.button("Reset filters", on_click=clear_filters, icon=":material/restart_alt:")

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


# ---------------------------------------------------------------- pages

page, filters_slot = header()
if page in ("Overview", "Fix-Next List"):
    with filters_slot:
        filtered = filter_panel(ranked)
    filter_summary(filtered)
else:
    filtered = ranked

if page == "Overview":
    ticker(filtered)
    hero(backtest)
    guide_strip("Overview")

    if filtered.empty:
        empty_state("No CVEs match these filters", "Open Filters at the top to change them, or clear them all.")
    else:
        top500 = filtered[filtered["rank"] <= 500]
        cutoff = ranked.head(500)["score"].iloc[-1]
        first = filtered.iloc[0]

        # Four KPI tiles: one row when there's room, 2 × 2 when not; same height, numbers aligned.
        with st.container(key="ffkpis"):
            a, b, c, d = st.columns(4, gap="small")
            a.metric("CVEs scored", f"{SCORED_TOTAL:,}",
                     help=f"Every CVE in the 2026 benchmark is ranked. The dashboard loads the top {len(ranked):,}; "
                          f"{len(filtered):,} match your current filters.")
            b.metric("Score cut-off for rank 500", f"{cutoff:.3f}", help="Score of the CVE ranked 500th in the full ranking.")
            pct = f"{top500['has_exploit'].mean():.0%}" if len(top500) else NO
            c.metric("Top 500 with public exploit code", pct)
            d.metric("Distinct vendors in top 500", f"{top500['vendor_guess'].nunique():,}")
        facts_strip(profile)

        eyebrow = "RANK #1 · FIX THIS NEXT" if int(first["rank"]) == 1 else f"RANK #{int(first['rank'])} · TOP OF YOUR FILTERS"
        cve_card(first, eyebrow)
        st.button("Open in CVE Detail →", on_click=open_detail, args=(first["cve_id"],))

        with st.container(key="ffrow"):
            col1, col2 = st.columns(2, gap="medium")
        with col1:
            with st.container(key="ffcard_backtest"):
                positives = int(backtest["positives_available"].max())
                chart_heading("Exploited CVEs found", f"in each ranking's top 100 and top 500 · 2025 hold-out, {positives} later-exploited CVEs")
                # Our row is highlighted. The team renamed FixFirst to FixNext; older CSVs still say
                # "FixFirst model", so match both and always show the new name.
                ours_pattern = r"fix\s*-?\s*(?:first|next)"
                is_ours = backtest["method"].str.contains(ours_pattern, case=False, regex=True, na=False)
                methods = [("FixNext" if ours else m) for m, ours in zip(backtest["method"], is_ours)]
                grouped_bar_chart(methods, backtest, is_ours.tolist(), positives)
        with col2:
            with st.container(key="ffcard_vendors"):
                chart_heading("Top vendors in the top 500", "Top 10 named vendors by number of CVEs")
                if top500.empty:
                    st.caption("None of the filtered CVEs are in the top 500.")
                else:
                    # "other" (no tracked vendor named in the description) would dwarf every real
                    # vendor, so it is left out of the bars and counted in a footnote instead.
                    all_counts = top500["vendor_guess"].value_counts()
                    n_other = int(all_counts.get("other", 0))
                    counts = all_counts.drop("other", errors="ignore").head(10)
                    if counts.empty:
                        st.caption("None of these CVEs name a tracked vendor.")
                    else:
                        bar_chart(counts.index.tolist(), counts.tolist(), TEAL,
                                  [f"{v}: {n} CVEs in the top 500" for v, n in counts.items()])
                    if n_other:
                        st.caption(f"Not shown: {n_other:,} of these {len(top500):,} CVEs ({n_other / len(top500):.0%}) "
                                   "don't name one of the vendors the model tracks (\"other\").")
        with st.container(key="ffcard_catches"):
            catches_section(catches)

        with st.container(key="ffask_overview"):
            ask_panel("ask_ov", project_context, "e.g. Why does FixNext beat EPSS? Which vendors dominate the top 500?",
                      ["Why does FixNext beat EPSS?", "What did it catch that EPSS missed?", "What does the model refuse to use?"])

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
            st.dataframe(styled_table(filtered.head(5)), hide_index=True, width="stretch", column_config=TABLE_COLUMNS)
            color_legend()
            st.button("Open the full list →", on_click=open_page, args=("Fix-Next List",))

elif page == "Fix-Next List":
    st.title("Fix-Next List")
    page_note("Fix-Next List")
    ticker(filtered)
    top_n = st.slider("Show top N", min_value=50, max_value=500, value=100, step=10)
    if filtered.empty:
        empty_state("No CVEs match these filters", "Open Filters at the top to change them, or clear them all.")
    else:
        shown = filtered.head(top_n)
        st.caption(f"Showing the top {len(shown):,} of {len(filtered):,} matching CVEs.")
        st.dataframe(styled_table(shown), hide_index=True, width="stretch", height=560, column_config=TABLE_COLUMNS)
        color_legend()

    # The submission file: always the first 500 of the FULL ranking, one column, filters ignored.
    submission = ranked.head(500)[["cve_id"]].to_csv(index=False)
    st.download_button("Download top500.csv", data=submission, file_name="top500.csv", mime="text/csv")
    st.caption("Our submission format: the first 500 CVEs of the full ranking, one column (cve_id). Filters don't change it.")

elif page == "CVE Detail":
    st.title("CVE Detail")
    page_note("CVE Detail")
    options = ranked["cve_id"].tolist()
    if st.session_state.get("detail_cve") not in options:
        st.session_state["detail_cve"] = options[0]
    cve = st.selectbox("CVE", options, key="detail_cve", help="Type to search. Ordered by rank.")
    row = ranked.loc[ranked["cve_id"] == cve].iloc[0]

    cve_card(row, f"RANK #{int(row['rank'])} · SCORE {fmt(row['score'])}", with_signals=False, with_similar=True)

    rationale = str(row["rationale"]).strip()
    body = esc(rationale) if rationale else '<span class="ff-pending">Granite rationale pending for this CVE</span>'
    st.html(f'<div class="ff-box"><h2>Why fix this next</h2><p>{body}</p></div>')
    vs_strip(row)
    how_model_sees(row)
    ask_panel("ask_cve", lambda: project_context() + "\n\n" + cve_context(row),
              f"e.g. Why is {row['cve_id']} ranked above its EPSS? What would an attacker gain?",
              ["Why is it ranked above its EPSS?", "What does an attacker gain?", "Which exploited CVEs does it resemble?"])

    severity = "" if is_blank(row["cvss3_severity"]) else str(row["cvss3_severity"]).upper()
    cvss_text = NO if is_blank(row["cvss3_score"]) else f"{row['cvss3_score']:.1f} {severity.title()}".strip()
    # (label, value, tint): the same color meaning as the table and its legend.
    tiles = [
        ("EPSS", fmt(row["epss"]), None if is_blank(row["epss"]) else rgba(EPSS_RGB, epss_alpha(row["epss"]))),
        ("CVSS", cvss_text, rgba(SEV_COLOR[severity], .26) if severity in SEV_COLOR and cvss_text != NO else None),
        ("Attack vector", NO if is_blank(row["attack_vector"]) else str(row["attack_vector"]).replace("_", " ").title(), None),
    ] + [(label, YES if row[col] == 1 else NO, rgba(EXPLOIT_RGB, .26) if row[col] == 1 else None) for col, label in FLAGS.items()]
    st.html(
        '<h2 class="ff-h2" style="margin:8px 0 10px">Signals</h2><div class="ff-tiles">'
        + "".join(
            f'<div class="ff-tile"{f" style={chr(39)}background:{bg}{chr(39)}" if bg else ""}><span>{esc(k)}</span><b>{esc(v)}</b></div>'
            for k, v, bg in tiles
        )
        + "</div>"
    )
    color_legend()

    st.subheader("Description")
    st.write(row["description"] or "No description.")
    st.markdown(f"[View {cve} on the NVD website ↗](https://nvd.nist.gov/vuln/detail/{cve})")

else:
    st.title("Methodology")
    page_note("Methodology")
    st.markdown(
        """
FixNext ranks every CVE published January–September 2026 by how likely attackers are to actually use it —
defined as being added to CISA's Known Exploited Vulnerabilities (KEV) list after it was published.
Everything the model looks at was already known at the end of the CVE's publish month.
"""
    )

    st.markdown("### How it was tested")
    st.markdown(
        """
Train on CVEs published in **2024**, then predict which CVEs published **January–June 2025** were later exploited
(39 were). Count how many of those 39 each ranking puts in its top 100 and top 500 — the same test IBM applies
to the 2026 benchmark, one year earlier, where we have the answers.
"""
    )
    s_bt = backtest_summary(backtest)
    _ours = backtest["method"].str.contains(r"fix\s*-?\s*(?:first|next)", case=False, regex=True, na=False)
    table = backtest.assign(method=[("**FixNext**" if o else m) for m, o in zip(backtest["method"], _ours)])
    cols = [c for c in ("hits_at_100", "hits_at_500") if c in table]
    header = "| Ranking | " + " | ".join("in top " + c.split("_")[-1] for c in cols) + " |\n|---|" + ":---:|" * len(cols)
    rows = "\n".join("| " + r["method"] + " | " + " | ".join(f"**{int(r[c])}**" if o else str(int(r[c])) for c in cols) + " |"
                      for (_, r), o in zip(table.iterrows(), _ours))
    st.markdown(header + "\n" + rows)
    st.markdown(
        f"""
Named catches the standard scores buried — ConnectWise ScreenConnect, two Kentico Xperience authentication
bypasses, a Windows NTLM hash leak — all with near-zero EPSS and no public exploit code when published, all later
exploited. The 18 that no ranking caught are listed too (`outputs/charts/caught_vs_missed.md`). With only
{s_bt['positives']} positives, differences of one or two hits are noise; we kept a change only when it helped at
one cutoff and hurt at none.
"""
    )

    st.markdown("### What the model uses")
    st.markdown(
        """
- **Who issued the CVE** (the assigner — usually the vendor's security team) and **the weakness type** (CWE).
  These are the two strongest features: fifteen issuers account for 72% of real exploitation, and attackers
  all but ignore cross-site scripting, CSRF and WordPress plugins.
- **Public exploit signals at the snapshot month**: EPSS, Exploit-DB, Metasploit, Nuclei templates, GitHub proof-of-concept code.
- **The CVSS v3 vector**: score, attack vector, privileges required, user interaction, impact.
- **The description** — keyword flags and a TF-IDF text signal.
- **IBM Granite — "looks like a known-exploited CVE."** `granite-embedding-small-english-r2` embeds every
  description; for each CVE we measure its cosine similarity to CVEs that were *already on KEV at that time*.
  The strongest-match similarity is the model's **#4 feature**. Used as plain embedding features instead,
  Granite did not beat TF-IDF on 39 positives — both results are in `outputs/backtest.md`.
- **The final score** is a blend of the LightGBM model with the "public exploit code first, then EPSS" ranking.

A two-line **"why fix this next"** for every CVE in the top 100 is written by `granite-3.3-2b-instruct`
from the description and the model's own reasons.
"""
    )

    st.markdown("### Keeping it fair — what it deliberately does not use")
    st.markdown(
        """
Today's NVD data leaks the future: NIST analyses exploited CVEs first. So for 2026 the model never sees
`nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, `cvss3_source`, `references.csv` (news and
threat-report links) or `affected_products.csv`. `src/config.py::assert_no_leakage` refuses them. The live 2026
KEV feed is never used as a feature; our #1 pick (CVE-2026-71362) was checked against it only after the model
was frozen — it had been added on 2026-09-24.

**Used:** `description`, `assigner`, `published` (to split time only), `cwe_ids`, CVSS v3 score and vector
components, the scoreboard's `epss` / `exploitdb` / `metasploit` / `nuclei` / `poc_github`, and
`known_exploited.csv` (≤ 2025-12-31) for labels. Full model card: `outputs/MODEL_CARD.md`.
"""
    )

footer()
