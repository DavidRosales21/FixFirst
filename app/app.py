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
import json
import streamlit.components.v1 as components
import math
import random
import re

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import json

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
QUICK_PICKS = {
    "EPSS would miss these": ("EPSS under 1% — an EPSS-first list never surfaces them", lambda d: d["epss"] < 0.01),
    "Has public exploit code": ("Exploit-DB, Metasploit, Nuclei or a GitHub PoC exists", lambda d: d["has_exploit"]),
    "Critical, but EPSS < 1%": ("Severity says fix, probability says ignore", lambda d: (d["cvss3_severity"] == "CRITICAL") & (d["epss"] < 0.01)),
    "No exploit code yet": ("Ranked on who issued it, the weakness and the description alone", lambda d: ~d["has_exploit"]),
    "Top 100": ("The hundred with a Granite rationale", lambda d: d["rank"] <= 100),
}
RANK_STEPS = {"Top 100": 100, "Top 500": 500, "Top 1,000": 1000, "All 5,000": 10 ** 9}
EPSS_STEPS = {"< 1%": 0.01, "< 10%": 0.10, "Any": 2.0}


FILTER_KEYS = ["f_vendor", "f_cwe", "f_month", "f_sev", "f_exploit", "f_query", "f_pick", "f_rank", "f_epss"]

# Chart colors: IBM Carbon steps checked for contrast on both the light and the dark surface.
BLUE, TEAL, PURPLE, GRAY = "#2FA874", "#2CB1BC", "#8B7CF6", "#8EA2B5"
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
def load_exploited(path):
    """The 39 CVEs of the 2025 hold-out that were later exploited, with their rank under each method (optional file)."""
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path, dtype={"cve_id": str})
    for col in ["rank_cvss", "rank_epss", "rank_flags_epss", "rank_fixnext"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df.dropna(subset=["rank_fixnext"])


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
exploited = load_exploited(os.path.join(HERE, "exploited_2025.csv"))
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
@import url('https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700&display=swap');
:root{
  /* cream canvas, navy panels, one green accent (html.ff-dark: set by the UI script from the page colour) */
  --ff-layer:#FFFFFF; --ff-line:#E4DED2; --ff-muted:#5B6B77; --ff-ink:#14202B;
  --ff-navy:#0D1B26; --ff-navy2:#152836; --ff-on-navy:#F3EFE7; --ff-on-navy-muted:#9FB0BD;
  --ff-green:#3FBF84; --ff-green-ink:#1F8F5F; --ff-green-bg:#E3F5EC; --ff-gold:#C9A86A;
  --ff-teal:#2CB1BC; --ff-teal-ink:#157F88; --ff-teal-bg:#DDF3F5; --ff-amber:#E3A63B; --ff-amber-ink:#A86F10; --ff-amber-bg:#FBEFD6;
  --ff-coral:#EF5350; --ff-coral-ink:#C62828; --ff-coral-bg:#FBE2E1; --ff-violet:#8B7CF6; --ff-violet-ink:#5B4BD6; --ff-violet-bg:#E9E6FD;
  --ff-accent:var(--ff-green-ink); --ff-r:16px; --ff-r2:10px;
  --ff-display:'Archivo','IBM Plex Sans','Helvetica Neue',Arial,sans-serif;
  --ff-ease: cubic-bezier(.2,0,.38,.9);
}
html.ff-dark{
  --ff-layer:#13242F; --ff-line:#243643; --ff-muted:#9FB0BD; --ff-ink:#F3EFE7;
  --ff-navy:#0D1B26; --ff-navy2:#1A2E3C; --ff-green-ink:#3FBF84; --ff-green-bg:#123527; --ff-accent:#3FBF84;
  --ff-teal-ink:#4FD1DB; --ff-teal-bg:#0F3A40; --ff-amber-ink:#F0BC5E; --ff-amber-bg:#3B2C10; --ff-coral-ink:#FF7B78; --ff-coral-bg:#3F1A1A; --ff-violet-ink:#A99CFF; --ff-violet-bg:#2A2452;
}
.stApp{font-variant-numeric:tabular-nums}
h1,h2,h3,.ff-brand b,[data-testid="stMetricValue"],.ff-fact b,.ff-gauge-num b,.ff-vs div b,.ff-tile b,.ff-catch .ff-ranks b{font-family:var(--ff-display) !important}
.stMainBlockContainer{padding-top:4.5rem !important}
.st-key-ffstage{margin-bottom:28px}
.st-key-ffstage [data-testid="stSelectbox"]{max-width:560px;margin-bottom:10px}
.st-key-ffstage [data-testid="stSelectbox"] > div > div{border-radius:var(--ff-r2)}
.st-key-ffstage iframe{display:block;border-radius:var(--ff-r)}
.st-key-ffhero [data-testid="stHorizontalBlock"]{align-items:center;gap:40px}
.ff-hero-side{margin:0 0 8px;font:500 12px/1 'IBM Plex Mono',monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--ff-green-ink)}
.st-key-ffhero .stButton button,.st-key-ffhero .stDownloadButton button{border-radius:var(--ff-r2) !important;min-height:48px;font-weight:600;font-family:var(--ff-display)}
.st-key-ffhero .stButton button[kind="primary"]{background:var(--ff-navy) !important;border:1px solid var(--ff-navy) !important;color:var(--ff-on-navy) !important}
.st-key-ffhero .stButton button[kind="primary"] p{color:var(--ff-on-navy) !important}
.st-key-ffhero .stDownloadButton button{background:transparent !important;border:1px solid var(--ff-ink) !important;color:var(--ff-ink) !important}
.st-key-ffslope{background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r);padding:20px 24px 12px;margin:8px 0 4px}
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
.ff-eyebrow{margin:0 0 14px;font:500 12px/1.4 'IBM Plex Mono',monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--ff-green-ink)}
.ff-h2{margin:0;font-family:var(--ff-display);font-size:20px;font-weight:600;letter-spacing:-.01em}
.ff-sub{margin:4px 0 8px;font-size:12px;color:var(--ff-muted)}

.ff-top{display:flex;flex-wrap:wrap;align-items:center;gap:6px 16px;padding:0 0 12px;border-bottom:1px solid var(--ff-line)}
.ff-top b{font-weight:600}
.ff-spacer{flex-grow:1}
.ff-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ff-green);margin-right:8px}

.ff-ticker{display:flex;align-items:center;height:44px;background:var(--ff-navy);color:var(--ff-on-navy);border-radius:var(--ff-r2);overflow:hidden;margin-bottom:16px}
.ff-ticker-label{flex:0 0 auto;height:100%;display:flex;align-items:center;padding:0 16px;background:var(--ff-green);color:var(--ff-navy);font-size:13px;font-weight:700;font-family:var(--ff-display)}
.ff-ticker-window{flex:1 1 auto;min-width:0;overflow:hidden}
.ff-track{display:flex;width:max-content;animation:ff-tick 48s linear infinite}
.ff-ticker:hover .ff-track{animation-play-state:paused}
.ff-item{display:inline-flex;align-items:baseline;gap:10px;padding:0 28px;border-right:1px solid rgba(243,239,231,.14);font-size:13px;white-space:nowrap}
.ff-item .ff-muted{color:var(--ff-on-navy-muted)}
.ff-item .ff-score{color:var(--ff-green)}

.ff-hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:28px;align-items:center;background:var(--ff-layer);padding:28px;animation:ff-rise 700ms var(--ff-ease) both}
.st-key-ffhero{padding:8px 4px 20px}
.st-key-ffhero [data-testid="stHorizontalBlock"]{align-items:center;gap:24px}
.st-key-ffhero [data-testid="stColumn"]{min-width:min(100%,320px) !important}
.st-key-ffhero iframe{border-radius:6px;display:block}
.ff-hero-text h1{margin:0;padding:0;font-family:var(--ff-display);font-weight:700;font-size:clamp(30px,3.3vw,46px);line-height:1.08;letter-spacing:-.025em}
.ff-hero-text h1 span{color:var(--ff-green-ink)}
.ff-hero-text p.ff-note{margin:18px 0 0;font-size:16px;line-height:1.55;color:var(--ff-muted);max-width:38em}
.ff-hero-cap{margin:6px 0 0;font-size:12px;color:var(--ff-muted);line-height:1.4}
.ff-slope-title{margin:0 0 4px;font-size:13px;font-weight:500;line-height:1.35}
.ff-slope{width:100%;max-width:820px;height:auto;display:block;font-family:inherit;overflow:visible;margin-top:6px}
.st-key-ffslope_ctl [data-testid="stHorizontalBlock"]{flex-wrap:wrap;gap:8px 20px}
.ff-read{background:var(--ff-navy);color:var(--ff-on-navy);border-radius:var(--ff-r2);padding:16px 18px;font-size:13px;line-height:1.5}
.ff-read>b{display:block;font-family:var(--ff-display);font-size:15px;font-weight:700;margin-bottom:6px}
.ff-read span{display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid rgba(243,239,231,.12);color:var(--ff-on-navy-muted)}
.ff-read span b{color:var(--ff-on-navy);font-family:var(--ff-display)}
.ff-read span:last-of-type{border-bottom:0}
.ff-read p{margin:8px 0 0;color:var(--ff-on-navy-muted)}.ff-read em{font-style:normal;color:var(--ff-green);font-weight:700}
.ff-slope .cve.ghost polyline{stroke:currentColor !important;stroke-opacity:.09 !important;stroke-width:1 !important}
.ff-slope .cve.ghost circle{fill:currentColor !important;fill-opacity:.14 !important;r:1.8}
.ff-slope .cve.lit polyline{stroke-opacity:.9;stroke-width:1.8}
.ff-slope .cve.lit.missed-by-all polyline{stroke:currentColor;stroke-opacity:.55}
.ff-slope .cve.lit.missed-by-all circle{fill:currentColor;fill-opacity:.7;r:2.6}
.ff-slope .cve.focus polyline{stroke:var(--ff-gold) !important;stroke-opacity:1 !important;stroke-width:3 !important}
.ff-slope .cve.focus circle{fill:var(--ff-gold) !important;fill-opacity:1 !important;r:4.5}
.ff-slope .lab.focus{fill:var(--ff-gold);font-weight:700}
.ff-slope:hover .cve.ghost{opacity:1}
.ff-slope .zone{fill:currentColor;opacity:.035}
.ff-slope .col{stroke:currentColor;stroke-opacity:.12;stroke-width:1}
.ff-slope .tick{font-size:10px;fill:currentColor;fill-opacity:.5;text-anchor:end;font-family:'IBM Plex Mono',ui-monospace,monospace}
.ff-slope .cut{stroke:currentColor;stroke-opacity:.6;stroke-width:1;stroke-dasharray:4 3}
.ff-slope .cutlab{font-size:10px;fill:currentColor;fill-opacity:.7}
.ff-slope .hname{font-size:11px;fill:currentColor;fill-opacity:.7;text-anchor:middle}
.ff-slope .hcount{font-size:20px;font-weight:700;fill:currentColor;text-anchor:middle;font-family:var(--ff-display)}
.ff-slope .hsub{font-size:10px;font-weight:400;fill-opacity:.6;font-family:inherit}
.ff-slope .hname.me,.ff-slope .hcount.me{fill:var(--ff-green-ink)}
.ff-slope .lab{font-size:10px;fill:var(--ff-green-ink)}
.ff-slope .cve polyline{fill:none;stroke-width:1.2;stroke-linejoin:round;stroke-dasharray:1;stroke-dashoffset:1;animation:ff-draw 900ms var(--ff-ease) forwards;animation-delay:calc(120ms + var(--i) * 28ms)}
.ff-slope .cve circle{opacity:0;animation:ff-pop 300ms ease-out forwards;animation-delay:calc(900ms + var(--i) * 28ms)}
.ff-slope .cve.missed-by-all polyline{stroke:currentColor;stroke-opacity:.16}
.ff-slope .cve.missed-by-all circle{fill:currentColor;fill-opacity:.25;r:2.2}
.ff-slope .cve.baseline-only polyline{stroke:var(--ff-amber);stroke-opacity:.95}
.ff-slope .cve.baseline-only circle{fill:var(--ff-amber)}
.ff-slope .cve.both polyline{stroke:var(--ff-teal);stroke-opacity:.5;stroke-width:1}
.ff-slope .cve.both circle{fill:var(--ff-teal);fill-opacity:.7;r:2.4}
.ff-slope .cve.FixNext-only polyline{stroke:var(--ff-accent);stroke-opacity:1;stroke-width:2.2}
.ff-slope .cve.FixNext-only circle{fill:var(--ff-accent);r:3.6}
.ff-slope:hover .cve.lit:not(:hover){opacity:.35}
.ff-slope .cve:hover polyline{stroke-opacity:1;stroke-width:2.6;stroke:var(--ff-accent)}
.ff-slope .cve:hover circle{fill:var(--ff-accent);fill-opacity:1;r:4}
.ff-hero-cap .sw{display:inline-block;width:14px;height:3px;vertical-align:middle;margin:0 5px 0 10px;border-radius:2px}
.ff-hero-cap .sw.me{background:var(--ff-accent)}.ff-hero-cap .sw.both{background:var(--ff-teal);opacity:.7}
.ff-hero-cap .sw.base{background:var(--ff-amber)}.ff-hero-cap .sw.none{background:currentColor;opacity:.2}
@keyframes ff-draw{to{stroke-dashoffset:0}}
@keyframes ff-pop{to{opacity:1}}

.ff-hero h1{margin:0;padding:0;font-weight:300;font-size:clamp(28px,2.8vw,40px);line-height:1.15}
.ff-hero h1 span{color:var(--ff-accent)}
.ff-hero p.ff-note{margin:16px 0 0;font-size:14px;line-height:1.5;color:var(--ff-muted);max-width:30em}

.ff-card{background:var(--ff-navy);color:var(--ff-on-navy);border-radius:var(--ff-r);padding:28px;display:flex;flex-wrap:wrap;gap:28px;align-items:center}
.ff-card .ff-eyebrow,.ff-card .ff-card-meta{color:var(--ff-on-navy-muted)}.ff-card .ff-eyebrow{color:var(--ff-green)}
.ff-gauge-wrap{position:relative;width:150px;height:150px;flex:0 0 auto}
.ff-ring{display:none}
.ff-ring.two{animation-delay:1.3s}
.ff-gauge{position:absolute;inset:0;border-radius:50%;background:conic-gradient(var(--ff-green) calc(var(--p) * 1%),rgba(243,239,231,.14) 0);
  -webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 12px),#000 calc(100% - 11px));
  mask:radial-gradient(farthest-side,transparent calc(100% - 12px),#000 calc(100% - 11px));
  animation:ff-fill 1.8s var(--ff-ease) .3s both}
.ff-gauge-num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ff-gauge-num b{font-size:32px;font-weight:700}
.ff-gauge-num span{font-size:12px;color:var(--ff-on-navy-muted)}
.ff-card-body{flex:1 1 260px;min-width:0}
.ff-cve{margin:0;font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:500;word-break:break-word}
.ff-card-meta{margin:6px 0 12px;font-size:14px;line-height:1.4;color:var(--ff-muted)}
.ff-pills{display:flex;flex-wrap:wrap;gap:8px}
.ff-pill{font-size:12px;padding:4px 10px;border-radius:24px;background:rgba(243,239,231,.1);color:var(--ff-on-navy)}
.ff-pill.epss{background:rgba(44,177,188,.22);color:#6FDCE4}
.ff-pill.exploit{background:rgba(239,83,80,.22);color:#FF9A98}
.ff-pill.vendor{background:rgba(227,166,59,.22);color:#F3C56E}
.ff-similar{margin:12px 0 0;font-size:13px;line-height:2}
.ff-sim{font-family:'IBM Plex Mono',monospace;font-size:12px;padding:3px 8px;margin-right:2px;background:rgba(243,239,231,.1);border-radius:6px;white-space:nowrap}
.ff-sim i{font-style:normal;color:var(--ff-on-navy-muted);margin-left:2px}
.ff-signals{display:flex;flex-wrap:wrap;gap:6px 8px;margin-top:14px;font-size:13px;color:var(--ff-on-navy-muted);align-items:center}
.ff-tag{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;font-size:12px;color:inherit;background:rgba(243,239,231,.1);border-radius:6px;white-space:nowrap}
.ff-tag i{display:inline-block;width:8px;height:8px;flex:0 0 auto}
.ff-tag.off{background:none;color:var(--ff-on-navy-muted)}

/* Active filters: a fixed-height box under the header, one chip per filter value. When the chips
   don't fit, the box scrolls and shows a blue scroll bar, so it's clear there is more inside. */
.ff-active{display:flex;flex-direction:column;gap:6px}
.ff-active-head{margin:0;font-size:13px}
.ff-active-head b{font-weight:600}
.ff-active-box{display:flex;flex-wrap:wrap;align-content:flex-start;gap:6px;max-height:88px;overflow-y:auto;overscroll-behavior:contain;
  padding:8px 6px 8px 10px;border:1px solid var(--ff-line);background:var(--ff-layer);border-radius:var(--ff-r2);font-size:13px;line-height:1.4}
.ff-active-box:focus-visible{outline:2px solid var(--ff-green-ink);outline-offset:2px}
.ff-active-none{color:var(--ff-muted)}
/* Streamlit makes every scroll bar transparent until hover; this one always shows (blue thumb, gray track). */
.ff-active-box{scrollbar-width:auto !important;scrollbar-color:var(--ff-green-ink) var(--ff-line) !important}
/* Older Safari, which ignores scrollbar-color */
.ff-active-box::-webkit-scrollbar{width:12px}
.ff-active-box::-webkit-scrollbar-track{background:var(--ff-line)}
.ff-active-box::-webkit-scrollbar-thumb{min-height:24px;background:var(--ff-green-ink);background-clip:padding-box;border:3px solid transparent;border-radius:12px}
.ff-chip{display:inline-flex;align-items:center;gap:6px;max-width:100%;padding:2px 10px;border-radius:12px;
  border:1px solid var(--ff-line);background:var(--ff-layer);color:inherit;overflow-wrap:anywhere}
.ff-chip-k{color:var(--ff-muted);white-space:nowrap}
.ff-chip-dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.ff-legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--ff-muted);margin:0}
.ff-legend span{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.ff-legend i{display:inline-block;width:10px;height:10px}

/* Header: project name · page tabs · theme switch (wraps onto two lines on narrow screens) */
.st-key-ffheader{background:var(--ff-navy);color:var(--ff-on-navy);border-radius:var(--ff-r);padding:8px 10px 8px 14px;margin-bottom:18px;border:1px solid rgba(243,239,231,.08)}
.st-key-ffheader [data-testid="stHorizontalBlock"]{flex-wrap:wrap;row-gap:4px;align-items:center}
.st-key-ffheader [data-testid="stColumn"]{width:auto !important;min-width:0 !important}
.st-key-ffheader [data-testid="stColumn"]{flex:0 0 auto !important}
.st-key-ffheader [data-testid="stColumn"]:nth-child(2){flex:1 1 auto !important;min-width:max-content !important}
.st-key-ffheader [data-testid="stColumn"]:nth-child(3){margin-left:auto}
.st-key-fftools{flex-wrap:nowrap !important;width:auto !important}
.st-key-fftools > div{width:auto !important;flex:0 0 auto !important}

/* Filters: an obvious button in the header, opening a wide pop-up panel with an X */
.st-key-fffilters button{min-height:40px;padding:0 14px !important;font-weight:600;font-family:var(--ff-display);border:1px solid rgba(243,239,231,.25) !important;border-radius:20px !important;background:transparent !important;color:var(--ff-on-navy) !important}
@media (hover:hover){.st-key-fffilters button:hover{background:rgba(243,239,231,.08) !important}}
.st-key-fffilters button[kind="primary"]{background:var(--ff-green) !important;border-color:var(--ff-green) !important;color:var(--ff-navy) !important}
.st-key-fffilters button[kind="primary"] p,.st-key-fffilters button[kind="primary"] span{color:var(--ff-navy) !important}
.st-key-fffilters button p,.st-key-fffilters button span{color:var(--ff-on-navy) !important}
.st-key-fffilters button [data-testid="stIconMaterial"]{font-size:22px}
[data-testid="stPopoverBody"]{width:min(780px,calc(100vw - 32px)) !important;max-width:calc(100vw - 32px) !important;border-radius:var(--ff-r) !important;padding:20px 22px !important;border:1px solid var(--ff-line) !important;box-shadow:0 24px 60px rgba(13,27,38,.28) !important}
.ff-pop-label{margin:12px 0 4px;font:500 11px/1.4 'IBM Plex Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--ff-green-ink)}
.ff-pop-hint{margin:-2px 0 6px;font-size:12.5px;color:var(--ff-muted)}
.ff-pop-count{margin:14px 0 0;padding-top:12px;border-top:1px solid var(--ff-line);font-size:13px;color:var(--ff-muted)}.ff-pop-count b{color:var(--ff-ink);font-family:var(--ff-display);font-size:15px}
[data-testid="stPopoverBody"] [data-testid="stPills"] button,[data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button{border-radius:20px !important;min-height:34px;font-size:13px}
[data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-checked="true"],[data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-pressed="true"]{background:var(--ff-navy) !important;color:var(--ff-on-navy) !important;border-color:var(--ff-navy) !important}
[data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-checked="true"] p,[data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-pressed="true"] p{color:var(--ff-on-navy) !important}
html.ff-dark [data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-checked="true"],html.ff-dark [data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-pressed="true"]{background:var(--ff-green) !important;color:var(--ff-navy) !important;border-color:var(--ff-green) !important}
html.ff-dark [data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-checked="true"] p,html.ff-dark [data-testid="stPopoverBody"] [data-testid="stButtonGroup"] button[aria-pressed="true"] p{color:var(--ff-navy) !important}
[data-testid="stPopoverBody"] [data-testid="stTextInput"] input,[data-testid="stPopoverBody"] [data-testid="stMultiSelect"] > div > div{border-radius:var(--ff-r2)}
.ff-pop-head{display:flex;align-items:center;justify-content:space-between;gap:12px;font-size:16px;
  border-bottom:1px solid var(--ff-line);padding-bottom:8px;margin-bottom:4px}
.ff-x{display:grid;place-items:center;width:40px;height:40px;padding:0;background:transparent;border:0;color:inherit;cursor:pointer}
.ff-x:focus-visible{outline:2px solid var(--ff-green-ink);outline-offset:-2px}
@media (hover:hover){.ff-x:hover{background:var(--ff-layer)}}
.ff-brand{display:flex;align-items:center;gap:12px;line-height:1.2;padding-right:16px}
.ff-brand>div{display:flex;flex-direction:column}
.ff-logo{flex:0 0 auto;display:block}
.ff-brand b{font-family:var(--ff-display);font-size:21px;font-weight:700;letter-spacing:-.02em;color:var(--ff-on-navy)}
.ff-brand span{font-size:12px;color:var(--ff-on-navy-muted);white-space:nowrap}
.ff-ibm{display:inline-flex;align-items:center;white-space:nowrap;font:500 11px/1 'IBM Plex Mono',monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--ff-green);padding:8px 10px;border:1px solid rgba(63,191,132,.45);border-radius:20px;margin-right:4px}
@media (max-width:900px){.ff-ibm{display:none}}
.st-key-page [data-testid="stButtonGroup"]{gap:4px;flex-wrap:wrap}
.st-key-page button{background:transparent !important;border:0 !important;border-radius:20px !important;min-height:40px;
  padding:0 16px !important;color:var(--ff-on-navy-muted) !important;box-shadow:none !important;font-family:var(--ff-display);font-weight:600}
.st-key-page button p{font-weight:600;color:inherit !important}
.st-key-page button[aria-checked="true"]{background:var(--ff-green) !important;color:var(--ff-navy) !important}
.st-key-page button[aria-checked="true"] p{color:var(--ff-navy) !important}
.st-key-page button:focus-visible{outline:2px solid var(--ff-green);outline-offset:2px}
@media (hover:hover){.st-key-page button:hover{background:rgba(243,239,231,.08) !important;color:var(--ff-on-navy) !important}}

.ff-ico{font-family:'Material Symbols Rounded';font-size:20px;line-height:1;font-weight:normal;font-style:normal;
  letter-spacing:normal;text-transform:none;white-space:nowrap;font-feature-settings:'liga';-webkit-font-smoothing:antialiased}
.ff-theme{display:inline-flex;border:1px solid rgba(243,239,231,.18);border-radius:20px;overflow:hidden;background:rgba(243,239,231,.06)}
.ff-theme button{color:var(--ff-on-navy-muted) !important}
.ff-theme button[aria-pressed="true"]{background:rgba(63,191,132,.22) !important;color:var(--ff-green) !important}
.ff-theme button,.ff-rail button{position:relative;display:grid;place-items:center;width:40px;height:40px;padding:0;margin:0;
  background:transparent;border:0;border-radius:0;color:var(--ff-muted);cursor:pointer;font:inherit}
.ff-theme button[aria-pressed="true"],.ff-rail button[aria-pressed="true"]{background:color-mix(in srgb,currentColor 14%,transparent);color:inherit}
.ff-theme button:focus-visible,.ff-rail button:focus-visible{outline:2px solid var(--ff-green-ink);outline-offset:-2px}
@media (hover:hover){.ff-theme button:hover{background:rgba(243,239,231,.1);color:var(--ff-on-navy)}.ff-rail button:hover{background:var(--ff-layer);color:inherit}}
.ff-theme button[aria-pressed="true"]{color:var(--ff-green-ink)}

/* Mini side menu of tools, fixed on the right edge */
.ff-rail{position:fixed;right:10px;top:50%;transform:translateY(-50%);z-index:999990;display:flex;flex-direction:column;gap:2px;
  padding:4px;background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.12)}
.ff-rail button[hidden]{display:none}
.ff-rail button[aria-pressed="true"]{color:var(--ff-green-ink)}
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
.ff-guide-item{padding:14px 16px;background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r2);counter-increment:guide}
.ff-guide-item.on{border-color:var(--ff-green-ink);box-shadow:inset 0 0 0 1px var(--ff-green-ink)}
.ff-guide{counter-reset:guide}
.ff-guide-item b{display:block;font-size:13px;font-weight:600;margin-bottom:3px}
.ff-guide-item b::before{content:counter(guide,decimal-leading-zero);font:500 11px/1 'IBM Plex Mono',monospace;color:var(--ff-green-ink);margin-right:10px;letter-spacing:.06em}
.ff-guide-item span{display:block;font-size:12px;line-height:1.45;color:var(--ff-muted)}
/* Three facts about the top 500 */
.ff-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,250px),1fr));gap:12px;margin:12px 0 4px}
.ff-fact{background:var(--ff-navy);color:var(--ff-on-navy);border-radius:var(--ff-r);padding:20px 22px}
.ff-fact b{display:block;font-size:34px;font-weight:700;line-height:1.1;color:var(--ff-green);letter-spacing:-.02em}
.ff-fact span{display:block;margin-top:8px;font-size:13px;line-height:1.45;color:var(--ff-on-navy-muted)}
.ff-fact em{font-style:normal;color:var(--ff-on-navy)}
/* Caught-vs-missed cards */
.ff-catches{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));gap:12px;margin-top:10px}
.ff-catch{background:var(--ff-layer);padding:18px;border:1px solid var(--ff-line);border-radius:var(--ff-r2)}
.ff-catch .ff-cve2{font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ff-muted)}
.ff-catch h4{margin:4px 0 10px;font-size:14px;font-weight:600;line-height:1.3}
.ff-catch .ff-ranks{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12px;color:var(--ff-muted)}
.ff-catch .ff-ranks b{display:block;font-size:20px;font-weight:700;color:inherit}
.ff-catch .ff-ranks .me b{color:var(--ff-green-ink)}
.ff-catch p{margin:10px 0 0;font-size:12px;color:var(--ff-muted);line-height:1.4}
/* CVE Detail: where the standard scores put it, and how the model reads it */
.ff-vs{display:flex;flex-wrap:wrap;gap:10px;margin:6px 0 14px}
.ff-vs div{flex:1 1 150px;padding:12px 16px;background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r2);font-size:12px;color:var(--ff-muted)}
.ff-vs div b{display:block;font-size:24px;font-weight:700;color:var(--ff-ink);margin-top:2px}
.ff-vs div.me{background:var(--ff-navy);border-color:var(--ff-navy);color:var(--ff-on-navy-muted)}
.ff-vs div.me b{color:var(--ff-green)}
.ff-how{margin:8px 0 0;padding:0;list-style:none;display:grid;gap:8px}
.ff-how li{display:grid;grid-template-columns:auto 1fr;gap:12px;align-items:start;padding:12px 16px;background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r2);font-size:14px;line-height:1.45}
.ff-how li i{font-style:normal;font-family:'IBM Plex Mono',monospace;font-size:11px;padding:3px 8px;background:var(--ff-green-bg);color:var(--ff-green-ink);border-radius:6px;white-space:nowrap;margin-top:1px}
.ff-pagenote{margin:-6px 0 10px;font-size:13px;color:var(--ff-muted)}
/* Ask FixNext (Gemini): one card, a three-colour accent, pill questions, a highlighted answer */
[class*="st-key-ffask"]{position:relative;margin-top:18px;padding:24px 26px 22px;background:var(--ff-navy);color:var(--ff-on-navy);border-radius:var(--ff-r)}
[class*="st-key-ffask"] .ff-ask-sub,[class*="st-key-ffask"] .ff-ask-note,[class*="st-key-ffask"] .ff-answer-meta{color:var(--ff-on-navy-muted)}
.ff-ask-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px 14px;margin:0 0 4px}
.ff-ask-head h2{margin:0;font-size:20px;font-weight:700;color:var(--ff-on-navy)}
.ff-ask-chip{font:500 11px/1 'IBM Plex Mono',monospace;letter-spacing:.08em;padding:5px 9px;border-radius:12px;background:rgba(63,191,132,.18);color:var(--ff-green);white-space:nowrap}
.ff-ask-sub{margin:0 0 12px;font-size:13px;color:var(--ff-muted)}
[class*="st-key-ffask"] [data-testid="stHorizontalBlock"]{flex-wrap:wrap;gap:8px}
[class*="st-key-ffask"] [data-testid="stColumn"]{flex:1 1 220px !important;min-width:0 !important;width:auto !important}
[class*="st-key-ffask"] button{border-radius:24px !important;border:1px solid rgba(243,239,231,.25) !important;
  background:rgba(243,239,231,.06) !important;min-height:38px;font-size:13px;color:var(--ff-on-navy) !important;white-space:normal;line-height:1.25}
[class*="st-key-ffask"] button p{color:var(--ff-on-navy) !important}
@media (hover:hover){[class*="st-key-ffask"] button:hover{background:rgba(63,191,132,.22) !important;border-color:var(--ff-green) !important}}
[class*="st-key-ffask"] [data-testid="stTextInput"] input{border-radius:var(--ff-r2)}
[class*="st-key-ffask"] [data-testid="stTextInput"] input{font-size:15px;min-height:46px}
.ff-answer{margin:12px 0 0;padding:16px 18px;background:var(--ff-navy2);border-left:3px solid var(--ff-green);border-radius:0 var(--ff-r2) var(--ff-r2) 0;font-size:15px;line-height:1.55}
.ff-answer p{margin:0 0 8px}.ff-answer p:last-child{margin:0}
.ff-answer-meta{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:11px;color:var(--ff-muted)}
.ff-answer-meta i{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ff-green)}
.ff-ask-note{margin:0;font-size:13px;color:var(--ff-muted)}
/* Floating chat: fixed bottom-right, scrolls with the page; collapses to a round button */
.st-key-ffchat{position:fixed;right:68px;bottom:40px;z-index:999980;width:min(380px,calc(100vw - 90px));
  background:var(--ff-navy);color:var(--ff-on-navy);border:1px solid rgba(243,239,231,.14);border-radius:var(--ff-r);overflow:hidden;
  box-shadow:0 18px 48px rgba(0,0,0,.32);padding:14px 16px 14px;font-size:13px}
.st-key-ffchat .ff-chat-empty,.st-key-ffchat .ff-msg.bot small{color:var(--ff-on-navy-muted)}
.st-key-ffchat_head [data-testid="stHorizontalBlock"]{flex-wrap:nowrap;align-items:center;gap:6px}
.st-key-ffchat_head [data-testid="stColumn"]:first-child{flex:1 1 auto !important;min-width:0 !important}
.st-key-ffchat_head [data-testid="stColumn"]:last-child{flex:0 0 36px !important;min-width:36px !important;width:36px !important}
.st-key-ffchat_quick{display:flex;flex-direction:column;gap:6px;margin-bottom:8px}
.st-key-ffchat_quick button{justify-content:flex-start;text-align:left;min-height:30px}
.st-key-ffchat_quick button p{font-size:12.5px}
.st-key-ffchat_quick button p{white-space:normal !important;text-align:left}
.st-key-ffchat button{border-radius:20px !important;border:1px solid rgba(243,239,231,.25) !important;
  background:rgba(243,239,231,.06) !important;min-height:32px;padding:2px 10px !important;font-size:12px;color:var(--ff-on-navy) !important;white-space:normal;line-height:1.2}
.st-key-ffchat button p{color:var(--ff-on-navy) !important}
@media (hover:hover){.st-key-ffchat button:hover{background:rgba(63,191,132,.22) !important}}
.st-key-ffchat .st-key-ffchat_hide button{border:1px solid var(--ff-line) !important;min-height:28px;height:28px;width:28px;padding:0 !important;
  font-size:18px;line-height:1;border-radius:50% !important;color:var(--ff-on-navy) !important;background:rgba(243,239,231,.1) !important}
.st-key-ffchat .st-key-ffchat_hide button p{margin:0;line-height:1;transform:translateY(-2px)}
.st-key-ffchat [data-testid="stTextInput"] input{font-size:13.5px;min-height:38px;border-radius:10px}
.st-key-ffchat [data-testid="stTextInput"] > div > div{border-radius:10px}
.ff-chat-head{display:flex;align-items:center;gap:10px;margin:0 0 6px}
.ff-chat-head b{font-size:15px;font-weight:700;font-family:var(--ff-display)}
.st-key-ffchat_head{padding-bottom:8px;margin-bottom:8px;border-bottom:1px solid rgba(243,239,231,.14)}
.ff-chat-head .ff-ask-chip{margin-left:auto}
.ff-chat-log{max-height:min(38vh,300px);overflow-y:auto;display:flex;flex-direction:column;gap:8px;margin:0 0 10px;padding-right:4px;scrollbar-width:thin}
.ff-msg{max-width:92%;padding:9px 12px;font-size:13.5px;line-height:1.45;border-radius:12px}
.ff-msg.user{align-self:flex-end;background:rgba(63,191,132,.22);border-bottom-right-radius:3px}
.ff-msg.bot{align-self:flex-start;background:var(--ff-navy2);border-left:3px solid var(--ff-green);border-bottom-left-radius:3px}
.ff-msg.bot small{display:block;margin-top:6px;font-size:11px;color:var(--ff-muted)}
.ff-chat-empty{margin:0 0 10px;font-size:12.5px;color:var(--ff-muted);line-height:1.45}
.st-key-ffchat_fab{position:fixed;right:68px;bottom:40px;left:auto;z-index:999980;width:max-content !important}
.st-key-ffchat_fab > div,.st-key-ffchat_fab [data-testid="stElementContainer"]{width:max-content !important}
.st-key-ffchat_fab button{border-radius:28px !important;min-height:48px;padding:0 20px !important;font-weight:700;font-family:var(--ff-display);
  background:var(--ff-navy) !important;color:var(--ff-on-navy) !important;border:1px solid rgba(243,239,231,.14) !important;box-shadow:0 10px 28px rgba(13,27,38,.35)}
.st-key-ffchat_fab button p{color:var(--ff-on-navy) !important}
.st-key-ffchat_fab button p::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ff-green);margin-right:9px;vertical-align:middle}
@media (max-width:520px){.st-key-ffchat{bottom:12px;right:12px;width:calc(100vw - 24px)}.st-key-ffchat_fab{bottom:12px;right:12px}}
@media (hover:hover){.ff-theme button:hover::after,.ff-rail button:hover::after{opacity:1}}
.stMainBlockContainer{padding-right:72px}
@media (max-width:640px){.stMainBlockContainer{padding-right:60px}}

.stButton button,.stDownloadButton button{border-radius:var(--ff-r2) !important}
.ff-reveal{opacity:0;transform:translateY(18px);transition:opacity .5s var(--ff-ease),transform .5s var(--ff-ease)}
.ff-reveal.ff-in{opacity:1;transform:none}
.ff-fact,.ff-catch,.ff-guide-item,[data-testid="stMetric"],.ff-tile,.ff-vs > div,.ff-how li,[class*="st-key-ffcard"]{transition:transform .25s var(--ff-ease),box-shadow .25s var(--ff-ease),opacity .5s var(--ff-ease)}
@media (hover:hover){.ff-fact:hover,.ff-catch:hover,.ff-guide-item:hover,[data-testid="stMetric"]:hover,.ff-tile:hover,.ff-vs > div:hover,.ff-how li:hover,[class*="st-key-ffcard"]:hover{transform:translateY(-3px);box-shadow:0 14px 30px rgba(13,27,38,.14)}}
@media (prefers-reduced-motion:reduce){.ff-reveal{opacity:1;transform:none;transition:none}}
/* colour by meaning: green = FixNext · teal = EPSS/industry · amber = said wait · coral = exploited/critical · violet = Granite & Gemini */
.st-key-ffkpis [data-testid="stColumn"]:nth-child(1) [data-testid="stMetric"]{border-top:4px solid var(--ff-green)}
.st-key-ffkpis [data-testid="stColumn"]:nth-child(2) [data-testid="stMetric"]{border-top:4px solid var(--ff-violet)}
.st-key-ffkpis [data-testid="stColumn"]:nth-child(3) [data-testid="stMetric"]{border-top:4px solid var(--ff-coral)}
.st-key-ffkpis [data-testid="stColumn"]:nth-child(4) [data-testid="stMetric"]{border-top:4px solid var(--ff-teal)}
.ff-fact:nth-child(1) b{color:var(--ff-teal)}.ff-fact:nth-child(2) b{color:var(--ff-coral)}.ff-fact:nth-child(3) b{color:var(--ff-amber)}
.ff-guide-item:nth-child(1) b::before{color:var(--ff-green-ink)}.ff-guide-item:nth-child(2) b::before{color:var(--ff-teal-ink)}.ff-guide-item:nth-child(3) b::before{color:var(--ff-violet-ink)}.ff-guide-item:nth-child(4) b::before{color:var(--ff-amber-ink)}
.ff-guide-item:nth-child(1){border-top:3px solid var(--ff-green)}.ff-guide-item:nth-child(2){border-top:3px solid var(--ff-teal)}.ff-guide-item:nth-child(3){border-top:3px solid var(--ff-violet)}.ff-guide-item:nth-child(4){border-top:3px solid var(--ff-amber)}
.ff-vs > div:nth-child(2) b{color:var(--ff-teal-ink)}.ff-vs > div:nth-child(3) b{color:var(--ff-amber-ink)}.ff-vs > div:nth-child(4) b{color:var(--ff-coral-ink)}
.ff-how li:nth-child(1) i{background:var(--ff-teal-bg);color:var(--ff-teal-ink)}.ff-how li:nth-child(2) i{background:var(--ff-amber-bg);color:var(--ff-amber-ink)}.ff-how li:nth-child(3) i{background:var(--ff-violet-bg);color:var(--ff-violet-ink)}.ff-how li:nth-child(4) i{background:var(--ff-coral-bg);color:var(--ff-coral-ink)}.ff-how li:nth-child(5) i{background:var(--ff-teal-bg);color:var(--ff-teal-ink)}
.ff-catch .ff-ranks span:nth-child(2) b{color:var(--ff-teal-ink)}.ff-catch .ff-ranks span:nth-child(3) b{color:var(--ff-amber-ink)}
.ff-catch{border-top:3px solid var(--ff-green)}
[class*="st-key-ffask"]{border-left:5px solid var(--ff-violet)}.ff-ask-chip{background:rgba(139,124,246,.22) !important;color:#C9C1FF !important}
.ff-answer{border-left-color:var(--ff-violet) !important}.ff-answer-meta i{background:var(--ff-violet) !important}
.st-key-ffchat{border-left:4px solid var(--ff-violet) !important}.ff-msg.bot{border-left-color:var(--ff-violet) !important}.ff-msg.user{background:rgba(139,124,246,.22) !important}
.st-key-ffchat_fab button p::before{background:var(--ff-violet) !important}
.ff-box{border-top:3px solid var(--ff-violet)}
.ff-ibm{color:var(--ff-teal) !important;border-color:rgba(44,177,188,.5) !important}
/* Streamlit's own menu stays (the rail and the theme buttons use it) but out of sight */
[data-testid="stMainMenu"]{visibility:hidden}
[data-testid="stAppDeployButton"]{display:none}
html.ff-driving [data-testid="stMainMenuPopover"]{opacity:0 !important;pointer-events:none !important}

.ff-footer{display:flex;flex-wrap:wrap;gap:6px 20px;justify-content:space-between;margin-top:40px;padding:18px 0 4px;
  border-top:1px solid var(--ff-line);font-size:12px;color:var(--ff-muted)}
.ff-footer b{font-weight:600}

/* Rows that wrap instead of squeezing: KPI tiles (min 200px) and chart cards (min 360px) */
.st-key-ffkpis [data-testid="stHorizontalBlock"],.st-key-ffrow [data-testid="stHorizontalBlock"]{flex-wrap:wrap;row-gap:1rem}
.st-key-ffkpis [data-testid="stColumn"]{flex:1 1 200px !important;min-width:min(100%,200px) !important;width:auto !important}
.st-key-ffrow [data-testid="stColumn"]{flex:1 1 360px !important;min-width:min(100%,360px) !important;width:auto !important}

.ff-box{background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r);padding:22px 26px}
.ff-box h2{margin:0 0 8px;font-size:18px;font-weight:700}
.ff-box p{margin:0;line-height:1.6;white-space:pre-line}
.ff-pending{color:var(--ff-muted);font-style:italic}
.ff-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:8px}
.ff-tile{background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r2);padding:14px 16px}
.ff-tile span{display:block;font-size:12px;color:var(--ff-muted);margin-bottom:10px}
.ff-tile b{font-size:22px;font-weight:700}
.ff-empty{background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r);padding:28px}
.ff-empty h2{margin:0 0 6px;font-size:18px;font-weight:400}
.ff-empty p{margin:0;color:var(--ff-muted)}

[data-testid="stMetric"]{background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r);padding:18px 18px 22px;
  min-height:148px;box-sizing:border-box;display:flex;flex-direction:column}
[data-testid="stMetric"] > div{flex:1 1 auto;display:flex;flex-direction:column}
[data-testid="stMetricValue"]{font-weight:700;letter-spacing:-.02em;margin-top:auto;padding-top:12px}
[data-testid="stHorizontalBlock"]:has([data-testid="stMetric"]){align-items:stretch}
[data-testid="stColumn"]:has([data-testid="stMetric"]) [data-testid="stVerticalBlock"],
[data-testid="stColumn"]:has([data-testid="stMetric"]) [data-testid="stElementContainer"],
[data-testid="stColumn"]:has([data-testid="stMetric"]) [data-testid="stMetric"]{height:100%}
@media (max-width:640px){[data-testid="stMetric"]{min-height:0}}
[data-testid="stMetricLabel"] *,[data-testid="stMetricValue"] *{white-space:normal !important;overflow:visible !important;text-overflow:clip !important}

[class*="st-key-ffcard"]{background:var(--ff-layer);border:1px solid var(--ff-line);border-radius:var(--ff-r);padding:22px 24px}


@media (prefers-reduced-motion:reduce){
  .ff-slope .cve polyline,.ff-slope .cve circle,.ff-dot,.ff-track,.ff-hero,.ff-px.lb,.ff-px.lp,.ff-card,.ff-gauge,.ff-ring,.ff-box,
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
    if (app) {
      var bg = getComputedStyle(app).backgroundColor;
      doc.documentElement.style.setProperty('--ff-bg', bg);
      var m = bg.match(/[0-9]+/g), dark = m && (0.2126 * m[0] + 0.7152 * m[1] + 0.0722 * m[2]) < 128;
      doc.documentElement.classList.toggle('ff-dark', !!dark);
    }
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
  // Scroll reveal + count-up: blocks rise into place when they enter the view; numbers count up once.
  var REVEAL = '[data-testid="stMetric"],.ff-fact,.ff-catch,.ff-guide-item,.ff-card,[class*="st-key-ffcard"],[data-testid="stPlotlyChart"],.st-key-ffslope,[class*="st-key-ffask"],.ff-box,.ff-tile,.ff-vs > div,.ff-how li,.ff-read,.ff-empty';
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function countUp(el) {
    var t = (el.textContent || '').trim(), m = t.match(/^([^0-9]*)([0-9][0-9,]*)([.][0-9]+)?(.*)$/);
    if (!m || el.dataset.ffCounted) return; el.dataset.ffCounted = '1';
    var pre = m[1], whole = m[2].replace(/,/g, ''), dec = m[3] ? m[3].length - 1 : 0, suf = m[4], end = parseFloat(whole + (m[3] || ''));
    if (!isFinite(end) || end === 0) return;
    var grouped = m[2].indexOf(',') >= 0, t0 = performance.now(), dur = 900;
    (function step(now) { var k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 3), v = end * e;
      var txt = dec ? v.toFixed(dec) : (grouped ? Math.round(v).toLocaleString('en-US') : String(Math.round(v)));
      el.textContent = pre + txt + suf; if (k < 1) requestAnimationFrame(step); })(t0);
  }
  var io = ('IntersectionObserver' in window) ? new IntersectionObserver(function (es) {
    es.forEach(function (e) { if (!e.isIntersecting) return; var el = e.target; io.unobserve(el);
      var sibs = Array.prototype.filter.call(el.parentElement ? el.parentElement.children : [], function (c) { return c.classList && c.classList.contains('ff-reveal'); });
      el.style.transitionDelay = (Math.min(sibs.indexOf(el), 5) * 70) + 'ms';
      el.classList.add('ff-in');
      if (!reduce) qa('[data-testid="stMetricValue"] div, .ff-fact b, .ff-tile b, .ff-vs b, .ff-catch .ff-ranks b, .ff-gauge-num b').forEach(function (n) { if (el.contains(n)) countUp(n); });
    });
  }, { threshold: 0.12 }) : null;
  function reveal() {
    if (!io || reduce) return;
    qa(REVEAL).forEach(function (el) { if (el.classList.contains('ff-reveal')) return; el.classList.add('ff-reveal'); io.observe(el); });
  }
  window.__ffUi = { sync: sync };
  var queued = false;
  new MutationObserver(function () {
    if (queued) return; queued = true;
    setTimeout(function () { queued = false; sync(); reveal(); }, 150);
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
  sync(); reveal();
})();
</script>
"""


def remember_page():
    """The page tabs always keep one page selected (clicking the active tab doesn't clear it)."""
    if st.session_state.get("page") is None:
        st.session_state["page"] = st.session_state.get("_last_page", PAGES[0])
    st.session_state["_last_page"] = st.session_state["page"]


LOGO_SVG = (
    '<svg class="ff-logo" viewBox="0 0 40 40" width="40" height="40" aria-hidden="true">'
    '<defs><linearGradient id="ffg" x1="0" y1="1" x2="1" y2="0"><stop offset="0" stop-color="#2CB1BC"/><stop offset="1" stop-color="#3FBF84"/></linearGradient></defs>'
    '<rect x="1" y="1" width="38" height="38" rx="11" fill="url(#ffg)"/>'
    '<rect x="8" y="23" width="6.5" height="9" rx="1.6" fill="#F3EFE7" opacity=".55"/>'
    '<rect x="16.75" y="16" width="6.5" height="16" rx="1.6" fill="#F3EFE7" opacity=".8"/>'
    '<rect x="25.5" y="8" width="6.5" height="24" rx="1.6" fill="#F3EFE7"/>'
    '<path d="M25.2 13.2l3.55-4.4 3.55 4.4" fill="none" stroke="#0D1B26" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)


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
        brand.markdown(f'<div class="ff-brand">{LOGO_SVG}<div><b>FixNext</b><span>{esc(tag)}</span></div></div>', unsafe_allow_html=True)
        nav.segmented_control("Page", PAGES, key="page", label_visibility="collapsed", on_change=remember_page)
        # Filters button + theme switch stay together as one group (and wrap together).
        with tools.container(horizontal=True, key="fftools", gap="small", vertical_alignment="center"):
            st.html('<span class="ff-ibm">Built with IBM Granite</span>')
            filters_slot = st.container()
            st.html(
                f'<div class="ff-theme" role="group" aria-label="Theme">{theme}</div>'
                f'<nav class="ff-rail" aria-label="App tools">{rail}</nav>' + UI_SCRIPT,
                unsafe_allow_javascript=True,
            )
    return st.session_state.get("page") or PAGES[0], filters_slot


def footer():
    st.html(
        '<footer class="ff-footer"><span><b>FixNext</b> · fixnext.select · built with IBM Granite</span>'
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

    if s.get("f_pick") in QUICK_PICKS:
        chip("Quick pick", esc(s["f_pick"]))
    if s.get("f_rank") in RANK_STEPS and s["f_rank"] != "All 5,000":
        chip("Rank", esc(s["f_rank"]))
    if s.get("f_epss") in EPSS_STEPS and s["f_epss"] != "Any":
        chip("EPSS", esc(s["f_epss"]))
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
        '<span class="ff-ticker-label">Fix next</span><div class="ff-ticker-window">'
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


SLOPE_COLS = [("rank_cvss", "CVSS first"), ("rank_epss", "EPSS first"),
              ("rank_flags_epss", "Exploit code, then EPSS"), ("rank_fixnext", "FixNext")]
SLOPE_LABELS = {"CVE-2025-3935": "ConnectWise ScreenConnect", "CVE-2025-2747": "Kentico Xperience (×2)",
                "CVE-2025-24054": "Microsoft Windows NTLM"}


def slope_chart(df, cols, lit, focus=None, cut=500, labels_for=None):
    """Later-exploited CVEs of the 2025 hold-out, one line each, across the chosen rankings.
    `lit` = set of cve_ids drawn in full; everything else is a faint ghost so the counts still add up."""
    n_cols = len(cols)
    W, H, top, bot = 640, 330, 58, 300
    xs = [90 + i * ((W - 230) / max(1, n_cols - 1)) for i in range(n_cols)] if n_cols > 1 else [W / 2]
    rmax = max(25_000, int(df[[c for c, _ in cols]].max().max()))
    y = lambda r: top + math.log(max(float(r), 1.0)) / math.log(rmax) * (bot - top)
    ycut = y(cut)
    df = df.assign(_lit=df["cve_id"].isin(lit)).sort_values(["_lit", "rank_fixnext"], ascending=[True, False])
    parts = [f'<svg class="ff-slope" viewBox="0 0 {W} {H}" role="img" aria-label="Where each ranking put the exploited CVEs of 2025">']
    parts.append(f'<rect x="{xs[0] - 24}" y="{top - 4}" width="{xs[-1] - xs[0] + 48:.1f}" height="{ycut - top + 4:.1f}" class="zone"/>')
    for r, lab in [(1, "#1"), (100, "#100"), (1000, "#1,000"), (10000, "#10,000")]:
        parts.append(f'<text x="{xs[0] - 32}" y="{y(r) + 4:.1f}" class="tick">{lab}</text>')
    parts.append(f'<line x1="{xs[0] - 24}" x2="{xs[-1] + 24}" y1="{ycut:.1f}" y2="{ycut:.1f}" class="cut"/>')
    parts.append(f'<text x="{xs[0] - 22}" y="{ycut + 12:.1f}" class="cutlab">top {cut} — above this line gets fixed</text>')
    for i, (col, name) in enumerate(cols):
        n = int((df[col] <= cut).sum())
        cls = "me" if col == "rank_fixnext" else ""
        parts.append(f'<line x1="{xs[i]:.1f}" x2="{xs[i]:.1f}" y1="{top - 4}" y2="{bot + 4}" class="col"/>')
        parts.append(f'<text x="{xs[i]:.1f}" y="22" class="hname {cls}">{esc(name)}</text>')
        parts.append(f'<text x="{xs[i]:.1f}" y="44" class="hcount {cls}">{n}<tspan class="hsub"> of {len(df)} in top {cut}</tspan></text>')
    labels = []
    for k, (_, r) in enumerate(df.iterrows()):
        pts = " ".join(f"{xs[i]:.1f},{y(r[c]):.1f}" for i, (c, _) in enumerate(cols))
        b = str(r["bucket"]).replace(" ", "-")
        is_lit = bool(r["_lit"]); is_focus = focus == r["cve_id"]
        cls = f'cve {b}{" lit" if is_lit else " ghost"}{" focus" if is_focus else ""}'
        tip = f'{r["cve_id"]} — {str(r["kev_name"]).replace(" Vulnerability", "")}\n' + " · ".join(f'{nm}: #{int(r[c]):,}' for c, nm in cols)
        parts.append(f'<g class="{cls}" style="--i:{k}"><title>{esc(tip)}</title><polyline points="{pts}" pathLength="1"/>'
                     + "".join(f'<circle cx="{xs[i]:.1f}" cy="{y(r[c]):.1f}" r="3"/>' for i, (c, _) in enumerate(cols)) + '</g>')
        if (labels_for and r["cve_id"] in labels_for) or is_focus:
            labels.append([y(r["rank_fixnext"]), labels_for.get(r["cve_id"]) if labels_for and r["cve_id"] in labels_for else short(str(r["kev_name"]).replace(" Vulnerability", ""), 26), is_focus])
    labels.sort(key=lambda t: t[0])
    for i in range(1, len(labels)):
        labels[i][0] = max(labels[i][0], labels[i - 1][0] + 12)
    for ly, lab, f in labels:
        parts.append(f'<text x="{xs[-1] + 10:.1f}" y="{ly + 4:.1f}" class="lab{" focus" if f else ""}">{esc(lab)}</text>')
    parts.append('</svg>')
    return "".join(parts)


# ---------------------------------------------------------------- the stage (hero)

STAGE_HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--navy:#0d1b26;--ink:#f3efe7;--muted:#9fb0bd;--green:#3fbf84;--amber:#e3a63b;--red:#ef5350;--gold:#c9a86a;--line:rgba(243,239,231,.14)}
html,body{margin:0;height:100%;overflow:hidden;background:transparent;font-family:'Archivo','IBM Plex Sans','Helvetica Neue',Arial,sans-serif;color:var(--ink)}
#wrap{position:relative;width:100%;height:100%;border-radius:18px;overflow:hidden;background:radial-gradient(120% 90% at 50% 30%,#1a3040 0%,#0f1f2b 45%,#0a1620 100%)}
#c{position:absolute;inset:0;width:100%;height:100%;display:block;cursor:grab}#c:active{cursor:grabbing}
.ui{position:absolute;inset:0;pointer-events:none}
#head{position:absolute;left:28px;top:22px;max-width:56%}
#count{font:500 12px/1 'IBM Plex Mono',monospace;letter-spacing:.14em;color:var(--muted);margin-bottom:8px}
#title{margin:0;font-size:24px;font-weight:700;letter-spacing:-.02em;line-height:1.12;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
#sub{margin:6px 0 0;font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#top-r{position:absolute;right:28px;top:24px;display:flex;flex-direction:column;align-items:flex-end;gap:10px}
#prog{display:flex;gap:6px;padding:7px 10px;border:1px solid var(--line);border-radius:20px;background:rgba(10,22,32,.55)}
#prog i{display:block;width:22px;height:3px;border-radius:2px;background:rgba(243,239,231,.22);transition:background .3s}
#prog i.on{background:var(--ink)}#prog i.done{background:var(--green)}
#days{font:500 13px/1 'IBM Plex Mono',monospace;letter-spacing:.06em;color:var(--muted);padding:8px 12px;border-radius:8px;background:rgba(10,22,32,.55);border:1px solid var(--line);transition:color .3s,border-color .3s}
#days b{color:var(--ink);font-weight:500}
#days.red{color:var(--red);border-color:rgba(239,83,80,.5)}#days.red b{color:var(--red)}
#beats{display:flex;gap:4px;pointer-events:auto}
#beats span{display:flex;align-items:center;gap:6px;padding:5px 9px;border-radius:14px;border:1px solid var(--line);background:rgba(10,22,32,.55);font:500 10px/1 'IBM Plex Mono',monospace;letter-spacing:.08em;color:var(--muted);cursor:pointer;transition:all .25s}
#beats span i{display:block;width:26px;height:3px;border-radius:2px;background:rgba(243,239,231,.18);overflow:hidden;position:relative}
#beats span i::after{content:"";position:absolute;left:0;top:0;bottom:0;width:calc(var(--p,0) * 100%);background:var(--green)}
#beats span.on{color:var(--ink);border-color:rgba(63,191,132,.6)}
#beats span.done i::after{width:100%}
.call{position:absolute;pointer-events:auto;transform:translate(-50%,-50%) translateY(6px);white-space:nowrap;padding:7px 11px;border-radius:7px;font-size:12px;font-weight:600;
  background:rgba(13,27,38,.92);border:1px solid var(--line);box-shadow:0 8px 24px rgba(0,0,0,.35);opacity:0;transition:opacity .4s,transform .4s,border-color .3s;cursor:default}
.call.show{opacity:1;transform:translate(-50%,-50%)}
.call small{display:block;font-weight:500;font-size:11px;color:var(--muted);margin-top:2px}
.call b{font-family:'IBM Plex Mono',monospace;font-weight:500}
.call.amber{border-color:rgba(227,166,59,.55)}.call.amber b{color:var(--amber)}
.call.green{border-color:rgba(63,191,132,.6)}.call.green b{color:var(--green)}
.call .more{display:none;max-width:240px;white-space:normal;margin-top:6px;padding-top:6px;border-top:1px solid var(--line);font-weight:500;font-size:11px;color:var(--ink);line-height:1.4}
.call.big{z-index:3}.call.big .more{display:block}
.call.dim{opacity:.35}
#lines{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
#lines line{stroke:rgba(243,239,231,.5);stroke-width:1;transition:opacity .4s}
#lines circle{fill:var(--ink)}
#verdict{position:absolute;left:50%;bottom:132px;z-index:2;transform:translateX(-50%) translateY(8px);padding:9px 16px;border-radius:8px;background:rgba(10,30,26,.94);border:1px solid rgba(63,191,132,.6);
  color:var(--green);font-size:13px;font-weight:600;white-space:nowrap;opacity:0;transition:opacity .5s,transform .5s}
#verdict.show{opacity:1;transform:translateX(-50%)}
#cards{position:absolute;left:28px;right:28px;bottom:22px;display:grid;grid-template-columns:repeat(3,1fr);gap:12px;pointer-events:auto}
.card{padding:12px 14px;border-radius:10px;background:rgba(13,27,38,.86);border:1px solid var(--line);backdrop-filter:blur(8px);font-size:12px;line-height:1.4;min-height:58px;transition:border-color .3s,background .3s;cursor:default}
.card i{font:500 11px/1 'IBM Plex Mono',monospace;color:var(--muted);margin-right:8px;font-style:normal;letter-spacing:.06em;transition:color .3s}
.card b{font-weight:600;font-size:12.5px}
.card p{margin:4px 0 0;color:var(--muted)}
.card.on{border-color:rgba(63,191,132,.65);background:rgba(16,38,42,.92)}.card.on i{color:var(--green)}
.card.amber{border-color:rgba(227,166,59,.6);background:rgba(44,34,18,.9)}.card.amber i{color:var(--amber)}
.card.red{border-color:rgba(239,83,80,.65);background:rgba(50,18,20,.9)}.card.red i{color:var(--red)}
.nav{position:absolute;top:50%;transform:translateY(-50%);width:38px;height:38px;border-radius:50%;border:1px solid var(--line);background:rgba(13,27,38,.7);color:var(--ink);
  display:grid;place-items:center;cursor:pointer;pointer-events:auto;font-size:18px;transition:background .2s}
.nav:hover{background:rgba(63,191,132,.3)}#prev{left:16px}#next{right:16px}
#hint{position:absolute;right:28px;bottom:118px;font:400 11px/1 'IBM Plex Mono',monospace;color:var(--muted);letter-spacing:.06em}
@media (max-width:760px){#title{font-size:19px;max-width:80%}#cards{grid-template-columns:1fr;gap:6px}.card{min-height:0;padding:8px 10px}.call{font-size:11px}#hint,#beats{display:none}#verdict{white-space:normal;text-align:center;width:80%}}
</style></head><body><div id="wrap">
<canvas id="c"></canvas>
<svg id="lines"></svg>
<div class="ui"><div id="head"><div id="count">01 / 05</div><h2 id="title"></h2><p id="sub"></p></div>
<div id="top-r"><div id="prog"></div><div id="days">Day <b>0</b> · published</div><div id="beats"></div></div>
<div id="calls"></div><div id="verdict"></div>
<div id="hint">hover a pillar · drag to orbit</div>
<div id="cards"><div class="card" id="k0"></div><div class="card" id="k1"></div><div class="card" id="k2"></div></div></div>
<button class="nav" id="prev" type="button" aria-label="Previous">‹</button><button class="nav" id="next" type="button" aria-label="Next">›</button>
</div>
<script type="importmap">{"imports":{"three":"https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js","three/addons/":"https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/"}}</script>
<script type="module">
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
const SL = __SLIDES__, RMAX = 25000, CUT = 500;
const $ = id => document.getElementById(id);
const cv = $('c'), wrap = $('wrap');
const renderer = new THREE.WebGLRenderer({canvas: cv, antialias: true, alpha: true});
renderer.setPixelRatio(Math.min(devicePixelRatio, 2)); renderer.shadowMap.enabled = true; renderer.shadowMap.type = THREE.PCFSoftShadowMap;
renderer.toneMapping = THREE.ACESFilmicToneMapping; renderer.toneMappingExposure = 0.95;
const scene = new THREE.Scene(); scene.fog = new THREE.Fog(0x0e1d28, 7, 16);
const pmrem = new THREE.PMREMGenerator(renderer); scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 60); camera.position.set(0.6, 3.1, 8.2);
const controls = new OrbitControls(camera, cv); controls.target.set(0, 0.75, 0); controls.enableDamping = true; controls.enablePan = false; controls.enableZoom = false;
controls.minPolarAngle = 0.9; controls.maxPolarAngle = 1.35; controls.autoRotate = true; controls.autoRotateSpeed = 0.45;
const key = new THREE.DirectionalLight(0xfff2e0, 2.0); key.position.set(3.5, 7, 4); key.castShadow = true; key.shadow.mapSize.set(2048, 2048);
key.shadow.camera.left = -5; key.shadow.camera.right = 5; key.shadow.camera.top = 5; key.shadow.camera.bottom = -5; key.shadow.radius = 6; key.shadow.bias = -0.0005; scene.add(key);
const rim = new THREE.DirectionalLight(0x3fbf84, 1.0); rim.position.set(-4, 3, -5); scene.add(rim);
scene.add(new THREE.HemisphereLight(0x3a5468, 0x070d12, 0.8));
const floor = new THREE.Mesh(new THREE.CircleGeometry(14, 64), new THREE.MeshStandardMaterial({color: 0x0c1a24, roughness: 0.9, metalness: 0.05, envMapIntensity: 0.25}));
floor.rotation.x = -Math.PI / 2; floor.receiveShadow = true; scene.add(floor);
// pedestal: dark brushed disc (low reflection so it never blows out to white on a real GPU)
const ped = new THREE.Mesh(new THREE.CylinderGeometry(1.95, 2.05, 0.16, 96), new THREE.MeshStandardMaterial({color: 0x13222f, roughness: 0.62, metalness: 0.3, envMapIntensity: 0.35}));
ped.position.y = 0.08; ped.receiveShadow = true; ped.castShadow = true; scene.add(ped);
const ring = new THREE.Mesh(new THREE.TorusGeometry(1.99, 0.014, 12, 160), new THREE.MeshStandardMaterial({color: 0xc9a86a, emissive: 0x7a5c2a, roughness: 0.3, metalness: 0.8}));
ring.rotation.x = Math.PI / 2; ring.position.y = 0.165; scene.add(ring);
const H = r => 0.12 + 2.0 * Math.max(0, 1 - Math.log(Math.max(r, 1)) / Math.log(RMAX));
// the top-500 line: dashed while nothing reaches it, solid green when FixNext crosses it
const cutMat = new THREE.MeshBasicMaterial({color: 0x3fbf84, transparent: true, opacity: 0.5});
const cutRing = new THREE.Mesh(new THREE.TorusGeometry(1.6, 0.012, 8, 160), cutMat); cutRing.rotation.x = Math.PI / 2; cutRing.position.y = 0.16 + H(CUT); scene.add(cutRing);
// red pulse on the floor when the CVE gets exploited
const pulseMat = new THREE.MeshBasicMaterial({color: 0xef5350, transparent: true, opacity: 0, side: THREE.DoubleSide});
const pulse = new THREE.Mesh(new THREE.RingGeometry(0.9, 1.0, 96), pulseMat); pulse.rotation.x = -Math.PI / 2; pulse.position.y = 0.17; scene.add(pulse);
// the crowd: the other CVEs, out of focus
const cm = new THREE.MeshStandardMaterial({color: 0x24384a, roughness: 0.7, metalness: 0.2, envMapIntensity: 0.3});
for (let i = 0; i < 90; i++) { const a = Math.random() * Math.PI * 2, d = 3.4 + Math.random() * 7, h = 0.15 + Math.random() * 0.9;
  const m = new THREE.Mesh(new THREE.BoxGeometry(0.22, h, 0.22), cm); m.position.set(Math.cos(a) * d, h / 2, Math.sin(a) * d); scene.add(m); }
// the object: four pillars
const group = new THREE.Group(); scene.add(group);
const COLS = [['CVSS first', 'cvss'], ['EPSS first', 'epss'], ['Exploit code, then EPSS', 'flags'], ['FixNext', 'fixnext']];
const X = [-1.05, -0.35, 0.35, 1.05];
const COLOR = {amber: 0xe3a63b, green: 0x3fbf84, teal: 0x4fb3bf, idle: 0x8ea2b5};
const EMIS = {amber: 0x5a3c08, green: 0x0f5a38, teal: 0x0f4a52, idle: 0x000000};
const pillars = COLS.map(([name, k], i) => {
  const mat = new THREE.MeshStandardMaterial({color: COLOR.idle, roughness: 0.25, metalness: 0.3, emissive: 0x000000, emissiveIntensity: 0.6, envMapIntensity: 0.6});
  const m = new THREE.Mesh(new THREE.BoxGeometry(0.42, 1, 0.42), mat); m.castShadow = true; m.receiveShadow = true;
  m.position.set(X[i], 0.16, 0); m.geometry.translate(0, 0.5, 0); m.scale.y = 0.001; m.userData.i = i; group.add(m); return m; });
function paint(i, tone) { const m = pillars[i].material; m.color.setHex(COLOR[tone]); m.emissive.setHex(EMIS[tone]); }
// callouts + leader lines
const callsEl = $('calls'), lines = $('lines'), svgNS = 'http://www.w3.org/2000/svg';
const calls = COLS.map((c, i) => { const d = document.createElement('div'); d.className = 'call'; d.dataset.i = i; callsEl.appendChild(d); return d; });
const segs = COLS.map(() => { const l = document.createElementNS(svgNS, 'line'); lines.appendChild(l); const c = document.createElementNS(svgNS, 'circle'); c.setAttribute('r', 3); lines.appendChild(c); return [l, c]; });
// ---- the story: four beats per slide
const BEATS = [['day 0', 3400], ['fixnext', 2600], ['later', 3000], ['verdict', 2600]];
let cur = 0, beat = -1, bt0 = 0, target = [0.001, 0.001, 0.001, 0.001], hold = false, hover = -1;
const prog = $('prog'); SL.forEach(() => prog.appendChild(document.createElement('i')));
const beatsEl = $('beats'); BEATS.forEach(([name], i) => { const s = document.createElement('span'); s.innerHTML = `<i></i>${name}`; s.addEventListener('click', () => setBeat(i)); beatsEl.appendChild(s); });
const fmtRank = r => '#' + Number(r).toLocaleString();
const cardEl = i => $('k' + i);
function setCards(cls0, cls1, cls2) { ['k0', 'k1', 'k2'].forEach((k, i) => { $(k).className = 'card ' + [cls0, cls1, cls2][i]; }); }
function days(n, label, red) { $('days').innerHTML = `Day <b>${Number(n).toLocaleString()}</b> · ${label}`; $('days').className = red ? 'red' : ''; }
let dayAnim = null;
function countDays(to, label, red, ms) { if (dayAnim) cancelAnimationFrame(dayAnim); const t0 = performance.now();
  (function step(now) { const k = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - k, 3); days(Math.round(to * e), label, red && k > 0.98); if (k < 1) dayAnim = requestAnimationFrame(step); })(t0); }
function show(n) {
  cur = (n + SL.length) % SL.length; const s = SL[cur];
  $('count').textContent = String(cur + 1).padStart(2, '0') + ' / ' + String(SL.length).padStart(2, '0');
  $('title').textContent = s.title; $('sub').textContent = s.sub;
  Array.from(prog.children).forEach((el, i) => { el.className = i < cur ? 'done' : i === cur ? 'on' : ''; });
  COLS.forEach(([name, k], i) => { const r = s.ranks[k], inside = r <= CUT;
    calls[i].className = 'call'; calls[i].innerHTML = `${name} <b>${fmtRank(r)}</b><small>${s.notes[k]}</small><div class="more">${s.more[k] || ''}</div>`; calls[i].dataset.tone = i === 3 ? 'green' : (inside ? 'teal' : 'amber'); });
  s.cards.forEach((c, i) => { cardEl(i).innerHTML = `<i>0${i + 1}</i><b>${c[0]}</b><p>${c[1]}</p>`; });
  $('verdict').className = ''; $('verdict').textContent = s.verdict;
  pillars.forEach((m, i) => { target[i] = 0.001; paint(i, 'idle'); }); cutMat.opacity = 0.5; pulseMat.opacity = 0;
  setBeat(0);
}
function setBeat(b) {
  beat = b; bt0 = performance.now(); const s = SL[cur];
  Array.from(beatsEl.children).forEach((el, i) => { el.className = i < b ? 'done' : i === b ? 'on' : ''; el.style.setProperty('--p', i < b ? 1 : 0); });
  calls.forEach(c => c.classList.remove('show'));
  if (b === 0) { // day 0: the standard scores give their verdicts, one by one
    days(0, 'published', false); setCards('', 'amber', ''); $('verdict').className = '';
    pillars.forEach((m, i) => { target[i] = i < 3 ? H(s.ranks[COLS[i][1]]) : 0.001; paint(i, i < 3 ? calls[i].dataset.tone : 'idle'); });
    [0, 1, 2].forEach(i => setTimeout(() => { if (beat === 0) { calls[i].classList.add('show', calls[i].dataset.tone); } }, 500 + i * 800));
    cutMat.opacity = 0.5; pulseMat.opacity = 0;
  } else if (b === 1) { // FixNext reads it
    pillars.forEach((m, i) => { target[i] = H(s.ranks[COLS[i][1]]); paint(i, i < 3 ? calls[i].dataset.tone : 'green'); });
    [0, 1, 2].forEach(i => calls[i].classList.add('show', calls[i].dataset.tone)); setCards('on', '', '');
    setTimeout(() => { if (beat === 1) { calls[3].classList.add('show', 'green'); cutMat.opacity = 1; } }, 900);
    days(0, 'FixNext ranks it ' + fmtRank(s.ranks.fixnext), false);
  } else if (b === 2) { // later: exploited (or, for 2026, the clock is running)
    pillars.forEach((m, i) => { target[i] = H(s.ranks[COLS[i][1]]); });
    calls.forEach((c, i) => c.classList.add('show', c.dataset.tone));
    if (s.kind === 'catch') { countDays(s.lag, 'exploited — on CISA KEV', true, 2200); setCards('', '', 'red'); pulseT0 = performance.now(); }
    else { countDays(s.days_since, 'since publication — judges count exploitation by Nov 4', false, 2200); setCards('', '', 'on'); }
  } else { // verdict
    pillars.forEach((m, i) => { if (i < 3 && s.kind === 'catch') target[i] = 0.1; });
    calls.forEach((c, i) => { if (i < 3 && s.kind === 'catch') c.classList.remove('show'); });
    $('verdict').className = 'show'; setCards('on', '', s.kind === 'catch' ? 'red' : 'on');
  }
}
let pulseT0 = -1;
$('prev').addEventListener('click', () => show(cur - 1)); $('next').addEventListener('click', () => show(cur + 1));
let keyPaused = false;
window.addEventListener('keydown', e => { if (e.key === 'ArrowRight') show(cur + 1); else if (e.key === 'ArrowLeft') show(cur - 1);
  else if (e.key === ' ') { keyPaused = !keyPaused; $('hint').textContent = keyPaused ? 'paused · space to resume' : 'hover a pillar · drag to orbit'; e.preventDefault(); }
  else if (e.key >= '1' && e.key <= '4') setBeat(Number(e.key) - 1); });
wrap.addEventListener('pointerdown', () => { try { window.focus(); } catch (e) {} });
$('cards').addEventListener('pointerenter', () => hold = true); $('cards').addEventListener('pointerleave', () => hold = false);
callsEl.addEventListener('pointerenter', () => hold = true, true); callsEl.addEventListener('pointerleave', () => hold = false, true);
cv.addEventListener('pointerdown', () => hold = true); window.addEventListener('pointerup', () => { hold = false; });
// hover links: card ↔ pillars ↔ callouts
const CARD_PILLARS = [[3], [0, 1, 2], []];
[0, 1, 2].forEach(i => { cardEl(i).addEventListener('pointerenter', () => setHover(CARD_PILLARS[i])); cardEl(i).addEventListener('pointerleave', () => setHover([])); });
calls.forEach((c, i) => { c.addEventListener('pointerenter', () => setHover([i])); c.addEventListener('pointerleave', () => setHover([])); });
function setHover(idx) { hover = idx.length ? idx[0] : -1;
  calls.forEach((c, i) => { c.classList.toggle('big', idx.includes(i)); c.classList.toggle('dim', idx.length > 0 && !idx.includes(i)); });
  pillars.forEach((m, i) => { m.material.emissiveIntensity = idx.includes(i) ? 1.6 : 0.6; });
  [0, 1, 2].forEach(k => cardEl(k).style.outline = (idx.length && CARD_PILLARS[k].some(p => idx.includes(p))) ? '1px solid rgba(243,239,231,.35)' : ''); }
const ray = new THREE.Raycaster(), mouse = new THREE.Vector2(-9, -9);
cv.addEventListener('pointermove', e => { const r = cv.getBoundingClientRect(); mouse.x = ((e.clientX - r.left) / r.width) * 2 - 1; mouse.y = -((e.clientY - r.top) / r.height) * 2 + 1; });
cv.addEventListener('pointerleave', () => { mouse.set(-9, -9); setHover([]); });
function resize() { const w = wrap.clientWidth || 800, h = wrap.clientHeight || 560; renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix(); lines.setAttribute('viewBox', `0 0 ${w} ${h}`); }
new ResizeObserver(resize).observe(wrap); resize();
const v = new THREE.Vector3();
function place(i, m) {
  const w = wrap.clientWidth, h = wrap.clientHeight; v.set(0, m.scale.y, 0); m.localToWorld(v); v.project(camera);
  const px = (v.x * 0.5 + 0.5) * w, py = (-v.y * 0.5 + 0.5) * h;
  const left = i < 2, lx = left ? Math.max(118, w * 0.16) : Math.min(w - 118, w * 0.84), ly = h * (i % 2 === 0 ? 0.36 : 0.52);
  const el = calls[i]; el.style.left = lx + 'px'; el.style.top = ly + 'px';
  const bw = el.offsetWidth / 2, ex = left ? lx + bw : lx - bw, on = el.classList.contains('show');
  const [l, c] = segs[i]; l.setAttribute('x1', ex); l.setAttribute('y1', ly); l.setAttribute('x2', px); l.setAttribute('y2', py); c.setAttribute('cx', px); c.setAttribute('cy', py);
  l.style.opacity = on ? 1 : 0; c.style.opacity = on ? 1 : 0;
}
let lastHit = -1;
function tick(now) { requestAnimationFrame(tick);
  pillars.forEach((m, i) => { const d = target[i] - m.scale.y; m.scale.y += d * (d < 0 ? 0.16 : 0.07); });
  if (pulseT0 > 0) { const k = (now - pulseT0) / 1400; if (k < 1) { pulse.scale.setScalar(1 + k * 1.6); pulseMat.opacity = 0.55 * (1 - k); } else { pulseMat.opacity = 0; pulseT0 = -1; } }
  if (beat === 1 || beat === 2) cutRing.material.opacity = 0.75 + 0.25 * Math.sin(now / 250);
  const el = now - bt0, dur = BEATS[beat] ? BEATS[beat][1] : 3000;
  if (beatsEl.children[beat]) beatsEl.children[beat].style.setProperty('--p', Math.min(1, el / dur));
  if (!hold && !keyPaused && el > dur) { if (beat < BEATS.length - 1) setBeat(beat + 1); else show(cur + 1); }
  // hover on pillars
  ray.setFromCamera(mouse, camera); const hit = ray.intersectObjects(pillars)[0]; const hi = hit ? hit.object.userData.i : -1;
  if (hi !== lastHit) { lastHit = hi; setHover(hi >= 0 ? [hi] : []); cv.style.cursor = hi >= 0 ? 'pointer' : 'grab'; }
  controls.autoRotate = hi < 0; controls.update(); pillars.forEach((m, i) => place(i, m)); renderer.render(scene, camera); }
show(0); requestAnimationFrame(tick);
</script></body></html>"""


def stage_slides(exp, catches, ranked):
    """One slide per exploited CVE the standard scores buried, plus the #1 CVE of 2026."""
    slides = []
    today = pd.Timestamp.today().normalize()
    if exp is not None and catches is not None:
        only = exp[exp["bucket"] == "FixNext only"].sort_values("rank_fixnext")
        extra = catches.set_index("cve_id")
        for _, r in only.iterrows():
            c = extra.loc[r["cve_id"]] if r["cve_id"] in extra.index else {}
            name = str(r["kev_name"]).replace(" Vulnerability", "").split(" Using ")[0]
            epss = float(c.get("epss", float("nan"))); cvss = float(c.get("cvss3_score", float("nan"))); lag = c.get("lag_days", None)
            cwe = short(str(c.get("cwe_name", "")), 44)
            sev = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
            slides.append({
                "kind": "catch", "title": name, "sub": f'{r["cve_id"]} · {r["kev_vendor"]} · {c.get("cwe_name", "")}', "lag": int(lag) if lag == lag else 0,
                "ranks": {"cvss": int(r["rank_cvss"]), "epss": int(r["rank_epss"]), "flags": int(r["rank_flags_epss"]), "fixnext": int(r["rank_fixnext"])},
                "notes": {"cvss": f"CVSS {cvss:.1f} {sev} — not in the 500", "epss": f"EPSS {epss:.3f} — says ignore", "flags": "no exploit code — says ignore", "fixnext": "inside the top 500 — fix next"},
                "more": {"cvss": f"Severity measures how bad an attack could be, not whether anyone will bother. Thousands of CVEs score higher; this one lands at #{int(r['rank_cvss']):,}.",
                         "epss": f"EPSS put the chance of exploitation at {epss * 100:.1f}%. Ranked by EPSS it sits at #{int(r['rank_epss']):,} — far outside anyone's patch window.",
                         "flags": f"No Exploit-DB, Metasploit, Nuclei or GitHub proof of concept existed at publish, so the exploit-code-first ranking fell back to EPSS: #{int(r['rank_flags_epss']):,}.",
                         "fixnext": f"Issuer {r['kev_vendor']}, weakness type {cwe}, and a description that resembles CVEs attackers already used — together they put it at #{int(r['rank_fixnext']):,}."},
                "verdict": f"Only FixNext would have fixed it before day {int(lag) if lag == lag else '?'}.",
                "cards": [["What the model saw", f"Issued by {r['kev_vendor']}; weakness type {cwe}; description resembles CVEs attackers already used."],
                          ["What the standard scores said", f"EPSS {epss:.3f}, rank #{int(r['rank_epss']):,}. No exploit code. CVSS {cvss:.1f}. Every standard ranking left it outside the top 500."],
                          ["What happened", f"Added to CISA's Known Exploited Vulnerabilities list {int(lag)} days after publication." if lag == lag else "Later confirmed exploited by CISA."]],
            })
    if ranked is not None and not ranked.empty:
        slides.append(slide_2026(ranked.iloc[0], today))
    return slides


def slide_2026(r, today, picked=False):
    """A 2026 CVE on the stage: its rank under each method, the signals as explanations, the Granite rationale."""
    if True:
        rk = lambda k: int(r[k]) if not is_blank(r.get(k)) else RMAX_2026
        pub = pd.to_datetime(r.get("published"), errors="coerce")
        since = int((today - pub.normalize()).days) if pub == pub else 0
        rank = int(r["rank"])
        return {
            "kind": "2026", "title": (f'#{rank:,} of 2026 — ' if not picked else f'Your pick · #{rank:,} of 2026 — ') + short(str(r.get("cwe_name", "")), 40),
            "sub": f'{r["cve_id"]} · {r.get("vendor_guess", "")} · published {pub.date() if pub == pub else "2026"}',
            "lag": 0, "days_since": since,
            "ranks": {"cvss": rk("cvss_rank"), "epss": rk("epss_rank"), "flags": rk("flags_rank"), "fixnext": int(r["rank"])},
            "notes": {"cvss": f"CVSS {fmt(r.get('cvss3_score'), '{:.1f}')}" + (" — not in the 500" if rk("cvss_rank") > 500 else ""),
                      "epss": f"EPSS {fmt(r.get('epss'), '{:.3f}')}" + (" — says ignore" if rk("epss_rank") > 500 else ""),
                      "flags": (flag_text(r) or "no exploit code") + (" — says ignore" if rk("flags_rank") > 500 else ""),
                      "fixnext": f"score {fmt(r.get('score'))} — " + ("top of the list" if rank == 1 else "inside the top 500" if rank <= 500 else "outside the top 500")},
            "more": {"cvss": "Where CVSS severity alone would rank it among the 72,670.", "epss": "Where the industry's probability score alone would rank it.",
                     "flags": "Where exploit-code-first, then EPSS, would rank it.", "fixnext": short(str(r.get("top_reasons", "")), 160)},
            "verdict": "Top of the list. Fix this next." if rank == 1 else (f"FixNext: fix it — #{rank:,} of 72,670." if rank <= 500 else f"FixNext: not in the 500 — #{rank:,} of 72,670."),
            "cards": [["What the model saw", short(str(r.get("top_reasons", "")) or "Issuer, weakness type, exploit signals and Granite similarity.", 150)],
                      ["Why fix this next" if rank <= 500 else "Why it can wait", short(str(r.get("rationale", "")) or "No Granite rationale for this CVE (written for the top 100).", 170)],
                      ["Status", f"Ranked #{rank:,} of 72,670 by FixNext. Judges count whether it is exploited by November 4, 2026."]],
        }


RMAX_2026 = 72_670


def stage(exp, catches, ranked, height=580, picked=None):
    slides = stage_slides(exp, catches, ranked)
    if picked is not None:
        slides.insert(0, slide_2026(picked, pd.Timestamp.today().normalize(), picked=True))
    if not slides:
        return
    html_doc = STAGE_HTML.replace("__SLIDES__", json.dumps(slides))
    if hasattr(st, "iframe"):            # Streamlit ≥ 1.67; components.html is deprecated
        st.iframe(html_doc, height=height)
    else:
        components.html(html_doc, height=height, scrolling=False)


def hero(bt):
    s = backtest_summary(bt)
    ours500, base500 = s.get("hits_at_500", (0, 0))
    ours100, base100 = s.get("hits_at_100", (0, 0))
    with st.container(key="ffstage"):
        pool = ranked.head(500)
        names = {r["cve_id"]: f'#{int(r["rank"])} · {r["cve_id"]} · {r.get("vendor_guess", "")} · {short(str(r.get("cwe_name", "")), 30)}' for _, r in pool.iterrows()}
        pick = st.selectbox("Put any CVE on the stage", ["—"] + list(names), format_func=lambda k: names.get(k, "Put any CVE of the top 500 on the stage…"),
                            key="stage_pick", label_visibility="collapsed")
        picked = pool[pool["cve_id"] == pick].iloc[0] if pick != "—" else None
        stage(exploited, catches, ranked, picked=picked)
    with st.container(key="ffhero"):
        left, right = st.columns([7, 5], gap="large")
        left.html(
            '<div class="ff-hero-text"><p class="ff-eyebrow">Vulnerability triage — Sheridan Datathon 2026 · IBM track</p>'
            '<h1>The vulnerabilities attackers will actually use.<br><span>Scored, ranked, explained.</span></h1>'
            f'<p class="ff-note">{SCORED_TOTAL:,} CVEs published in 2026, ranked by how likely attackers are to use them — from the description, '
            'who issued it, the weakness type and the exploit signals, read by IBM Granite. '
            f'Tested on 2025: {ours500} of the {s["positives"]} later-exploited CVEs land in our top 500; the best industry ranking finds {base500}. '
            f'In the top 100: {ours100} vs {base100}.</p></div>'
        )
        with right:
            right.html('<p class="ff-hero-side">Start here</p>')
            c1, c2 = st.columns(2)
            c1.button("Open the Fix-Next list", on_click=open_page, args=("Fix-Next List",), key="ffcta1", type="primary", use_container_width=True)
            submission = ranked.head(500)[["cve_id"]].to_csv(index=False)
            c2.download_button("Download top500.csv", data=submission, file_name="top500.csv", mime="text/csv", key="ffcta2", use_container_width=True)
            st.html('<p class="ff-hero-cap">Hosted at fixnext.select · code and model card on GitHub · "Ask FixNext" in the corner answers questions about any CVE.</p>')


SLOPE_VIEWS = {
    "FixNext caught, EPSS missed": lambda d: d["bucket"] == "FixNext only",
    "Everything FixNext caught": lambda d: d["rank_fixnext"] <= 500,
    "Missed by every ranking": lambda d: d["bucket"] == "missed by all",
    "All 39": lambda d: d["cve_id"].notna(),
}


def slope_panel():
    """The back-test as a small chart with controls: which CVEs to light up, which rankings to compare, one CVE to follow."""
    if exploited is None or exploited.empty:
        return
    df = exploited
    with st.container(key="ffslope"):
        chart_heading("Where each ranking put the CVEs attackers used in 2025",
                      f"{len(df)} CVEs published Jan–Jun 2025 and later confirmed exploited. One line each; higher = ranked closer to #1.")
        c1, c2 = st.columns([7, 5], gap="medium")
        view = c1.segmented_control("Light up", list(SLOPE_VIEWS), key="slope_view", default="FixNext caught, EPSS missed")
        compare = c2.segmented_control("Compare", ["EPSS vs FixNext", "All four rankings"], key="slope_cmp", default="EPSS vs FixNext")
        view = view or "FixNext caught, EPSS missed"
        lit = set(df.loc[SLOPE_VIEWS[view](df), "cve_id"])
        cols = [("rank_epss", "EPSS first"), ("rank_fixnext", "FixNext")] if compare != "All four rankings" else SLOPE_COLS
        chart_col, read_col = st.columns([8, 4], gap="large")
        with read_col:
            names = {r["cve_id"]: f'{r["cve_id"]} · {short(str(r["kev_name"]).replace(" Vulnerability", ""), 34)}' for _, r in df.sort_values("rank_fixnext").iterrows()}
            pick = st.selectbox("Follow one CVE", ["—"] + list(names), format_func=lambda k: names.get(k, k), key="slope_focus")
            focus = None if pick == "—" else pick
            if focus:
                r = df.set_index("cve_id").loc[focus]
                st.html('<div class="ff-read"><b>' + esc(str(r["kev_name"]).replace(" Vulnerability", "")) + '</b>'
                        + ''.join(f'<span>{esc(nm)}<b>#{int(r[c]):,}</b></span>' for c, nm in SLOPE_COLS)
                        + '<p>' + ("Inside FixNext's top 500." if r["rank_fixnext"] <= 500 else "Outside FixNext's top 500 — a miss we show.") + '</p></div>')
            else:
                n_lit = len(lit); n_in = int((df.loc[df["cve_id"].isin(lit), "rank_fixnext"] <= 500).sum())
                st.html('<div class="ff-read"><b>How to read it</b>'
                        + ('<p>Each line is one CVE that attackers went on to use. Left: where EPSS ranked it on the day. Right: where FixNext ranked it. '
                           if compare != "All four rankings" else
                           '<p>Each line is one CVE that attackers went on to use, read left to right: CVSS first, EPSS first, exploit code then EPSS, FixNext. ')
                        + 'Above the dashed line means inside the top 500 — the ones that get fixed.</p>'
                        f'<p><em>{n_lit}</em> lit up · <em>{n_in}</em> of them inside FixNext\'s top 500 · hover a line for its name.</p></div>')
        with chart_col:
            labels_for = SLOPE_LABELS if view == "FixNext caught, EPSS missed" else None
            st.markdown(slope_chart(df, cols, lit, focus=focus, labels_for=labels_for), unsafe_allow_html=True)
            st.html('<p class="ff-hero-cap">Per-CVE ranks come from a re-fit of the frozen model; it places one borderline CVE (#458) inside the cut that the '
                    'frozen back-test did not — 20 here, 19 in the headline. The other three columns reconcile exactly.</p>')


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

# Stable Flash first (fast, least congested), then the newest Flash, then Flash-Lite. Quota is per model,
# so a 429 on one still leaves the next one. Names from aistudio.google.com/docs/models (Nov 2026).
GEMINI_MODELS = ["gemini-3.6-flash", "gemini-3.8-flash", "gemini-3.5-flash-lite"]


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
    client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=60_000))  # ms — Cloud → Google is slower than a laptop; never hang the page
    errs = []
    prompt = f"CONTEXT:\n{context}\n\nQUESTION: {question}"
    for model in GEMINI_MODELS:
        # Gemini 3.x models "think" before answering, which is slow and eats the output budget, so thinking
        # is set to its minimum (3.x uses thinking_level; thinking_budget was the 2.x knob). If a model
        # rejects that, the second config asks again with the model's default.
        configs = [
            types.GenerateContentConfig(system_instruction=SYSTEM_RULES, temperature=0.2, max_output_tokens=1024,
                                        thinking_config=types.ThinkingConfig(thinking_level=types.ThinkingLevel.MINIMAL)),
            types.GenerateContentConfig(system_instruction=SYSTEM_RULES, temperature=0.2, max_output_tokens=1024),
        ]
        for i, cfg in enumerate(configs):
            try:
                r = client.models.generate_content(model=model, contents=prompt, config=cfg)
                text = (r.text or "").strip()
                if text:
                    return text + f"\n\n*{model}*"
                fr = r.candidates[0].finish_reason if r.candidates else "no candidates"
                errs.append(f"{model}#{i}: empty answer ({fr})")
            except Exception as e:  # try the next config / model name, but say what happened
                errs.append(f"{model}#{i}: {type(e).__name__} {str(e)[:150]}")
                if "Timeout" in type(e).__name__ or "timed out" in str(e).lower():  # network problem: other models won't help
                    return f"Gemini didn't answer in time ({type(e).__name__}). Try again in a few seconds."
                if getattr(e, "code", None) in (404, 429, 500, 503, 504):
                    break   # unknown model / quota / overloaded: the other config won't help, so don't spend a call on it
    return "Gemini didn't answer — " + " | ".join(errs)


def ask_panel(key, context_fn, placeholder, examples):
    """A question box backed by Gemini, in its own card. Shows a short note when no key is configured."""
    with st.container(key=f"ffask_{key}"):
        st.html('<div class="ff-ask-head"><h2>Ask FixNext</h2><span class="ff-ask-chip">Google Gemini</span></div>'
                '<p class="ff-ask-sub">Answers come only from FixNext\'s own numbers and findings — nothing outside the project.</p>')
        if not gemini_key():
            st.html('<p class="ff-ask-note">Available on the hosted app (fixnext.streamlit.app) and when running locally with GEMINI_API_KEY set. '
                    'The in-browser version at fixnext.select keeps no API key.</p>')
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
                model = ""
                if answer.rstrip().endswith("*") and "\n\n*" in answer:
                    answer, model = answer.rsplit("\n\n*", 1)
                    model = model.rstrip("*")
                paras = "".join(f"<p>{esc(x.strip())}</p>" for x in answer.split("\n") if x.strip())
                meta = f'<div class="ff-answer-meta"><i></i>{esc(model)}</div>' if model else ""
                st.html(f'<div class="ff-answer">{paras}{meta}</div>')


CHAT_QUICK = {
    "Overview": ["Why does FixNext beat EPSS?", "What did it catch that EPSS missed?", "Which vendors dominate the top 500?"],
    "Fix-Next List": ["What's the EPSS rank column?", "How do I get the top 500 file?", "Why are so many low-EPSS CVEs here?"],
    "CVE Detail": ["Why is it ranked above its EPSS?", "What does an attacker gain?", "Which exploited CVEs does it resemble?"],
    "Methodology": ["How was it tested?", "What does the model refuse to use?", "How is IBM Granite used?"],
}


def _chat_submit():
    q = st.session_state.get("ffchat_in", "").strip()
    if not q:
        return
    st.session_state["ffchat_in"] = ""
    st.session_state["ffchat_pending"] = q


def _chat_quick(q):
    st.session_state["ffchat_pending"] = q


def floating_chat(current_page, context_fn):
    """A small chat pinned to the bottom-right corner on every page. Hidden entirely when no key is set."""
    if not gemini_key():
        return
    if "ffchat_open" not in st.session_state:
        st.session_state["ffchat_open"] = False
    msgs = st.session_state.setdefault("ffchat_msgs", [])

    if not st.session_state["ffchat_open"]:
        with st.container(key="ffchat_fab"):
            if st.button("Ask FixNext", key="ffchat_openbtn"):
                st.session_state["ffchat_open"] = True
                st.rerun()
        return

    with st.container(key="ffchat"):
        with st.container(key="ffchat_head"):
            head, hide = st.columns([8, 1])
            head.html('<div class="ff-chat-head"><b>Ask FixNext</b><span class="ff-ask-chip">Google Gemini</span></div>')
            with hide:
                with st.container(key="ffchat_hide"):
                    if st.button("–", key="ffchat_closebtn", help="Hide the chat"):
                        st.session_state["ffchat_open"] = False
                        st.rerun()

        pending = st.session_state.pop("ffchat_pending", None)
        if pending:
            msgs.append(("user", pending, ""))
            with st.spinner("Asking Gemini…"):
                answer = ask_gemini(pending, context_fn()) or "No answer."
            model = ""
            if answer.rstrip().endswith("*") and "\n\n*" in answer:
                answer, model = answer.rsplit("\n\n*", 1)
                model = model.rstrip("*")
            msgs.append(("bot", answer, model))
            del msgs[:-12]   # keep the last 6 exchanges

        if msgs:
            log = "".join(
                f'<div class="ff-msg {role}">{esc(text)}{f"<small>{esc(model)}</small>" if role == "bot" and model else ""}</div>'
                for role, text, model in msgs
            )
            st.html(f'<div class="ff-chat-log">{log}</div>')
        else:
            st.html('<p class="ff-chat-empty">Ask anything about the ranking, the model, or the CVE you\'re looking at. '
                    'Answers use only FixNext\'s own numbers.</p>')

        quick = CHAT_QUICK.get(current_page, CHAT_QUICK["Overview"])
        if not msgs:   # quick questions only until the conversation starts, to keep the panel short
            with st.container(key="ffchat_quick"):
                for q in quick:
                    st.button(q, key=f"ffchat_q_{abs(hash(q)) % 100_000}", on_click=_chat_quick, args=(q,), width="stretch")
        st.text_input("Ask", key="ffchat_in", placeholder="Type a question and press Enter", label_visibility="collapsed", on_change=_chat_submit)


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

def filter_mask(df, s):
    """The current filters as a boolean mask (from session state, so it can be counted before the widgets draw)."""
    mask = pd.Series(True, index=df.index)
    pick = s.get("f_pick")
    if pick in QUICK_PICKS:
        mask &= QUICK_PICKS[pick][1](df)
    if s.get("f_rank") in RANK_STEPS:
        mask &= df["rank"] <= RANK_STEPS[s["f_rank"]]
    if s.get("f_epss") in EPSS_STEPS:
        mask &= df["epss"] < EPSS_STEPS[s["f_epss"]]
    if s.get("f_vendor"):
        mask &= df["vendor_guess"].isin(s["f_vendor"])
    if s.get("f_cwe"):
        mask &= df["cwe_name"].isin(s["f_cwe"])
    if s.get("f_month"):
        mask &= df["snapshot_month"].isin(s["f_month"])
    if s.get("f_sev"):
        mask &= df["cvss3_severity"].isin(s["f_sev"])
    if s.get("f_exploit"):
        mask &= df["has_exploit"]
    q = (s.get("f_query") or "").strip()
    if q:
        mask &= df["cve_id"].str.contains(q, case=False, regex=False, na=False) | df["description"].str.contains(q, case=False, regex=False, na=False)
    return mask


def filter_panel(df):
    """The Filters button in the header and its pop-up panel (closes with X or a click outside).
    Nothing picked means 'all'. Quick picks are one-tap stories; chips carry counts; the footer says how many match."""
    ss = st.session_state
    active = sum(1 for k in FILTER_KEYS if ss.get(k) and ss.get(k) not in ("All 5,000", "Any"))
    label = f"Filters · {active}" if active else "Filters"
    n_match = int(filter_mask(df, ss).sum())
    with st.popover(label, icon=":material/filter_alt:", type="primary" if active else "secondary", key="fffilters"):
        st.html(
            '<div class="ff-pop-head"><div><b>Filters</b>'
            '<span class="ff-muted"> · Overview and Fix-Next List</span></div>'
            f'<button type="button" class="ff-x" data-ff-close aria-label="Close filters">{icon("close")}</button></div>'
        )
        st.html('<p class="ff-pop-label">Quick picks</p>')
        pick = st.pills("Quick picks", list(QUICK_PICKS), selection_mode="single", key="f_pick", label_visibility="collapsed",
                        format_func=lambda k: f"{k} ({int(QUICK_PICKS[k][1](df).sum()):,})")
        if pick in QUICK_PICKS:
            st.html(f'<p class="ff-pop-hint">{esc(QUICK_PICKS[pick][0])}</p>')
        query = st.text_input("Search", key="f_query", placeholder="CVE id or a word from the description", icon=":material/search:")

        left, right = st.columns(2, gap="medium")
        left.html('<p class="ff-pop-label">FixNext rank</p>')
        left.pills("FixNext rank", list(RANK_STEPS), selection_mode="single", key="f_rank", label_visibility="collapsed")
        right.html('<p class="ff-pop-label">EPSS at most</p>')
        right.pills("EPSS at most", list(EPSS_STEPS), selection_mode="single", key="f_epss", label_visibility="collapsed",
                    format_func=lambda k: f"{k} ({int((df['epss'] < EPSS_STEPS[k]).sum()):,})" if k != "Any" else "Any")

        sev_counts = df["cvss3_severity"].value_counts()
        sev_values = [x for x in SEVERITY_ORDER if x in sev_counts.index] + sorted(set(sev_counts.index) - set(SEVERITY_ORDER))
        st.html('<p class="ff-pop-label">Severity</p>')
        st.pills("Severity", sev_values, selection_mode="multi", key="f_sev", label_visibility="collapsed",
                 format_func=lambda x: f":{SEV_MD.get(x, 'gray')}[●] {str(x).title()} ({sev_counts[x]:,})")
        st.toggle(f"Only CVEs with public exploit code ({int(df['has_exploit'].sum()):,})", key="f_exploit")

        vendor_counts = df["vendor_guess"].value_counts()
        vendor_options = [v for v in vendor_counts.index if v != "other"] + (["other"] if "other" in vendor_counts else [])
        cwe_counts = df["cwe_name"].value_counts()
        cwe_ids = df.drop_duplicates("cwe_name").set_index("cwe_name")["cwe_primary"]
        left, right = st.columns(2, gap="medium")
        left.html('<p class="ff-pop-label">Vendor</p>')
        left.multiselect("Vendor", vendor_options, key="f_vendor", placeholder="All vendors", label_visibility="collapsed",
                         format_func=lambda v: f"{v} ({vendor_counts[v]:,})")
        right.html('<p class="ff-pop-label">Weakness type</p>')
        right.multiselect("Weakness type", cwe_counts.index.tolist(), key="f_cwe", placeholder="All weakness types", label_visibility="collapsed",
                          format_func=lambda n: f"{cwe_label(n, cwe_ids.get(n), limit=48)} ({cwe_counts[n]:,})")

        month_counts = df["snapshot_month"].value_counts()
        st.html('<p class="ff-pop-label">Published in</p>')
        st.pills("Published in", sorted(month_counts.index), selection_mode="multi", key="f_month", label_visibility="collapsed",
                 format_func=lambda m: f"{month_label(m)[:3]} ({month_counts[m]:,})")

        foot_l, foot_r = st.columns([3, 1], vertical_alignment="center")
        foot_l.html(f'<p class="ff-pop-count"><b>{n_match:,}</b> of {len(df):,} CVEs match' + (f' · {active} filter{"s" if active != 1 else ""} on' if active else ' · no filters on') + '</p>')
        if active:
            foot_r.button("Reset", on_click=clear_filters, icon=":material/restart_alt:", key="ff_reset", use_container_width=True)

    return df[filter_mask(df, ss)]


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
        slope_panel()

        eyebrow = "Rank 1 — fix this next" if int(first["rank"]) == 1 else f"Rank {int(first['rank']):,} — top of your filters"
        cve_card(first, eyebrow)
        st.button("Open in CVE Detail", on_click=open_detail, args=(first["cve_id"],))

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

        if True:
            ask_panel("ov", project_context, "e.g. Why does FixNext beat EPSS? Which vendors dominate the top 500?",
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
            st.button("Open the full list", on_click=open_page, args=("Fix-Next List",))

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

    cve_card(row, f"Rank {int(row['rank']):,} — score {fmt(row['score'])}", with_signals=False, with_similar=True)

    rationale = str(row["rationale"]).strip()
    body = esc(rationale) if rationale else '<span class="ff-pending">Granite rationale pending for this CVE</span>'
    st.html(f'<div class="ff-box"><h2>Why fix this next</h2><p>{body}</p></div>')
    vs_strip(row)
    how_model_sees(row)
    ask_panel("cve", lambda: project_context() + "\n\n" + cve_context(row),
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

if page == "CVE Detail" and "row" in globals():
    floating_chat(page, lambda: project_context() + "\n\n" + cve_context(row))
else:
    floating_chat(page, project_context)
