"""Train the FixNext model, back-test vs baselines, and rank the 2026 scoreboard.

Runnable as `python -m src.train`. Reads outputs/features.parquet (from
build_features.py) and the pre-2024 exposure-rate tables in outputs/history/.
Writes:
  outputs/backtest.md        -- valid hits@100/500 table (with/without history) + provenance
  outputs/ranked_2026.csv    -- full 2026 ranking (David's dashboard contract)
  outputs/top500.csv         -- first 500 cve_id (submission)
  outputs/importances.csv    -- top 25 feature importances of the final model
  outputs/model.pkl          -- the final model (gitignored)

MSG-010 (DEV-ENGINE). TF-IDF+SVD text features stand in for Granite embeddings
(MSG-008). History features are strictly pre-2024 constants (see
outputs/history/history_README.md). Features never include pub_month/published,
anything in config.FORBIDDEN_COLS, or cvss3_source.
"""
import pickle
from functools import lru_cache

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD

from .config import DATA, OUT

CVSS_CATS = [
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality_impact",
    "integrity_impact", "availability_impact",
]
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]

HIST_DIR = OUT / "history"
BASE_RATE = 0.0062  # overall pre-2024 KEV rate (history_README.md)
HIST_COLS = [
    "hist_assigner_rate", "hist_assigner_n", "hist_cwe_rate",
    "hist_vendor_rate", "hist_severity_rate", "hist_av_rate",
]

LGBM_PARAMS = dict(
    n_estimators=300, learning_rate=0.03, num_leaves=8, min_child_samples=40,
    subsample=0.8, subsample_freq=1, colsample_bytree=0.5, reg_lambda=5,
    scale_pos_weight=20, random_state=0, verbose=-1,
)

RANKED_COLS = [
    "rank", "cve_id", "score", "published", "snapshot_month", "vendor_guess",
    "cwe_primary", "cwe_name", "cvss3_score", "cvss3_severity", "attack_vector",
    "epss", "exploitdb", "metasploit", "nuclei", "poc_github", "assigner",
    "top_reasons", "rationale", "description",
]


def cvss_severity(x):
    if pd.isna(x):
        return ""
    if x >= 9:
        return "CRITICAL"
    if x >= 7:
        return "HIGH"
    if x >= 4:
        return "MEDIUM"
    if x > 0:
        return "LOW"
    return ""


@lru_cache(maxsize=1)
def load_history():
    """Pre-2024 exposure-rate lookup tables (constants, not fit on train data)."""
    def rate_map(fname, key, val="rate"):
        t = pd.read_csv(HIST_DIR / fname, dtype={key: str})
        return dict(zip(t[key].astype(str), t[val]))
    return {
        "assigner_rate": rate_map("assigner_rates.csv", "assigner"),
        "assigner_n": rate_map("assigner_rates.csv", "assigner", "cves"),
        "cwe_rate": rate_map("cwe_rates.csv", "cwe_primary"),
        "vendor_rate": rate_map("vendor_kw_rates.csv", "keyword"),
        "severity_rate": rate_map("severity_rates.csv", "cvss3_severity"),
        "av_rate": rate_map("attack_vector_rates.csv", "attack_vector"),
    }


def build_X(df, fit_mask):
    """Feature matrix for every row in df; fit-set encoders use fit_mask rows only.

    History features (hist_*) are constants from pre-2024 tables, identical for
    every split (no fitting), appended after the keyword flags.
    """
    fit = df[fit_mask]
    X = pd.DataFrame(index=df.index)

    # numeric (epss + cvss3_score keep NaN; model handles it)
    X["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    X["cvss3_score"] = pd.to_numeric(df["cvss3_score"], errors="coerce")
    X["desc_len"] = pd.to_numeric(df["desc_len"], errors="coerce").fillna(0)
    for c in FLAGS:
        X[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    X["any_flag"] = X[FLAGS].max(axis=1)
    for c in [c for c in df.columns if c.startswith("kw_")]:
        X[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)

    # history exposure rates (pre-2024 constants; "other"/missing -> base_rate)
    H = load_history()
    X["hist_assigner_rate"] = df["assigner"].map(H["assigner_rate"]).fillna(BASE_RATE)
    X["hist_assigner_n"] = pd.to_numeric(df["assigner"].map(H["assigner_n"]), errors="coerce").fillna(0).astype(int)
    X["hist_cwe_rate"] = df["cwe_primary"].map(H["cwe_rate"]).fillna(BASE_RATE)
    vg = df["vendor_guess"].where(df["vendor_guess"] != "other")
    X["hist_vendor_rate"] = vg.map(H["vendor_rate"]).fillna(BASE_RATE)
    sev = pd.to_numeric(df["cvss3_score"], errors="coerce").map(cvss_severity)
    X["hist_severity_rate"] = sev.map(H["severity_rate"]).fillna(BASE_RATE)
    X["hist_av_rate"] = df["attack_vector"].map(H["av_rate"]).fillna(BASE_RATE)

    # categorical (categories fixed from the fit set)
    cat_cols = []
    for c in CVSS_CATS + ["vendor_guess"]:
        cats = sorted(fit[c].dropna().unique())
        X[c] = pd.Categorical(df[c], categories=cats)
        cat_cols.append(c)
    for c, n in [("assigner", 150), ("cwe_primary", 60)]:
        top = fit[c].value_counts().head(n).index
        vals = df[c].where(df[c].isin(top), "other")
        X[c] = pd.Categorical(vals, categories=sorted(set(top) | {"other"}))
        cat_cols.append(c)

    # text: TF-IDF -> TruncatedSVD(16), fit on fit set, transform all
    desc = df["description"].fillna("")
    tf = TfidfVectorizer(max_features=30000, ngram_range=(1, 2), min_df=5, sublinear_tf=True)
    tf.fit(desc[fit_mask])
    svd = TruncatedSVD(n_components=16, random_state=0)
    svd.fit(tf.transform(desc[fit_mask]))
    Z = svd.transform(tf.transform(desc))
    for i in range(16):
        X[f"txt{i}"] = Z[:, i]

    return X, cat_cols


def no_hist(X):
    return X.drop(columns=[c for c in HIST_COLS if c in X.columns])


def fit_model(X, y, cat_cols):
    m = lgb.LGBMClassifier(**LGBM_PARAMS)
    m.fit(X, y, categorical_feature=[c for c in cat_cols if c in X.columns])
    return m


def flags_then_epss(X):
    return X["any_flag"] * 10 + X["epss"].fillna(0)


def hits_at_k(frame, col, k):
    top = frame.sort_values(col, ascending=False, na_position="last", kind="mergesort").head(k)
    return int(top["y"].sum())


def top_reasons(row):
    out = []
    e = pd.to_numeric(row["epss"], errors="coerce")
    if pd.notna(e) and e > 0.05:
        out.append(f"EPSS {e:.2f}")
    if int(row["poc_github"]) == 1:
        out.append("public PoC on GitHub")
    if int(row["metasploit"]) == 1:
        out.append("Metasploit module")
    if int(row["nuclei"]) == 1:
        out.append("Nuclei template")
    if int(row["exploitdb"]) == 1:
        out.append("Exploit-DB entry")
    if row["vendor_guess"] != "other":
        out.append(f"high-exposure vendor ({row['vendor_guess']})")
    if row["attack_vector"] == "NETWORK":
        out.append("network-reachable")
    return "; ".join(out[:4])


PROVENANCE = """## Column provenance (feature -> raw source)

History tables are strictly pre-2024: CVEs published 2019-01-01..2023-12-31, KEV label date_added <= 2023-12-31, base_rate 0.0062.

| feature | raw source |
|---|---|
| epss | scoreboard_2026.epss (2026) / exploit_signals_20XX.epss at publish month (2024-25) |
| exploitdb, metasploit, nuclei, poc_github | same snapshot-month exploit flags |
| any_flag | max of the 4 flags |
| cvss3_score | vulnerabilities.cvss3_score |
| attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact | vulnerabilities.<same column> |
| assigner | vulnerabilities.assigner (top 150 in fit set, else 'other') |
| cwe_primary | first id of vulnerabilities.cwe_ids (top 60 in fit set, else 'other') |
| vendor_guess | first vendor keyword found in vulnerabilities.description |
| desc_len | length of vulnerabilities.description |
| kw_* | lowercase substring flags on vulnerabilities.description (ios/sap word-boundary) |
| txt0..txt15 | TruncatedSVD(16) of TF-IDF(1-2 gram) of vulnerabilities.description |
| hist_assigner_rate / hist_assigner_n | outputs/history/assigner_rates.csv (rate / cves), keyed by assigner |
| hist_cwe_rate | outputs/history/cwe_rates.csv.rate, keyed by cwe_primary |
| hist_vendor_rate | outputs/history/vendor_kw_rates.csv.rate, keyed by vendor_guess ('other'->base_rate) |
| hist_severity_rate | outputs/history/severity_rates.csv.rate, keyed by severity derived from cvss3_score |
| hist_av_rate | outputs/history/attack_vector_rates.csv.rate, keyed by attack_vector |
| y (label, training only) | known_exploited.date_added > publish month-end |
| split | derived from pub_month |

Not used as features: pub_month/published, nvd_status, n_references, n_affected_cpes, last_modified, cvss3_source, references.csv, affected_products.csv.
"""


def main():
    df = pd.read_parquet(OUT / "features.parquet")
    df["y"] = pd.to_numeric(df["y"], errors="coerce").astype(int)

    # ---------- validation back-test: fit on train (2024), score valid (2025 H1) ----------
    ev_df = df[df["split"].isin(["train", "valid"])].copy().reset_index(drop=True)
    Xev, cat_cols = build_X(ev_df, (ev_df["split"] == "train").values)
    tr = (ev_df["split"] == "train").values
    va = (ev_df["split"] == "valid").values
    ytr = ev_df["y"].values[tr]

    # model without history (reproduces the MSG-006 rows) and with history
    m_nohist = fit_model(no_hist(Xev)[tr], ytr, cat_cols)
    p_nohist = m_nohist.predict_proba(no_hist(Xev)[va])[:, 1]
    m_hist = fit_model(Xev[tr], ytr, cat_cols)
    p_hist = m_hist.predict_proba(Xev[va])[:, 1]
    # ablation: no-history, minus the two possibly-after-the-fact phrase flags
    drop_kw = [c for c in ["kw_exploited", "kw_in_the_wild"] if c in Xev.columns]
    m_abl = fit_model(no_hist(Xev)[tr].drop(columns=drop_kw), ytr, cat_cols)
    p_abl = m_abl.predict_proba(no_hist(Xev)[va].drop(columns=drop_kw))[:, 1]

    Xva = Xev[va]
    fte = flags_then_epss(Xva).values
    ev = pd.DataFrame({
        "y": ev_df["y"].values[va],
        "cvss_first": Xva["cvss3_score"].values,
        "epss_first": Xva["epss"].values,
        "flags_then_epss": fte,
        "model": p_nohist,
        "model_ablation": p_abl,
        "model_history": p_hist,
    })
    ev["blend"] = ev["model"].rank(pct=True) + ev["flags_then_epss"].rank(pct=True)
    ev["blend_history"] = ev["model_history"].rank(pct=True) + ev["flags_then_epss"].rank(pct=True)
    pos_valid = int(ev["y"].sum())

    rankings = ["cvss_first", "epss_first", "flags_then_epss", "model", "blend",
                "model_ablation", "model_history", "blend_history"]
    table = {r: {k: hits_at_k(ev, r, k) for k in (100, 500)} for r in rankings}

    # choose among the 4 candidates by valid hits@500; ties -> +history/blend variant
    priority = {"blend_history": 3, "model_history": 2, "blend": 1, "model": 0}
    candidates = ["model", "blend", "model_history", "blend_history"]
    choice = max(candidates, key=lambda c: (table[c][500], priority[c]))
    has_history = "history" in choice
    is_blend = "blend" in choice
    pretty = {"model": "model", "blend": "blend",
              "model_history": "model + history", "blend_history": "blend + history"}

    # ---------- final model: refit on all labelled rows (train+valid+late), score 2026 ----------
    fit_mask = df["split"].isin(["train", "valid", "late"]).values
    Xall, cat_cols2 = build_X(df, fit_mask)
    Xf = Xall if has_history else no_hist(Xall)
    final = fit_model(Xf[fit_mask], df["y"].values[fit_mask], cat_cols2)

    sc = (df["split"] == "score").values
    Xsc = Xf[sc]
    p_sc = final.predict_proba(Xsc)[:, 1]
    fte_sc = flags_then_epss(Xall[sc]).values
    if is_blend:
        raw = (pd.Series(p_sc).rank(pct=True) + pd.Series(fte_sc).rank(pct=True)).values
    else:
        raw = p_sc
    span = raw.max() - raw.min()
    score01 = (raw - raw.min()) / span if span > 0 else np.zeros_like(raw)

    out = df[sc].copy().reset_index(drop=True)
    out["score"] = score01
    wk = pd.read_csv(DATA / "weakness_types.csv", usecols=["cwe_id", "name"], dtype=str)
    name_map = dict(zip(wk["cwe_id"], wk["name"]))
    out["cwe_name"] = out["cwe_primary"].map(name_map).fillna("Unknown")
    out["cvss3_severity"] = pd.to_numeric(out["cvss3_score"], errors="coerce").map(cvss_severity)
    out["top_reasons"] = out.apply(top_reasons, axis=1)
    out["rationale"] = ""
    out["snapshot_month"] = out["pub_month"]
    out["published"] = pd.to_datetime(out["published"], errors="coerce").dt.strftime("%Y-%m-%d")
    out = out.sort_values("score", ascending=False, kind="mergesort").reset_index(drop=True)
    out["rank"] = np.arange(1, len(out) + 1)

    ranked = out[RANKED_COLS]
    ranked.to_csv(OUT / "ranked_2026.csv", index=False)
    ranked[["cve_id"]].head(500).to_csv(OUT / "top500.csv", index=False)

    imp = (pd.DataFrame({"feature": Xf.columns, "importance": final.feature_importances_})
           .sort_values("importance", ascending=False).reset_index(drop=True))
    imp.head(25).to_csv(OUT / "importances.csv", index=False)

    with open(OUT / "model.pkl", "wb") as f:
        pickle.dump(final, f)

    # ---------- backtest.md ----------
    label = {
        "cvss_first": "CVSS first", "epss_first": "EPSS first",
        "flags_then_epss": "Flags then EPSS", "model": "FixNext model (LightGBM)",
        "blend": "Blend (model + flags/EPSS)",
        "model_ablation": "model ablation (no kw_exploited / kw_in_the_wild)",
        "model_history": "FixNext model + history", "blend_history": "Blend + history",
    }
    lines = [
        f"# FixNext back-test -- valid split (2025-01..2025-06), positives available: {pos_valid}",
        "",
        "| ranking | hits@100 | hits@500 |",
        "|---|---:|---:|",
    ]
    for r in rankings:
        lines.append(f"| {label[r]} | {table[r][100]} | {table[r][500]} |")
    lines += [
        "",
        "HQ reference (valid, hits@500): CVSS 5 | EPSS 11 | Flags-then-EPSS 17 | quick LightGBM 14-16.",
        "",
        f"**Chosen 2026 ranking rule: {pretty[choice]}** "
        f"(valid hits@500 = {table[choice][500]}; candidates model={table['model'][500]}, "
        f"blend={table['blend'][500]}, model+history={table['model_history'][500]}, "
        f"blend+history={table['blend_history'][500]}; ties -> blend+history).",
        "",
        PROVENANCE,
    ]
    md = "\n".join(lines)
    (OUT / "backtest.md").write_text(md)

    print(md)
    print(f"\nranked_2026.csv rows: {len(ranked)}   top500.csv rows: 500   history in final model: {has_history}")
    print("\nTop 15 feature importances:")
    print(imp.head(15).to_string(index=False))
    print("\nTop 10 ranked_2026 rows:")
    show = ranked.head(10)[["cve_id", "score", "vendor_guess", "cwe_name", "epss", "top_reasons"]].copy()
    show["score"] = show["score"].round(4)
    print(show.to_string(index=False))


if __name__ == "__main__":
    main()
