"""Train the FixNext model, back-test vs baselines, and rank the 2026 scoreboard.

Runnable as `python -m src.train`. Reads outputs/features.parquet, the pre-2024
exposure-rate tables in outputs/history/, and the IBM Granite description
embeddings in data/granite_embeddings.npy (+ _ids.csv). Writes backtest.md,
ranked_2026.csv, top500.csv, importances.csv, model.pkl.

MSG-008 (DEV-ENGINE): IBM Granite embeddings (ibm-granite/granite-embedding-
small-english-r2, 384-d, L2-normalised) reduced with PCA(32) -> gr0..gr31 as the
text signal. TEXT_MODE in {tfidf, granite, both}. USE_HISTORY default False
(MSG-010 decision: history gave no lift). Features never include
pub_month/published, config.FORBIDDEN_COLS, or cvss3_source.
"""
import pickle
from functools import lru_cache

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD, PCA

from .config import DATA, OUT

# ---- shipping configuration -------------------------------------------------
USE_HISTORY = False          # MSG-010: history features off by default (no lift)
TEXT_MODE = "granite"        # {"tfidf", "granite", "both"}; default granite (IBM tech)
# -----------------------------------------------------------------------------

CVSS_CATS = [
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality_impact",
    "integrity_impact", "availability_impact",
]
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]

HIST_DIR = OUT / "history"
BASE_RATE = 0.0062
HIST_COLS = [
    "hist_assigner_rate", "hist_assigner_n", "hist_cwe_rate",
    "hist_vendor_rate", "hist_severity_rate", "hist_av_rate",
]
TXT_COLS = [f"txt{i}" for i in range(16)]
GR_COLS = [f"gr{i}" for i in range(32)]

LGBM_PARAMS = dict(
    n_estimators=300, learning_rate=0.03, num_leaves=8, min_child_samples=40,
    subsample=0.8, subsample_freq=1, colsample_bytree=0.5, reg_lambda=5,
    scale_pos_weight=20, random_state=0, verbose=-1,
)
LGBM_PARAMS_BIG = dict(LGBM_PARAMS, num_leaves=15, n_estimators=500, min_child_samples=25)

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


@lru_cache(maxsize=1)
def load_embeddings():
    emb = np.load(DATA / "granite_embeddings.npy")          # (N, 384) float16
    ids = pd.read_csv(DATA / "granite_embeddings_ids.csv")["cve_id"].astype(str).tolist()
    return emb, {c: i for i, c in enumerate(ids)}


def granite_matrix(cve_ids):
    emb, idx = load_embeddings()
    missing = [c for c in cve_ids if c not in idx]
    print(f"[granite] {len(cve_ids)} rows, {len(missing)} cve_ids missing from embeddings")
    assert not missing, f"{len(missing)} cve_ids missing from embeddings (e.g. {missing[:3]})"
    return emb[[idx[c] for c in cve_ids]].astype(np.float32)


def build_superset(df, fit_mask):
    """Build every feature (numeric, history, categorical, txt, gr) once; callers
    slice the columns they want with select(). Encoders/PCA fit on fit_mask only."""
    fit = df[fit_mask]
    X = pd.DataFrame(index=df.index)

    X["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    X["cvss3_score"] = pd.to_numeric(df["cvss3_score"], errors="coerce")
    X["desc_len"] = pd.to_numeric(df["desc_len"], errors="coerce").fillna(0)
    for c in FLAGS:
        X[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    X["any_flag"] = X[FLAGS].max(axis=1)
    kw_cols = [c for c in df.columns if c.startswith("kw_")]
    for c in kw_cols:
        X[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)

    # history (built always; included in a config only when use_history)
    H = load_history()
    X["hist_assigner_rate"] = df["assigner"].map(H["assigner_rate"]).fillna(BASE_RATE)
    X["hist_assigner_n"] = pd.to_numeric(df["assigner"].map(H["assigner_n"]), errors="coerce").fillna(0).astype(int)
    X["hist_cwe_rate"] = df["cwe_primary"].map(H["cwe_rate"]).fillna(BASE_RATE)
    vg = df["vendor_guess"].where(df["vendor_guess"] != "other")
    X["hist_vendor_rate"] = vg.map(H["vendor_rate"]).fillna(BASE_RATE)
    sev = pd.to_numeric(df["cvss3_score"], errors="coerce").map(cvss_severity)
    X["hist_severity_rate"] = sev.map(H["severity_rate"]).fillna(BASE_RATE)
    X["hist_av_rate"] = df["attack_vector"].map(H["av_rate"]).fillna(BASE_RATE)

    cat_cols = []
    for c in CVSS_CATS + ["vendor_guess"]:
        X[c] = pd.Categorical(df[c], categories=sorted(fit[c].dropna().unique()))
        cat_cols.append(c)
    for c, n in [("assigner", 150), ("cwe_primary", 60)]:
        top = fit[c].value_counts().head(n).index
        vals = df[c].where(df[c].isin(top), "other")
        X[c] = pd.Categorical(vals, categories=sorted(set(top) | {"other"}))
        cat_cols.append(c)

    # txt: TF-IDF -> SVD(16), fit on fit set
    desc = df["description"].fillna("")
    tf = TfidfVectorizer(max_features=30000, ngram_range=(1, 2), min_df=5, sublinear_tf=True)
    tf.fit(desc[fit_mask])
    svd = TruncatedSVD(n_components=16, random_state=0)
    svd.fit(tf.transform(desc[fit_mask]))
    Z = svd.transform(tf.transform(desc))
    for i in range(16):
        X[f"txt{i}"] = Z[:, i]

    # gr: Granite 384-d -> PCA(32), fit on fit set
    G = granite_matrix(df["cve_id"].tolist())
    pca = PCA(n_components=32, random_state=0)
    pca.fit(G[fit_mask])
    Zg = pca.transform(G)
    for i in range(32):
        X[f"gr{i}"] = Zg[:, i]

    return X, cat_cols, kw_cols


def select(X, kw_cols, text_mode, use_history, drop_kw=()):
    base_num = ["epss", "cvss3_score", "desc_len"] + FLAGS + ["any_flag"] + \
               [c for c in kw_cols if c not in drop_kw]
    cols = list(base_num)
    if use_history:
        cols += HIST_COLS
    cols += CVSS_CATS + ["vendor_guess", "assigner", "cwe_primary"]
    if text_mode in ("tfidf", "both"):
        cols += TXT_COLS
    if text_mode in ("granite", "both"):
        cols += GR_COLS
    return X[cols]


def fit_model(X, y, cat_cols, params=LGBM_PARAMS):
    m = lgb.LGBMClassifier(**params)
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


def main():
    df = pd.read_parquet(OUT / "features.parquet")
    df["y"] = pd.to_numeric(df["y"], errors="coerce").astype(int)

    # ---------- validation back-test ----------
    ev = df[df["split"].isin(["train", "valid"])].copy().reset_index(drop=True)
    Xs, cat_cols, kw_cols = build_superset(ev, (ev["split"] == "train").values)
    tr = (ev["split"] == "train").values
    va = (ev["split"] == "valid").values
    ytr = ev["y"].values[tr]
    drop_kw = [c for c in ["kw_exploited", "kw_in_the_wild"] if c in kw_cols]

    def proba(text_mode, use_history=False, drop=(), params=LGBM_PARAMS):
        Xc = select(Xs, kw_cols, text_mode, use_history, drop)
        m = fit_model(Xc[tr], ytr, cat_cols, params)
        return m.predict_proba(Xc[va])[:, 1]

    Xva = Xs[va]
    fte = flags_then_epss(Xva).values
    f = pd.DataFrame({"y": ev["y"].values[va]})
    f["cvss_first"] = Xva["cvss3_score"].values
    f["epss_first"] = Xva["epss"].values
    f["flags_then_epss"] = fte
    f["model"] = proba("tfidf")
    f["model_ablation"] = proba("tfidf", drop=drop_kw)
    f["model_history"] = proba("tfidf", use_history=True)
    f["model_granite"] = proba("granite")
    f["model_both"] = proba("both")
    p_gbig = proba("granite", params=LGBM_PARAMS_BIG)
    rp = lambda s: pd.Series(s).rank(pct=True).values
    rfte = rp(fte)
    for name, col in [("blend", "model"), ("blend_history", "model_history"),
                      ("blend_granite", "model_granite"), ("blend_both", "model_both")]:
        f[name] = rp(f[col].values) + rfte
    f["blend_granite_big"] = rp(p_gbig) + rfte
    pos_valid = int(f["y"].sum())

    rows = ["cvss_first", "epss_first", "flags_then_epss", "model", "blend",
            "model_ablation", "model_history", "blend_history",
            "model_granite", "blend_granite", "model_both", "blend_both",
            "blend_granite_big"]
    h = {r: {k: hits_at_k(f, r, k) for k in (50, 100, 500)} for r in rows}

    # rule pick among blend variants
    col = {"tfidf": "blend", "granite": "blend_granite", "both": "blend_both", "granite_big": "blend_granite_big"}
    H = lambda key, k: h[col[key]][k]
    base_keys = ["tfidf", "granite", "both"]
    best500 = max(H(k, 500) for k in base_keys)
    best100 = max(H(k, 100) for k in base_keys)
    keys = list(base_keys)
    if H("granite_big", 500) > best500 and H("granite_big", 100) > best100:
        keys.append("granite_big")
    pref = {"granite": 3, "granite_big": 2, "both": 1, "tfidf": 0}
    choice = max(keys, key=lambda k: (H(k, 500), H(k, 100), pref[k]))
    # required-IBM-tech preference: ship granite if it is not worse at @500 AND @100
    if not choice.startswith("granite") and H("granite", 500) >= H(choice, 500) and H("granite", 100) >= H(choice, 100):
        choice = "granite"
    if choice.startswith("granite") and H(choice, 500) > max(H("tfidf", 500), H("both", 500)):
        case = f"Granite is strictly best at hits@500 ({H(choice,500)}); shipped on merit."
    elif choice.startswith("granite") and H("granite", 500) >= H("tfidf", 500) and H("granite", 100) >= H("tfidf", 100):
        case = ("Granite is not worse than TF-IDF at @500 and @100; shipped as the required IBM technology "
                "(more defensible than TF-IDF on 67 positives).")
    elif choice.startswith("granite"):
        case = "Granite shipped by rule tiebreak."
    else:
        case = f"Granite is worse at @500/@100; shipped {choice} instead."

    text_mode = "granite" if choice in ("granite", "granite_big") else choice
    params = LGBM_PARAMS_BIG if choice == "granite_big" else LGBM_PARAMS

    # ---------- final model: refit on train+valid+late, score 2026 ----------
    fit_mask = df["split"].isin(["train", "valid", "late"]).values
    Xs2, cat2, kw2 = build_superset(df, fit_mask)
    Xf = select(Xs2, kw2, text_mode, USE_HISTORY)
    final = fit_model(Xf[fit_mask], df["y"].values[fit_mask], cat2, params)

    sc = (df["split"] == "score").values
    p_sc = final.predict_proba(Xf[sc])[:, 1]
    fte_sc = flags_then_epss(Xs2[sc]).values
    raw = pd.Series(p_sc).rank(pct=True).values + pd.Series(fte_sc).rank(pct=True).values  # blend
    span = raw.max() - raw.min()
    score01 = (raw - raw.min()) / span if span > 0 else np.zeros_like(raw)

    out = df[sc].copy().reset_index(drop=True)
    out["score"] = score01
    wk = pd.read_csv(DATA / "weakness_types.csv", usecols=["cwe_id", "name"], dtype=str)
    out["cwe_name"] = out["cwe_primary"].map(dict(zip(wk["cwe_id"], wk["name"]))).fillna("Unknown")
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
    with open(OUT / "model.pkl", "wb") as fh:
        pickle.dump(final, fh)

    # ---------- backtest.md ----------
    label = {
        "cvss_first": "CVSS first", "epss_first": "EPSS first",
        "flags_then_epss": "Flags then EPSS",
        "model": "FixNext model (TF-IDF)", "blend": "Blend (TF-IDF)",
        "model_ablation": "model ablation (no kw_exploited / kw_in_the_wild)",
        "model_history": "FixNext model + history", "blend_history": "Blend + history",
        "model_granite": "FixNext model (Granite)", "blend_granite": "Blend (Granite)",
        "model_both": "FixNext model (TF-IDF + Granite)", "blend_both": "Blend (TF-IDF + Granite)",
        "blend_granite_big": "Blend (Granite, bigger model)",
    }
    lines = [
        f"# FixNext back-test -- valid split (2025-01..2025-06), positives available: {pos_valid}",
        "",
        "| ranking | hits@50 | hits@100 | hits@500 |",
        "|---|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(f"| {label[r]} | {h[r][50]} | {h[r][100]} | {h[r][500]} |")
    lines += [
        "",
        "HQ reference (valid, hits@500): CVSS 5 | EPSS 11 | Flags-then-EPSS 17 | quick LightGBM 14-16.",
        "",
        f"**Chosen 2026 ranking rule: blend ({text_mode}"
        + (", bigger model" if choice == "granite_big" else "") + ")**. "
        + f"Candidates (blend) hits@500/@100: tfidf={H('tfidf',500)}/{H('tfidf',100)}, "
        + f"granite={H('granite',500)}/{H('granite',100)}, both={H('both',500)}/{H('both',100)}, "
        + f"granite_big={H('granite_big',500)}/{H('granite_big',100)}. {case}",
        "",
        "## Column provenance (feature -> raw source)",
        "",
        "Granite: ibm-granite/granite-embedding-small-english-r2, 384-d L2-normalised embeddings of "
        "vulnerabilities.description -> PCA(32) fit on the fit set (train for the back-test; "
        "train+valid+late for the final) -> gr0..gr31.",
        "TF-IDF: TruncatedSVD(16) of TF-IDF(1-2 gram) of vulnerabilities.description -> txt0..txt15.",
        "History (USE_HISTORY=False by default; ablation rows only): pre-2024 KEV rates, "
        "window 2019-01-01..2023-12-31, label date_added <= 2023-12-31, base_rate 0.0062.",
        "",
        "| feature | raw source |",
        "|---|---|",
        "| epss | scoreboard_2026.epss (2026) / exploit_signals.epss at publish month (2024-25) |",
        "| exploitdb, metasploit, nuclei, poc_github, any_flag | snapshot-month exploit flags (any_flag = max) |",
        "| cvss3_score | vulnerabilities.cvss3_score |",
        "| attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact | vulnerabilities.<same column> |",
        "| assigner (top 150), cwe_primary (first id of cwe_ids, top 60), vendor_guess (first vendor kw in description) | vulnerabilities.assigner / cwe_ids / description |",
        "| desc_len, kw_* | length / lowercase substring flags on vulnerabilities.description |",
        "| gr0..gr31 | PCA(32) of Granite 384-d embeddings of vulnerabilities.description |",
        "| txt0..txt15 | TruncatedSVD(16) of TF-IDF of vulnerabilities.description |",
        "| hist_* (ablation only) | outputs/history/*.csv pre-2024 KEV rates keyed by assigner/cwe/vendor/severity/attack_vector |",
        "| y (label, training only) | known_exploited.date_added > publish month-end |",
        "",
        "Not used as features: pub_month/published, nvd_status, n_references, n_affected_cpes, last_modified, cvss3_source, references.csv, affected_products.csv.",
        "",
    ]
    md = "\n".join(lines)
    (OUT / "backtest.md").write_text(md)

    print(md)
    print(f"\nshipped: blend / text_mode={text_mode} / params={'big' if choice=='granite_big' else 'default'} "
          f"/ USE_HISTORY={USE_HISTORY}")
    print(f"ranked_2026.csv rows: {len(ranked)}   top500.csv rows: 500")
    print("\nTop 15 feature importances:")
    print(imp.head(15).to_string(index=False))
    print("\nTop 10 ranked_2026 rows:")
    show = ranked.head(10)[["cve_id", "score", "vendor_guess", "cwe_name", "epss", "top_reasons"]].copy()
    show["score"] = show["score"].round(4)
    print(show.to_string(index=False))


if __name__ == "__main__":
    main()
