"""Train the FixNext model, back-test vs baselines, and rank the 2026 scoreboard.

Runnable as `python -m src.train`. Reads outputs/features.parquet, the pre-2024
exposure-rate tables in outputs/history/, and the IBM Granite description
embeddings in data/granite_embeddings.npy (+ _ids.csv). Writes backtest.md,
ranked_2026.csv, top500.csv, importances.csv, similar_exploited.csv, model.pkl.

MSG-014 (DEV-ENGINE): Granite embeddings used two ways -- PCA(32) -> gr0..gr31
(TEXT_MODE), and kNN "resembles a known-exploited CVE" features (gr_knn_*),
leakage-safe in time: reference set = KEV CVEs with date_added <= cutoff that
have an embedding (t=2024-12-31 for the back-test, 2025-12-31 for 2026 scoring),
a row's own cve_id excluded from its neighbours. USE_HISTORY default False
(MSG-010). Features never include pub_month/published, config.FORBIDDEN_COLS, or
cvss3_source.
"""
import pickle
from functools import lru_cache

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD, PCA

from .config import DATA, OUT

USE_HISTORY = False
TEXT_MODE = "granite"

CVSS_CATS = [
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality_impact",
    "integrity_impact", "availability_impact",
]
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]

HIST_DIR = OUT / "history"
BASE_RATE = 0.0062
HIST_COLS = ["hist_assigner_rate", "hist_assigner_n", "hist_cwe_rate",
             "hist_vendor_rate", "hist_severity_rate", "hist_av_rate"]
TXT_COLS = [f"txt{i}" for i in range(16)]
GR_COLS = [f"gr{i}" for i in range(32)]
KNN_COLS = ["gr_knn_max", "gr_knn_top5", "gr_knn_cnt90"]

KNN_T_BACKTEST = "2024-12-31"   # reference cutoff for labelled (train/valid/late) rows
KNN_T_FINAL = "2025-12-31"      # reference cutoff for 2026 score rows
KNN_SIM_THRESH = 0.90

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
    emb = np.load(DATA / "granite_embeddings.npy")
    ids = pd.read_csv(DATA / "granite_embeddings_ids.csv")["cve_id"].astype(str).tolist()
    return emb, {c: i for i, c in enumerate(ids)}


def granite_matrix(cve_ids):
    emb, idx = load_embeddings()
    missing = [c for c in cve_ids if c not in idx]
    print(f"[granite] {len(cve_ids)} rows, {len(missing)} missing from embeddings")
    assert not missing, f"{len(missing)} cve_ids missing from embeddings (e.g. {missing[:3]})"
    return emb[[idx[c] for c in cve_ids]].astype(np.float32)


def kev_ref_ids(t):
    """KEV cve_ids with date_added <= t that have a Granite embedding."""
    kev = pd.read_csv(DATA / "known_exploited.csv", usecols=["cve_id", "date_added"], dtype=str)
    kev["d"] = pd.to_datetime(kev["date_added"], errors="coerce")
    ids = kev[kev["d"] <= pd.Timestamp(t)]["cve_id"].astype(str).tolist()
    _, idx = load_embeddings()
    return [c for c in ids if c in idx]


def _sim_chunks(query_ids, ref_ids):
    """Yield (start, S) cosine-similarity blocks of query vs ref, self-masked."""
    emb, idx = load_embeddings()
    R = emb[[idx[c] for c in ref_ids]].astype(np.float32)        # (|R|, 384), L2-normalised
    ref_pos = {c: j for j, c in enumerate(ref_ids)}
    Q = emb[[idx[c] for c in query_ids]].astype(np.float32)
    for s in range(0, len(query_ids), 20000):
        qc = query_ids[s:s + 20000]
        S = Q[s:s + 20000] @ R.T                                 # cosine (vectors are unit-norm)
        for i, c in enumerate(qc):
            if c in ref_pos:
                S[i, ref_pos[c]] = -1.0                          # exclude own cve_id
        yield s, S


def knn_feats(query_ids, ref_ids):
    out = np.zeros((len(query_ids), 3), dtype=np.float32)
    for s, S in _sim_chunks(query_ids, ref_ids):
        out[s:s + S.shape[0], 0] = S.max(axis=1)
        k = min(5, S.shape[1])
        out[s:s + S.shape[0], 1] = np.partition(S, -k, axis=1)[:, -k:].mean(axis=1)
        out[s:s + S.shape[0], 2] = (S >= KNN_SIM_THRESH).sum(axis=1)
    return out


def attach_knn(df):
    """Add gr_knn_* columns: labelled rows vs R(2024-12-31), score rows vs R(2025-12-31)."""
    df = df.copy()
    ref_bt = kev_ref_ids(KNN_T_BACKTEST)
    ref_fin = kev_ref_ids(KNN_T_FINAL)
    for c in KNN_COLS:
        df[c] = np.nan
    lab = df["split"].isin(["train", "valid", "late"]).values
    sco = (df["split"] == "score").values
    if lab.any():
        df.loc[lab, KNN_COLS] = knn_feats(df.loc[lab, "cve_id"].tolist(), ref_bt)
    if sco.any():
        df.loc[sco, KNN_COLS] = knn_feats(df.loc[sco, "cve_id"].tolist(), ref_fin)
    return df, len(ref_bt), len(ref_fin)


def top_neighbours(query_ids, ref_ids, k=3):
    ref_arr = np.array(ref_ids)
    rows = [None] * len(query_ids)
    for s, S in _sim_chunks(query_ids, ref_ids):
        kk = min(k, S.shape[1])
        order = np.argsort(-S, axis=1)[:, :kk]
        for i in range(S.shape[0]):
            cols = order[i]
            rows[s + i] = list(zip(ref_arr[cols].tolist(), S[i, cols].round(4).tolist()))
    return rows


def build_superset(df, fit_mask):
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
    for c in KNN_COLS:
        if c in df.columns:
            X[c] = pd.to_numeric(df[c], errors="coerce")

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

    desc = df["description"].fillna("")
    tf = TfidfVectorizer(max_features=30000, ngram_range=(1, 2), min_df=5, sublinear_tf=True)
    tf.fit(desc[fit_mask])
    svd = TruncatedSVD(n_components=16, random_state=0)
    svd.fit(tf.transform(desc[fit_mask]))
    Z = svd.transform(tf.transform(desc))
    for i in range(16):
        X[f"txt{i}"] = Z[:, i]

    G = granite_matrix(df["cve_id"].tolist())
    pca = PCA(n_components=32, random_state=0)
    pca.fit(G[fit_mask])
    Zg = pca.transform(G)
    for i in range(32):
        X[f"gr{i}"] = Zg[:, i]

    return X, cat_cols, kw_cols


def select(X, kw_cols, text_mode, use_history, use_knn=False, drop_kw=()):
    cols = ["epss", "cvss3_score", "desc_len"] + FLAGS + ["any_flag"] + \
           [c for c in kw_cols if c not in drop_kw]
    if use_knn:
        cols += [c for c in KNN_COLS if c in X.columns]
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
    return int(frame.sort_values(col, ascending=False, na_position="last", kind="mergesort").head(k)["y"].sum())


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
    df, n_ref_bt, n_ref_fin = attach_knn(df)
    print(f"[knn] usable KEV reference: R({KNN_T_BACKTEST})={n_ref_bt}, R({KNN_T_FINAL})={n_ref_fin}")

    # ---------- validation back-test ----------
    ev = df[df["split"].isin(["train", "valid"])].copy().reset_index(drop=True)
    Xs, cat_cols, kw_cols = build_superset(ev, (ev["split"] == "train").values)
    tr = (ev["split"] == "train").values
    va = (ev["split"] == "valid").values
    ytr = ev["y"].values[tr]
    drop_kw = [c for c in ["kw_exploited", "kw_in_the_wild"] if c in kw_cols]

    def proba(text_mode, use_history=False, use_knn=False, drop=(), params=LGBM_PARAMS):
        Xc = select(Xs, kw_cols, text_mode, use_history, use_knn, drop)
        m = fit_model(Xc[tr], ytr, cat_cols, params)
        return m.predict_proba(Xc[va])[:, 1]

    Xva = Xs[va]
    fte = flags_then_epss(Xva).values
    rp = lambda s: pd.Series(s).rank(pct=True).values
    rfte = rp(fte)
    f = pd.DataFrame({"y": ev["y"].values[va]})
    f["cvss_first"] = Xva["cvss3_score"].values
    f["epss_first"] = Xva["epss"].values
    f["flags_then_epss"] = fte
    f["model"] = proba("tfidf")
    f["model_ablation"] = proba("tfidf", drop=drop_kw)
    f["model_history"] = proba("tfidf", use_history=True)
    f["model_granite"] = proba("granite")
    f["model_both"] = proba("both")
    f["model_knn"] = proba("tfidf", use_knn=True)
    p_gbig = proba("granite", params=LGBM_PARAMS_BIG)
    for name, col in [("blend", "model"), ("blend_history", "model_history"),
                      ("blend_granite", "model_granite"), ("blend_both", "model_both"),
                      ("blend_knn", "model_knn")]:
        f[name] = rp(f[col].values) + rfte
    f["blend_granite_big"] = rp(p_gbig) + rfte
    pos_valid = int(f["y"].sum())

    rows = ["cvss_first", "epss_first", "flags_then_epss", "model", "blend",
            "model_ablation", "model_history", "blend_history",
            "model_granite", "blend_granite", "model_both", "blend_both",
            "blend_granite_big", "model_knn", "blend_knn"]
    h = {r: {k: hits_at_k(f, r, k) for k in (50, 100, 500)} for r in rows}

    # rule: ship kNN blend only if not worse than current TF-IDF blend at @500 AND @100
    ship_knn = h["blend_knn"][500] >= 19 and h["blend_knn"][100] >= 14
    use_knn_final = ship_knn
    shipped = "blend (TF-IDF + Granite kNN)" if ship_knn else "blend (TF-IDF)"
    rule_note = (f"Blend (TF-IDF + Granite kNN) hits@500/@100 = {h['blend_knn'][500]}/{h['blend_knn'][100]}; "
                 f"threshold is >=19 AND >=14. "
                 + ("Meets it -> ship kNN blend." if ship_knn else "Does not meet it -> ship plain TF-IDF blend."))

    # ---------- final model: refit on train+valid+late, score 2026 ----------
    fit_mask = df["split"].isin(["train", "valid", "late"]).values
    Xs2, cat2, kw2 = build_superset(df, fit_mask)
    Xf = select(Xs2, kw2, "tfidf", USE_HISTORY, use_knn=use_knn_final)
    final = fit_model(Xf[fit_mask], df["y"].values[fit_mask], cat2)

    sc = (df["split"] == "score").values
    p_sc = final.predict_proba(Xf[sc])[:, 1]
    fte_sc = flags_then_epss(Xs2[sc]).values
    raw = pd.Series(p_sc).rank(pct=True).values + pd.Series(fte_sc).rank(pct=True).values
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

    # ---------- similar_exploited.csv: top-3 R(2025-12-31) neighbours for the top 500 ----------
    top_ids = ranked["cve_id"].head(500).tolist()
    nb = top_neighbours(top_ids, kev_ref_ids(KNN_T_FINAL), k=3)
    se_rows = []
    for cid, neigh in zip(top_ids, nb):
        neigh = (neigh + [("", "")] * 3)[:3]
        se_rows.append([cid, neigh[0][0], neigh[0][1], neigh[1][0], neigh[1][1], neigh[2][0], neigh[2][1]])
    pd.DataFrame(se_rows, columns=["cve_id", "neighbour_1_cve", "neighbour_1_sim", "neighbour_2_cve",
                                   "neighbour_2_sim", "neighbour_3_cve", "neighbour_3_sim"]
                 ).to_csv(OUT / "similar_exploited.csv", index=False)

    # ---------- backtest.md ----------
    label = {
        "cvss_first": "CVSS first", "epss_first": "EPSS first", "flags_then_epss": "Flags then EPSS",
        "model": "FixNext model (TF-IDF)", "blend": "Blend (TF-IDF)",
        "model_ablation": "model ablation (no kw_exploited / kw_in_the_wild)",
        "model_history": "FixNext model + history", "blend_history": "Blend + history",
        "model_granite": "FixNext model (Granite)", "blend_granite": "Blend (Granite)",
        "model_both": "FixNext model (TF-IDF + Granite)", "blend_both": "Blend (TF-IDF + Granite)",
        "blend_granite_big": "Blend (Granite, bigger model)",
        "model_knn": "FixNext model (TF-IDF + Granite kNN)", "blend_knn": "Blend (TF-IDF + Granite kNN)",
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
        f"**FROZEN ranking rule: {shipped}.** {rule_note}",
        "",
        "## Column provenance (feature -> raw source)",
        "",
        "Granite embeddings: ibm-granite/granite-embedding-small-english-r2, 384-d L2-normalised, of "
        "vulnerabilities.description. Two uses: (a) PCA(32) fit on the fit set -> gr0..gr31 (TEXT_MODE); "
        "(b) kNN gr_knn_* features below.",
        f"Granite kNN: cosine similarity to the reference set R(t) = KEV CVEs (known_exploited.date_added "
        f"<= t) that have an embedding, own cve_id excluded. t = {KNN_T_BACKTEST} for labelled rows "
        f"(train/valid/late; R={n_ref_bt}), t = {KNN_T_FINAL} for 2026 score rows (R={n_ref_fin}). "
        f"gr_knn_max = max sim; gr_knn_top5 = mean of top-5 sims; gr_knn_cnt90 = count of sims >= {KNN_SIM_THRESH}.",
        "History (USE_HISTORY=False; ablation rows only): pre-2024 KEV rates, 2019-01-01..2023-12-31, "
        "label cutoff 2023-12-31, base_rate 0.0062.",
        "",
        "| feature | raw source |",
        "|---|---|",
        "| epss | scoreboard_2026.epss (2026) / exploit_signals.epss at publish month (2024-25) |",
        "| exploitdb, metasploit, nuclei, poc_github, any_flag | snapshot-month exploit flags (any_flag = max) |",
        "| cvss3_score | vulnerabilities.cvss3_score |",
        "| attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact | vulnerabilities.<same column> |",
        "| assigner (top 150), cwe_primary (first id of cwe_ids, top 60), vendor_guess (first vendor kw) | vulnerabilities.assigner / cwe_ids / description |",
        "| desc_len, kw_* | length / lowercase substring flags on vulnerabilities.description |",
        "| gr0..gr31 | PCA(32) of Granite 384-d embeddings of vulnerabilities.description |",
        "| gr_knn_max, gr_knn_top5, gr_knn_cnt90 | cosine similarity of the Granite embedding to R(t) KEV CVEs |",
        "| txt0..txt15 | TruncatedSVD(16) of TF-IDF of vulnerabilities.description |",
        "| hist_* (ablation only) | outputs/history/*.csv pre-2024 KEV rates |",
        "| y (label, training only) | known_exploited.date_added > publish month-end |",
        "",
        "Not used as features: pub_month/published, nvd_status, n_references, n_affected_cpes, last_modified, cvss3_source, references.csv, affected_products.csv.",
        "",
    ]
    md = "\n".join(lines)
    (OUT / "backtest.md").write_text(md)

    print(md)
    print(f"\nFROZEN shipped: {shipped} (use_knn={use_knn_final})")
    print(f"ranked_2026.csv rows: {len(ranked)}   top500.csv rows: 500   similar_exploited.csv rows: {len(se_rows)}")
    print("\nTop 15 feature importances:")
    print(imp.head(15).to_string(index=False))
    print("\nsimilar_exploited.csv (first 3 rows):")
    print(pd.read_csv(OUT / "similar_exploited.csv").head(3).to_string(index=False))


if __name__ == "__main__":
    main()
