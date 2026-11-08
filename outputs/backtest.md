# FixNext back-test -- valid split (2025-01..2025-06), positives available: 39

| ranking | hits@50 | hits@100 | hits@500 |
|---|---:|---:|---:|
| CVSS first | 3 | 4 | 6 |
| EPSS first | 3 | 7 | 11 |
| Flags then EPSS | 5 | 10 | 17 |
| FixNext model (TF-IDF) | 6 | 9 | 14 |
| Blend (TF-IDF) | 12 | 14 | 19 |
| model ablation (no kw_exploited / kw_in_the_wild) | 5 | 9 | 15 |
| FixNext model + history | 5 | 6 | 14 |
| Blend + history | 12 | 13 | 19 |
| FixNext model (Granite) | 6 | 8 | 13 |
| Blend (Granite) | 8 | 10 | 16 |
| FixNext model (TF-IDF + Granite) | 5 | 6 | 11 |
| Blend (TF-IDF + Granite) | 9 | 10 | 18 |
| Blend (Granite, bigger model) | 11 | 12 | 15 |
| FixNext model (TF-IDF + Granite kNN) | 4 | 6 | 13 |
| Blend (TF-IDF + Granite kNN) | 12 | 15 | 19 |

HQ reference (valid, hits@500): CVSS 5 | EPSS 11 | Flags-then-EPSS 17 | quick LightGBM 14-16.

**FROZEN ranking rule: blend (TF-IDF + Granite kNN).** Blend (TF-IDF + Granite kNN) hits@500/@100 = 19/15; threshold is >=19 AND >=14. Meets it -> ship kNN blend.

## Column provenance (feature -> raw source)

Granite embeddings: ibm-granite/granite-embedding-small-english-r2, 384-d L2-normalised, of vulnerabilities.description. Two uses: (a) PCA(32) fit on the fit set -> gr0..gr31 (TEXT_MODE); (b) kNN gr_knn_* features below.
Granite kNN: cosine similarity to the reference set R(t) = KEV CVEs (known_exploited.date_added <= t) that have an embedding, own cve_id excluded. t = 2024-12-31 for labelled rows (train/valid/late; R=125), t = 2025-12-31 for 2026 score rows (R=317). gr_knn_max = max sim; gr_knn_top5 = mean of top-5 sims; gr_knn_cnt90 = count of sims >= 0.9.
History (USE_HISTORY=False; ablation rows only): pre-2024 KEV rates, 2019-01-01..2023-12-31, label cutoff 2023-12-31, base_rate 0.0062.

| feature | raw source |
|---|---|
| epss | scoreboard_2026.epss (2026) / exploit_signals.epss at publish month (2024-25) |
| exploitdb, metasploit, nuclei, poc_github, any_flag | snapshot-month exploit flags (any_flag = max) |
| cvss3_score | vulnerabilities.cvss3_score |
| attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact | vulnerabilities.<same column> |
| assigner (top 150), cwe_primary (first id of cwe_ids, top 60), vendor_guess (first vendor kw) | vulnerabilities.assigner / cwe_ids / description |
| desc_len, kw_* | length / lowercase substring flags on vulnerabilities.description |
| gr0..gr31 | PCA(32) of Granite 384-d embeddings of vulnerabilities.description |
| gr_knn_max, gr_knn_top5, gr_knn_cnt90 | cosine similarity of the Granite embedding to R(t) KEV CVEs |
| txt0..txt15 | TruncatedSVD(16) of TF-IDF of vulnerabilities.description |
| hist_* (ablation only) | outputs/history/*.csv pre-2024 KEV rates |
| y (label, training only) | known_exploited.date_added > publish month-end |

Not used as features: pub_month/published, nvd_status, n_references, n_affected_cpes, last_modified, cvss3_source, references.csv, affected_products.csv.
