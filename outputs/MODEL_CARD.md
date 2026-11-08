# FixNext — Model Card

**Team FixNext · Sheridan Datathon 2026 · IBM "Before the Breach"**

## 1. What it predicts, and for whom
FixNext ranks the 72,670 vulnerabilities (CVEs) published in 2026 by how likely each is to be **used by real attackers** — specifically, added to CISA's Known Exploited Vulnerabilities (KEV) list *after* it was published. It is built for a security team that cannot patch everything and needs to know **what to fix first and why**. The deliverable is `top500.csv` (the 500 highest-risk CVEs) and `ranked_2026.csv` (all 72,670, each with a plain-English "why" and the known-exploited CVEs it resembles).

## 2. Training data, labels, and time split
Sources: NIST NVD (fkie-cad mirror, 2026-11-06), CISA KEV (to 2025-12-31), FIRST EPSS, public exploit flags (Exploit-DB, Metasploit, Nuclei, GitHub — t0sche/cvss-bt), MITRE CWE, IBM Granite embeddings. One row per CVE published 2024-01-01 onward.
**Label** (training only): `y = 1` if the CVE was added to KEV *after* the last day of its publish month (a "slow burner"); CVEs already on KEV at publish month are dropped (mirrors the benchmark). Time split, and the few positives that make this hard:

| split | window | rows | KEV positives |
|---|---|---:|---:|
| train | 2024-01 .. 2024-12 | 39,873 | 67 |
| valid | 2025-01 .. 2025-06 | 23,587 | 39 |
| late | 2025-07 .. 2025-12 | 24,461 | 16 |
| score | 2026 (benchmark) | 72,670 | — (y = −1) |

The final model is refit on train+valid+late (all 2024–25 labelled rows) and applied to 2026.

## 3. Features and where each comes from
All features are known at publish time (or end of snapshot month). Model: LightGBM; final score = rank-average **blend** of the model and a "public-exploit-code-then-EPSS" ranking.

- **Exploit signals** `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `any_flag` — scoreboard_2026 / exploit_signals at the snapshot month.
- **Severity** `cvss3_score` and its vector parts (`attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, three impact fields) — vulnerabilities.csv.
- **Identity** `assigner` (top 150), `cwe_primary` (first CWE id, top 60), `vendor_guess` (first vendor keyword in the text) — the two strongest features in the model.
- **Text** `desc_len`, keyword flags `kw_*`, and `txt0..txt15` = TruncatedSVD(16) of a TF-IDF (1–2 gram) of the description.
- **Granite (IBM) — PCA** `gr0..gr31` = PCA(32) of the 384-d `ibm-granite/granite-embedding-small-english-r2` embedding of the description (available but not in the shipped model; see §4).
- **Granite (IBM) — kNN resemblance** `gr_knn_max`, `gr_knn_top5`, `gr_knn_cnt90` = cosine similarity of a CVE's Granite embedding to the **reference set R(t)** = KEV CVEs that already had an embedding and `date_added ≤ t`, with the CVE's own id excluded. **t = 2024-12-31** for labelled rows (R = 125 KEV CVEs), **t = 2025-12-31** for 2026 scoring (R = 317). The three features are the max similarity, the mean of the top-5, and the count of neighbours with similarity ≥ 0.90. `gr_knn_max` is the #4 feature overall.

## 4. Validation and honest reading
Time-based: train on 2024, measure on 2025-H1 (39 positives). Hits@k = how many of the top-k were later exploited.

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
| **Blend (TF-IDF + Granite kNN) — SHIPPED** | **12** | **15** | **19** |

On the same 2025 validation, the three official baselines find 6, 11 and 17 of the 39; the shipped blend finds 19 (and 15 of them in the top 100). The 2026 benchmark itself is scored by the judges; IBM reports the baselines find 6–8 there.

**Honest reading (3 lines).** (1) With only 39 validation positives, differences of 1–2 hits are noisy; we trusted them only where a change helped at one cutoff and hurt at none. (2) Granite as **PCA features** did *not* beat the simple TF-IDF text signal (worse at every cutoff) — but Granite used for **kNN resemblance to known-exploited CVEs** did help (+1 at top-100, equal elsewhere) and `gr_knn_max` became the #4 feature. (3) Five years of pre-2024 per-group KEV **history rates** gave no lift and were dropped — the `assigner` and `cwe_primary` features already carry that signal.

## 5. Known limitations / with more time
- **Tiny positive count** (122 across 2024–25; 39 in validation) → wide uncertainty and real overfitting risk; the blend is deliberately conservative.
- **KEV is a lower bound** on exploitation: a CVE not on KEV may still have been attacked, so labels undercount and metrics are pessimistic.
- **EPSS changed its model in March 2025**, so pre/post scores aren't perfectly comparable across the split.
- **Feb 2025 signals gap** (~14,500 CVEs missing) raises the valid epss-missing rate.
- **Late-2026 CVEs have little look-ahead**, so slow burners there are the hardest to catch.
- *With more time:* Granite-written rationales for every top-50, calibrated probabilities, per-publish-month kNN cutoffs for training rows, and external exploit telemetry (e.g. GreyNoise) as additional signals.

## 6. Columns deliberately NOT used (leakage control)
These are populated or enriched *after* attacks happen (NIST reviews exploited CVEs first), so using them for 2026 would leak the answer: `nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, `cvss3_source`, `references.csv` (news/threat-report links), and `affected_products.csv` for 2026 (missing for 51k unanalysed CVEs — its very presence leaks). Publish date / month is used only to split time, never as a feature. The live CISA KEV feed is never used as a 2026 feature.
