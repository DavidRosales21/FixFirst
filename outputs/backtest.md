# FixNext back-test -- valid split (2025-01..2025-06), positives available: 39

| ranking | hits@100 | hits@500 |
|---|---:|---:|
| CVSS first | 4 | 6 |
| EPSS first | 7 | 11 |
| Flags then EPSS | 10 | 17 |
| FixNext model (LightGBM) | 9 | 14 |
| Blend (model + flags/EPSS) | 14 | 19 |
| model ablation (no kw_exploited / kw_in_the_wild) | 9 | 15 |
| FixNext model + history | 6 | 14 |
| Blend + history | 13 | 19 |

HQ reference (valid, hits@500): CVSS 5 | EPSS 11 | Flags-then-EPSS 17 | quick LightGBM 14-16.

**Chosen 2026 ranking rule: blend + history** (valid hits@500 = 19; candidates model=14, blend=19, model+history=14, blend+history=19; ties -> blend+history).

## Column provenance (feature -> raw source)

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
