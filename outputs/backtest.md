# FixFirst back-test -- valid split (2025-01..2025-06), positives available: 39

| ranking | hits@100 | hits@500 |
|---|---:|---:|
| CVSS first | 4 | 6 |
| EPSS first | 7 | 11 |
| Flags then EPSS | 10 | 17 |
| FixFirst model (LightGBM) | 9 | 14 |
| Blend (model + flags/EPSS) | 14 | 19 |
| model ablation (no kw_exploited / kw_in_the_wild) | 9 | 15 |

HQ reference (valid, hits@500): CVSS 5 | EPSS 11 | Flags-then-EPSS 17 | quick LightGBM 14-16.

**Chosen 2026 ranking rule: blend** (valid hits@500 model=14 vs blend=19 -> blend; ties -> blend).
