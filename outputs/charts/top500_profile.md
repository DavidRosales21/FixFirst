# FixNext - profile of the top 500 (vs all 72670 ranked 2026 CVEs)

## Headline observations

1. 60.4% of the top 500 have EPSS under 1% (median 0.0069) — EPSS-first would bury them — yet 84.6% carry a public exploit flag, vs 2.3% across all 72670 CVEs.
2. The top 500 piles into a few dangerous weakness types: OS Command Injection (13.2% vs 1.8% overall), Path Traversal (8.6% vs 3.3%) and Deserialization of Untrusted Data (8.0% vs 1.3%) — several times their rate in the full pool.
3. 55.4% of the top 500 are CRITICAL (vs 11.8% overall) and only 3.0% are MEDIUM (vs 36.5%) — it elevates severe, exploitable bugs rather than high-CVSS noise.

## Key stats

| metric | top500 | overall |
| --- | --- | --- |
| % with any exploit flag | 84.6 | 2.3 |
| % with EPSS < 0.01 (EPSS-blind) | 60.4 | 98.0 |
| median EPSS | 0.0069 | 0.0018 |

## Vendor (vendor_guess) share

| vendor_guess | top500_% | overall_% |
| --- | --- | --- |
| other | 84.8 | 77.4 |
| microsoft | 2.6 | 1.4 |
| adobe | 2.4 | 0.5 |
| windows | 2.4 | 3.8 |
| chrome | 1.6 | 3.6 |
| oracle | 1.2 | 4.4 |
| cisco | 1.2 | 0.4 |
| ivanti | 1.0 | 0.0 |
| fortinet | 1.0 | 0.1 |
| palo alto | 0.6 | 0.1 |

## Weakness type (cwe_name) share

| cwe_name | top500_% | overall_% |
| --- | --- | --- |
| OS Command Injection | 13.2 | 1.8 |
| Path Traversal | 8.6 | 3.3 |
| Deserialization of Untrusted Data | 8.0 | 1.3 |
| Code Injection | 7.4 | 1.2 |
| Missing Authentication for Critical Fu.. | 6.4 | 1.5 |
| Improper Input Validation | 4.2 | 2.2 |
| Incorrect Authorization | 3.2 | 1.9 |
| Improper Access Control | 2.8 | 4.6 |
| SQL Injection | 2.8 | 3.2 |
| Improper Authentication | 2.4 | 1.3 |

## CVSS severity share

| cvss3_severity | top500_% | overall_% |
| --- | --- | --- |
| CRITICAL | 55.4 | 11.8 |
| HIGH | 40.0 | 39.9 |
| MEDIUM | 3.0 | 36.5 |
| LOW | 0.2 | 3.0 |

## Snapshot-month share

| snapshot_month | top500_% | overall_% |
| --- | --- | --- |
| 2026-01 | 5.2 | 5.9 |
| 2026-02 | 7.2 | 6.3 |
| 2026-03 | 6.2 | 8.6 |
| 2026-04 | 8.2 | 8.0 |
| 2026-05 | 7.4 | 9.5 |
| 2026-07 | 32.8 | 24.3 |
| 2026-08 | 16.4 | 16.8 |
| 2026-09 | 16.6 | 20.5 |
