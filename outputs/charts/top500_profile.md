# FixNext - profile of the top 500 (vs all 72670 ranked 2026 CVEs)

## Headline observations

1. 60.2% of the top 500 have EPSS under 1% (median 0.0072) — EPSS-first would bury them — yet 83.4% carry a public exploit flag, vs 2.3% across all 72670 CVEs.
2. The top 500 piles into a few dangerous weakness types: OS Command Injection (15.0% vs 1.8% overall), Path Traversal (8.2% vs 3.3%) and Deserialization of Untrusted Data (7.8% vs 1.3%) — several times their rate in the full pool.
3. 55.2% of the top 500 are CRITICAL (vs 11.8% overall) and only 5.0% are MEDIUM (vs 36.5%) — it elevates severe, exploitable bugs rather than high-CVSS noise.

## Key stats

| metric | top500 | overall |
| --- | --- | --- |
| % with any exploit flag | 83.4 | 2.3 |
| % with EPSS < 0.01 (EPSS-blind) | 60.2 | 98.0 |
| median EPSS | 0.0072 | 0.0018 |

## Vendor (vendor_guess) share

| vendor_guess | top500_% | overall_% |
| --- | --- | --- |
| other | 84.0 | 77.4 |
| windows | 3.4 | 3.8 |
| microsoft | 3.2 | 1.4 |
| adobe | 2.2 | 0.5 |
| oracle | 1.4 | 4.4 |
| cisco | 1.2 | 0.4 |
| chrome | 1.2 | 3.6 |
| palo alto | 1.0 | 0.1 |
| ivanti | 0.8 | 0.0 |
| fortinet | 0.8 | 0.1 |

## Weakness type (cwe_name) share

| cwe_name | top500_% | overall_% |
| --- | --- | --- |
| OS Command Injection | 15.0 | 1.8 |
| Path Traversal | 8.2 | 3.3 |
| Deserialization of Untrusted Data | 7.8 | 1.3 |
| Code Injection | 7.0 | 1.2 |
| Missing Authentication for Critical Fu.. | 6.4 | 1.5 |
| SQL Injection | 4.4 | 3.2 |
| Improper Input Validation | 3.6 | 2.2 |
| Incorrect Authorization | 3.6 | 1.9 |
| Improper Access Control | 3.0 | 4.6 |
| Unrestricted Upload of File with Dange.. | 2.2 | 0.8 |

## CVSS severity share

| cvss3_severity | top500_% | overall_% |
| --- | --- | --- |
| CRITICAL | 55.2 | 11.8 |
| HIGH | 38.2 | 39.9 |
| MEDIUM | 5.0 | 36.5 |
| LOW | 0.0 | 3.0 |

## Snapshot-month share

| snapshot_month | top500_% | overall_% |
| --- | --- | --- |
| 2026-01 | 5.2 | 5.9 |
| 2026-02 | 6.2 | 6.3 |
| 2026-03 | 7.0 | 8.6 |
| 2026-04 | 9.6 | 8.0 |
| 2026-05 | 7.6 | 9.5 |
| 2026-07 | 30.2 | 24.3 |
| 2026-08 | 17.2 | 16.8 |
| 2026-09 | 17.0 | 20.5 |
