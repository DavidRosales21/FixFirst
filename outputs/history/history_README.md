# FixNext - historical exposure rates (strictly pre-2024)

Per-group KEV (exploitation) rates for use as **model features**, built so they cannot
leak any 2024+ training or validation label.

## Window and label
- CVEs published **2019-01-01 .. 2023-12-31** (inclusive).
- Label = on CISA KEV with **date_added <= 2023-12-31**. KEV entries added after that date
  are treated as unknown (label 0): they are 'future' relative to this window.
- Features used: description text, assigner, first CWE id, CVSS v3 severity, attack vector -
  all known at publish time. No EPSS, no exploit flags, no NVD-review fields, nothing dated after 2023.

## Smoothing
- rate = (kev + 20 * base_rate) / (cves + 20)
- base_rate (overall KEV rate in window) = **0.0062** (0.62%), 683 of 109665 CVEs.

## Row counts
| table | rows (groups) | min group size |
| --- | --- | --- |
| assigner_rates.csv | 167 | >=20 CVEs |
| cwe_rates.csv | 167 | >=20 CVEs |
| vendor_kw_rates.csv | 17 | all keywords |
| severity_rates.csv | 5 | all |
| attack_vector_rates.csv | 5 | all |
| speed_by_assigner.csv | 27 | >=5 KEV CVEs (+ALL) |