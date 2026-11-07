# FixFirst - Discovery findings (reproduced by src/discovery.py)

Window: CVEs published 2021-01-01..2025-12-31. Labels: CISA KEV <= 2025-12-31. Base rate 0.50% (813 of 162141).

## F1. A few security teams account for most exploited CVEs
Headline: **Microsoft alone = 19.6% of all KEV** - who issued the CVE beats how severe it is. Top assigners by KEV count (>=200 CVEs):

| assigner_label | cves | kev | kev_rate_pct | share_of_all_kev_pct | lift_vs_base |
| --- | --- | --- | --- | --- | --- |
| microsoft | 5135 | 159 | 3.10 | 19.56 | 6.18 |
| mitre | 31450 | 131 | 0.42 | 16.11 | 0.83 |
| apple | 2717 | 65 | 2.39 | 8.00 | 4.77 |
| google | 1485 | 53 | 3.57 | 6.52 | 7.12 |
| cisco | 1800 | 24 | 1.33 | 2.95 | 2.66 |
| github | 9115 | 22 | 0.24 | 2.71 | 0.48 |
| vmware | 421 | 22 | 5.23 | 2.71 | 10.42 |
| apache | 1145 | 18 | 1.57 | 2.21 | 3.14 |
| hackerone | 637 | 17 | 2.67 | 2.09 | 5.32 |
| fortinet | 788 | 16 | 2.03 | 1.97 | 4.05 |
| adobe | 3154 | 15 | 0.48 | 1.85 | 0.95 |
| samsung | 1246 | 13 | 1.04 | 1.60 | 2.08 |
| qualcomm | 1351 | 11 | 0.81 | 1.35 | 1.62 |
| paloaltonetworks | 220 | 10 | 4.55 | 1.23 | 9.07 |
| android | 2398 | 10 | 0.42 | 1.23 | 0.83 |

## F2. Severity is a weak guide
Headline: **98.7% of CRITICAL CVEs are never exploited** (CRITICAL KEV rate 1.32%).

| cvss3_severity | cves | kev | rate_pct |
| --- | --- | --- | --- |
| CRITICAL | 22592 | 298 | 1.32 |
| HIGH | 60317 | 415 | 0.69 |
| MEDIUM | 72856 | 97 | 0.13 |
| LOW | 3272 | 3 | 0.09 |
| NONE | 2 | 0 | 0.00 |
| (none) | 3102 | 0 | 0.00 |

## F3. Attackers ignore the most common bug types
Headline: **XSS (CWE-79): 15 of 25755 exploited.** Top 8 and bottom 6 (>=1000 CVEs) weakness types:

| cwe_id | short_name | cves | kev | rate_pct | lift |
| --- | --- | --- | --- | --- | --- |
| CWE-843 | Type Confusion | 401 | 25 | 6.23 | 12.43 |
| CWE-288 | Authentication Bypass Using an.. | 339 | 11 | 3.24 | 6.47 |
| CWE-306 | Missing Authentication for Cri.. | 1115 | 27 | 2.42 | 4.83 |
| CWE-502 | Deserialization of Untrusted D.. | 1626 | 34 | 2.09 | 4.17 |
| CWE-78 | OS Command Injection | 2848 | 52 | 1.83 | 3.64 |
| CWE-94 | Code Injection | 1765 | 26 | 1.47 | 2.94 |
| CWE-416 | Use After Free | 4027 | 59 | 1.47 | 2.92 |
| CWE-290 | Authentication Bypass by Spoof.. | 377 | 5 | 1.33 | 2.65 |
| CWE-476 | NULL Pointer Dereference | 3212 | 0 | 0.00 | 0.00 |
| CWE-352 | Cross-Site Request Forgery (CS.. | 5769 | 1 | 0.02 | 0.03 |
| CWE-79 | Cross-site Scripting | 25755 | 15 | 0.06 | 0.12 |
| CWE-401 | Missing Release of Memory afte.. | 1229 | 1 | 0.08 | 0.16 |
| CWE-400 | Uncontrolled Resource Consumpt.. | 1661 | 2 | 0.12 | 0.24 |
| CWE-862 | Missing Authorization | 5385 | 7 | 0.13 | 0.26 |

## F4. Exploitation is fast
Headline: **median 28 days from publish to KEV.** Lag quantiles and per-assigner medians:

| assigner | metric | lag_days |
| --- | --- | --- |
| ALL_KEV | q0 | -290.00 |
| ALL_KEV | q10 | 0.00 |
| ALL_KEV | q25 | 1.00 |
| ALL_KEV | q50 | 28.00 |
| ALL_KEV | q75 | 176.00 |
| ALL_KEV | q90 | 359.00 |
| ALL_KEV | q100 | 1691.00 |
| microsoft | median_lag | 6.00 |
| mitre | median_lag | 105.00 |
| apple | median_lag | 2.00 |
| google | median_lag | 4.00 |
| cisco | median_lag | 9.50 |
| github | median_lag | 132.50 |
| vmware | median_lag | 52.50 |
| apache | median_lag | 113.00 |

## F5. The attacker's vocabulary
Headline: **internet-edge + auth-bypass + RCE words raise the odds; XSS/WordPress near zero.** Description phrases by lift vs base:

| phrase | cves | kev | kev_rate_pct | lift |
| --- | --- | --- | --- | --- |
| vpn | 645 | 26 | 4.03 | 8.04 |
| authentication bypass | 1049 | 25 | 2.38 | 4.75 |
| firewall | 603 | 13 | 2.16 | 4.30 |
| gateway | 923 | 18 | 1.95 | 3.89 |
| use after free | 1720 | 33 | 1.92 | 3.83 |
| remote code execution | 6315 | 103 | 1.63 | 3.25 |
| deserialization | 1398 | 22 | 1.57 | 3.14 |
| unauthenticated | 11123 | 147 | 1.32 | 2.64 |
| command injection | 3779 | 49 | 1.30 | 2.59 |
| path traversal | 2357 | 22 | 0.93 | 1.86 |
| privilege escalation | 2511 | 14 | 0.56 | 1.11 |
| router | 1836 | 10 | 0.54 | 1.09 |
| buffer overflow | 6815 | 29 | 0.43 | 0.85 |
| denial of service | 9607 | 19 | 0.20 | 0.39 |
| sql injection | 10940 | 13 | 0.12 | 0.24 |
| plugin | 17198 | 5 | 0.03 | 0.06 |
| cross-site scripting | 19369 | 4 | 0.02 | 0.04 |
| wordpress | 13542 | 0 | 0.00 | 0.00 |
