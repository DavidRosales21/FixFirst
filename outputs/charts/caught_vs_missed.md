# FixNext - caught vs missed (2025-H1 valid split, 39 exploited CVEs)

Reconciliation with outputs/backtest.md (hits@500): FixNext=20 (exp 19), flags-then-EPSS=17 (exp 17), EPSS=11 (exp 11), CVSS=6 (exp 6) - MISMATCH, see note below.

## FixNext vs the baseline (flags-then-EPSS), top 500
|  | caught by baseline | missed by baseline |
| --- | --- | --- |
| caught by FixNext | 16 | 4 |
| missed by FixNext | 1 | 18 |

- **FixNext only (we caught, baseline missed): 4**  |  both: 16  |  baseline only: 1  |  missed by all: 18

## FixNext vs EPSS-first, top 500
- FixNext only: 9  |  both: 11  |  EPSS only: 0  |  missed by both: 19

## The slide: CVEs FixNext caught that the baseline missed
| CVE | name | vendor | CWE | CVSS | EPSS@snapshot | FixNext rank | baseline rank | days to exploit | ransomware |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2025-3935 | ConnectWise ScreenConnect Improp.. | ConnectWise | Deserialization of Untrusted Data | 7.2 | 0.002 | 189 | 1176 | 38 | no |
| CVE-2025-2747 | Kentico Xperience CMS Authentica.. | Kentico | Authentication Bypass Using an A.. | 9.8 | 0.001 | 369 | 1747 | 210 | no |
| CVE-2025-2746 | Kentico Xperience CMS Authentica.. | Kentico | Authentication Bypass Using an A.. | 9.8 | 0.001 | 383 | 1746 | 210 | no |
| CVE-2025-24054 | Microsoft Windows NTLM Hash Disc.. | Microsoft | External Control of File Name or.. | 5.4 | 0.001 | 458 | 1702 | 37 | no |

## Missed by all (FixNext and baseline both missed) - the honest column
| CVE | name | vendor | CWE | CVSS | EPSS@snapshot | FixNext rank | why it's hard |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2024-58136 | Yiiframework Yii Improper Protec.. | Yiiframework | Improper Protection of Alternate.. | 9.8 | 0.001 | 630 | low EPSS (0.001); not a high-exposure vendor; no public exploit code at publish |
| CVE-2024-54085 | AMI MegaRAC SPx Authentication B.. | AMI | Authentication Bypass by Spoofing | 9.8 | 0.001 | 765 | low EPSS (0.001); not a high-exposure vendor; no public exploit code at publish |
| CVE-2024-53704 | SonicWall SonicOS SSLVPN Imprope.. | SonicWall | Improper Authentication | 9.8 | 0.000 | 2237 | low EPSS (0.000); not a high-exposure vendor; no public exploit code at publish |
| CVE-2024-57968 | Advantive VeraCore Unrestricted .. | Advantive | Unrestricted Upload of File with.. | 8.8 | 0.000 | 2896 | low EPSS (0.000); not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-24472 | Fortinet FortiOS and FortiProxy .. | Fortinet | Authentication Bypass Using an A.. | 8.1 | 0.000 | 3505 | low EPSS (0.000); not a high-exposure vendor; no public exploit code at publish |
| CVE-2024-13159 | Ivanti Endpoint Manager (EPM) Ab.. | Ivanti | Absolute Path Traversal | 7.5 | 0.000 | 3761 | low EPSS (0.000); no public exploit code at publish |
| CVE-2024-13160 | Ivanti Endpoint Manager (EPM) Ab.. | Ivanti | Absolute Path Traversal | 7.5 | 0.000 | 3762 | low EPSS (0.000); no public exploit code at publish |
| CVE-2024-13161 | Ivanti Endpoint Manager (EPM) Ab.. | Ivanti | Absolute Path Traversal | 7.5 | 0.000 | 3763 | low EPSS (0.000); no public exploit code at publish |
| CVE-2025-35939 | Craft CMS External Control of As.. | Craft CMS | External Control of Assumed-Immu.. | 5.3 | 0.001 | 4839 | low EPSS (0.001); only MEDIUM/LOW severity; not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-25181 |  Advantive VeraCore SQL Injectio.. | Advantive | SQL Injection | 7.5 | 0.000 | 4943 | low EPSS (0.000); not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-27915 | Synacor Zimbra Collaboration Sui.. | Synacor | Cross-site Scripting | 5.4 | 0.000 | 5642 | low EPSS (0.000); only MEDIUM/LOW severity; not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-48927 | TeleMessage TM SGNL Initializati.. | TeleMessage | Initialization of a Resource wit.. | 5.3 | 0.000 | 7719 | low EPSS (0.000); only MEDIUM/LOW severity; not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-0411 | 7-Zip Mark of the Web Bypass Vul.. | 7-Zip | Protection Mechanism Failure | 7.0 | blank | 10669 | EPSS blank; not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-32463 | Sudo Inclusion of Functionality .. | Sudo | Inclusion of Functionality from .. | 7.8 | blank | 11221 | EPSS blank; not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-23209 | Craft CMS Code Injection Vulnera.. | Craft CMS | Code Injection | 8.1 | blank | 11479 | EPSS blank; not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-48928 | TeleMessage TM SGNL Exposure of .. | TeleMessage | Exposure of Core Dump File to an.. | 4.0 | 0.000 | 12833 | low EPSS (0.000); only MEDIUM/LOW severity; not a high-exposure vendor; no public exploit code at publish |
| CVE-2023-52163 | Digiever DS-2105 Pro Missing Aut.. | Digiever | Missing Authorization | 8.8 | blank | 19236 | EPSS blank; not a high-exposure vendor; no public exploit code at publish |
| CVE-2025-6554 | Google Chromium V8 Type Confusio.. | Google | Type Confusion | 8.1 | blank | 23186 | EPSS blank; no public exploit code at publish |
