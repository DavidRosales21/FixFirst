# FixNext — Before the Breach

Live demo: https://fixnext.select (dashboard)

**Sheridan Datathon 2026 · IBM Track.** Which of 2026's 72,670 vulnerabilities will attackers actually use? FixNext ranks them with a model that reads the CVE description (IBM Granite embeddings) plus the weakness type, the issuing organisation, the CVSS attack vector and the public exploit signals known at publish time — and writes a plain-English "why fix this first" for the top of the list.

Team: Hossam, David, Antesh, Calvin.

## Layout
```
data/        IBM track CSVs + Granite outputs (not committed — see data/README.md)
src/         pipeline: config.py (paths + leakage rules) · build_features.py · train.py
scripts/     check_top500.py — validates the submission file
notebooks/   Colab notebooks: granite_embed.ipynb, granite_explain.ipynb
outputs/     features.parquet, top500.csv, backtest.md, charts
app/         Streamlit dashboard
tests/       pytest
```

## Team workflow (David's rules — follow them)
1. `git pull` before you start working.
2. Create a branch per task: `git checkout -b task-name`.
3. Push your branch and open a Pull Request into `main`. HQ reviews every PR against the leakage rules before merge.
4. Avoid editing the same notebook as someone else at the same time.
5. `data/` is ignored by Git — large files never get pushed. Share them via the team Drive.

## Setup
Repo: https://github.com/DavidRosales21/FixNext
```bash
git clone https://github.com/DavidRosales21/FixNext.git
cd FixNext
pip install -r requirements.txt
```

## Run
```bash
pip install -r requirements.txt
python -m src.build_features        # → outputs/features.parquet
python -m src.train                 # → outputs/top500.csv + outputs/backtest.md
python scripts/check_top500.py      # validate submission format
streamlit run app/app.py
```

## Keeping it fair — columns used
Allowed (known at publish / end of snapshot month): `description`, `assigner`, `published`, `cwe_ids`, CVSS v3 score and vector components, and the scoreboard's `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github`. Labels come from `known_exploited.csv` (≤ 2025-12-31) for training only.

**Not used for 2026 features:** `nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, `cvss3_source`, `references.csv`, `affected_products.csv` — NIST fills these in after attacks, so they leak the answer. `src/config.py::assert_no_leakage` enforces this.

## Results

### Back-test — CVEs published Jan–Jun 2025, scored with information available at end of publish month
| Ranking | Exploited CVEs found in top 100 | in top 500 |
|---|---|---|
| CVSS v3 score first | [ ] | [ ] |
| EPSS first | [ ] | [ ] |
| Public exploit code first, then EPSS | [ ] | [ ] |
| **FixNext** | [ ] | [ ] |
| FixNext without "exploited"/"in the wild" keywords (ablation) | [ ] | [ ] |
Positives available: [ ]. Full table: outputs/backtest.md.

### What we found
**Microsoft alone = 19.6% of all KEV** — who issued the CVE beats how severe it is.
![](outputs/charts/1_assigner_lift.png)

**98.7% of CRITICAL CVEs are never exploited** (CRITICAL KEV rate 1.32%).
![](outputs/charts/2_severity.png)

**XSS (CWE-79): 15 of 25,755 exploited** — attackers ignore the most common bug types.
![](outputs/charts/3_cwe_best_worst.png)

**Median 28 days from publish to KEV** — exploitation is fast.
![](outputs/charts/4_speed.png)

**Internet-edge + auth-bypass + RCE words raise the odds; XSS/WordPress near zero.**
![](outputs/charts/5_phrases.png)

## IBM technology
- `ibm-granite/granite-embedding-small-english-r2` — description embeddings (Colab GPU)
- `ibm-granite/granite-3.3-2b-instruct` — "why fix this first" rationales

## Credits
NIST National Vulnerability Database (fkie-cad/nvd-json-data-feeds mirror, 2026-11-06) · CISA Known Exploited Vulnerabilities catalog (to 2025-12-31) · EPSS (FIRST) · public exploit flags from t0sche/cvss-bt (Exploit-DB, Metasploit, Nuclei, GitHub) · MITRE CWE v4.14 · IBM Granite (Hugging Face).
