# FixNext — Before the Breach

Live demo: https://fixnext.streamlit.app (fast) · https://fixnext.select (runs in your browser, ~25 s to load)

Model card for judges: [outputs/MODEL_CARD.md](outputs/MODEL_CARD.md)

**Sheridan Datathon 2026 · IBM Track.** Which of 2026's 72,670 vulnerabilities will attackers actually use? FixNext ranks them with a model that reads the CVE description (IBM Granite embeddings) plus the weakness type, the issuing organisation, the CVSS attack vector and the public exploit signals known at publish time — and writes a plain-English "why fix this next" for the top of the list.

Team: Hossam, David, Antesh, Calvin.

## Layout
```
data/        IBM track CSVs + Granite outputs (not committed — see data/README.md)
src/         pipeline: config.py (paths + leakage rules) · build_features.py · train.py
scripts/     check_top500.py — validates the submission file
notebooks/   Colab notebooks: granite_embed.ipynb, granite_explain.ipynb
outputs/     top500.csv · ranked_2026.csv · backtest.md · MODEL_CARD.md · similar_exploited.csv · rationales.csv · rationales_2.csv · charts/ · history/
app/         Streamlit dashboard
tests/       pytest
```

## How we worked
Branch per task, pull request into main, every PR reviewed against the leakage rules in src/config.py before merge. data/ is git-ignored; raw files came from the track's data.zip, Granite outputs from Colab.

## Quick start — the dashboard (3 commands, no data download needed)
```bash
git clone https://github.com/DavidRosales21/FixNext.git && cd FixNext
python -m pip install -r requirements.txt
python -m streamlit run app/app.py
```
Opens at http://localhost:8501 with the frozen 2026 ranking (app/ranked_light.csv). Hosted: https://fixnext.select

## Reproduce the full pipeline (needs the 850 MB data.zip from the track + Granite embeddings)
See [data/README.md](data/README.md) for what goes in `data/` (the track's data.zip files and the Granite embedding outputs).
```bash
python -m pip install -r requirements.txt
python -m src.build_features        # CSVs → outputs/features.parquet (one row per CVE)
python -m src.train                 # train + back-test → outputs/top500.csv, backtest.md, ranked_2026.csv
python scripts/check_top500.py      # validate the submission format
python -m src.discovery             # the 5 discovery findings → outputs/charts/ (charts + tables)
python -m src.history_rates         # strictly pre-2024 exposure-rate features → outputs/history/
python -m src.caught_vs_missed      # exploited CVEs we caught vs missed on the 2025 hold-out → chart 6
python -m src.results_charts        # FixNext vs baselines + top-500 profile → charts 7, 8
python -m src.make_app_data         # light browser data for the dashboard → app/ranked_light.csv, app/backtest.csv
python -m streamlit run app/app.py  # launch the dashboard on the reproduced data
```

## Keeping it fair — columns used
Allowed (known at publish / end of snapshot month): `description`, `assigner`, `published`, `cwe_ids`, CVSS v3 score and vector components, and the scoreboard's `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github`. Labels come from `known_exploited.csv` (≤ 2025-12-31) for training only.

**Not used for 2026 features:** `nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, `cvss3_source`, `references.csv`, `affected_products.csv` — NIST fills these in after attacks, so they leak the answer. `src/config.py::assert_no_leakage` enforces this.

## Results

### Back-test — CVEs published Jan–Jun 2025, scored with information available at end of publish month
| Ranking | Exploited CVEs found in top 100 | in top 500 |
|---|---|---|
| CVSS v3 score first | 4 | 6 |
| EPSS first | 7 | 11 |
| Public exploit code first, then EPSS | 10 | 17 |
| **FixNext** | **15** | **19** |
| FixNext without "exploited"/"in the wild" keywords (ablation) | 9 | 15 |
Positives available: 39. Full table: [outputs/backtest.md](outputs/backtest.md).

Final rule: blend of LightGBM (TF-IDF text + CWE + assigner + CVSS vector + exploit signals + IBM Granite nearest-exploited-CVE similarity) with the exploit-code-then-EPSS ranking. Full ablations, including Granite PCA and five-year history features that did not help, in [outputs/backtest.md](outputs/backtest.md).

### What we found
All figures below live in [outputs/charts/](outputs/charts/).

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

**On the 2025 hold-out, FixNext found 19 of 39 exploited CVEs in its top 500** — vs 17 (exploit-code + EPSS), 11 (EPSS) and 6 (CVSS).
![](outputs/charts/7_model_vs_baselines.png)

**We caught exploited CVEs the industry scores buried** — ConnectWise ScreenConnect, Kentico Xperience, Microsoft NTLM — all with near-zero EPSS; the honest "missed by all" cases are called out too.
![](outputs/charts/6_caught_vs_missed.png)

## IBM technology (Granite)
- ibm-granite/granite-embedding-small-english-r2 embeds every CVE description (180,308 vectors, Colab GPU). For each CVE we compute its cosine similarity to CVEs already on CISA KEV at that time — this "resembles a known-exploited CVE" signal is the model's #4 feature (gr_knn_max). Used as PCA features instead, Granite did not beat TF-IDF on 39 validation positives; both results are in outputs/backtest.md.
- ibm-granite/granite-3.3-2b-instruct writes the two-line "why fix this next" rationale for every CVE in the top 100 (outputs/rationales*.csv), shown in the dashboard.
- Notebooks: notebooks/granite_embed.ipynb, notebooks/granite_explain.ipynb.

## Credits
NIST National Vulnerability Database (fkie-cad/nvd-json-data-feeds mirror, 2026-11-06) · CISA Known Exploited Vulnerabilities catalog (to 2025-12-31) · EPSS (FIRST) · public exploit flags from t0sche/cvss-bt (Exploit-DB, Metasploit, Nuclei, GitHub) · MITRE CWE v4.14 · IBM Granite (Hugging Face).

Demo video: (link added Sunday)
