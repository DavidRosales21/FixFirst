# gh-pages — fixnext.select

This branch is the published site, served by GitHub Pages at https://fixnext.select.
It only holds the deploy files; the code lives on the other branches.

- `index.html` runs the Streamlit dashboard in the visitor's browser with
  [stlite](https://github.com/whitphx/stlite) (`@stlite/browser@1.12.0`, Streamlit 1.65),
  and shows a loading screen while Python starts (about 20–30 s).
- `app/` is a copy of `app/` from the `app-ui` branch (commit f2e1875), unchanged.
  It currently uses the sample data (`sample_ranked_2026.csv`, `sample_backtest.csv`).
- `CNAME` sets the custom domain; `.nojekyll` makes Pages serve `app/.streamlit/config.toml`.

To publish a newer version of the app, copy the updated `app/` folder over this one
and push to `gh-pages`. Pages redeploys on its own in a minute or two.

**Real data:** copy the model's `ranked_light.csv` and `backtest.csv` into `app/` here and
push. `index.html` checks for them on each visit and `app.py` prefers them over the sample,
so nothing else changes. Until they exist, those two checks show as 404s in the console.
