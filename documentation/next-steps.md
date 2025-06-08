# Next Steps

## 1 Ingest CVEs for the whitelist

Goal: Build a master CVE table (≈ 10 k–35 k rows) covering every CPE in your list.

## 2 Tag each CVE with an asset_category

## 3 Compute composite risk scores

## 4 Build a simple dashboard notebook

Use matplotlib/plotly or Streamlit:
* Bar or heat-map of risk_score by asset.
* Time-series line: monthly CVE counts for the selected asset.
* Table of top-N critical CVEs.

## 5 Add OpenAI-powered features

Explain Top Risk
* user input: asset dropdown
* behind-the-scenes: Pull top 5 CVEs, craft prompt
* output: Bullet-list + mitigation text

Mitigation Roadmap
* user input: list of cve ids
* behind-the-scenes: Prompt GPT with CVE JSON blobs
* output:  Step-by-step action plan

Trend Insight
* user input: date range
* behind-the-scenes: Aggregate monthly counts first
* output: Plain-English summary

## Quick sanity-check workflow

🔄 Run CVE ingest once → confirm smb_cves.parquet row count looks right. \
📊 Risk-score script → verify each asset has a score 0–1.\
🖼 Visuals render → charts show meaningful spread.\
🤖 OpenAI calls → prompt returns sensible, actionable text. \
💡 Slides + HTML → proof-read, time a demo run (≤ 5 min).


```python

```
