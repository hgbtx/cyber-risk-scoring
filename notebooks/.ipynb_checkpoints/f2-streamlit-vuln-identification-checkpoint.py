# ---
# jupyter:
#   jupytext:
#     text_representation:
#       extension: .py
#       format_name: light
#       format_version: '1.5'
#       jupytext_version: 1.16.7
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# +
import os
import time
import requests
import pandas as pd
import streamlit as st
from pathlib import Path

# --- Streamlit UI Elements ---
st.title("CVE Lookup Tool for CPEs")

uploaded_file = st.file_uploader("Upload your CPE whitelist CSV", type=["csv"])
api_key = st.text_input("Enter your NVD API key", type="password")
start_query = st.button("Start Query")

# --- Configuration ---
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
rate_secs = 1.0
per_page = 2000
progress_every = 25

def fetch_cves_for_cpe(cpe_uri: str) -> list[dict]:
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return []
    cpe_query = ":".join(parts[:6]) if parts[5] == "*" else cpe_uri
    all_items, start = [], 0
    headers = {"apiKey": api_key}
    while True:
        params = {
            "cpeName": cpe_query,
            "resultsPerPage": per_page,
            "startIndex": start,
        }
        r = requests.get(api_url, headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            st.warning(f"⚠️ {cpe_query[:70]} → {r.status_code}")
            break
        data = r.json()
        items = data.get("vulnerabilities", [])
        all_items.extend(items)
        start += per_page
        if start >= data.get("totalResults", 0) or not items:
            break
        time.sleep(rate_secs)
    return all_items

def flatten(v: dict, cpe_uri: str) -> dict:
    cve = v["cve"]
    metrics = cve.get("metrics", {})
    cvss31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
    cvss30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
    cvss = cvss31 or cvss30
    descr = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    cwes = [
        d["value"] for w in cve.get("weaknesses", [])
        for d in w.get("description", []) if d.get("lang") == "en"
    ]
    refs = " | ".join(r["url"] for r in cve.get("references", [])[:10])
    tags = ", ".join(tag for r in cve.get("references", [])[:10] for tag in r.get("tags", []))
    return {
        "cveID": cve["id"],
        "cpeName": cpe_uri,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vectorString": cvss.get("vectorString"),
        "baseScore": cvss.get("baseScore"),
        "baseSeverity": cvss.get("baseSeverity"),
        "attackVector": cvss.get("attackVector"),
        "attackComplexity": cvss.get("attackComplexity"),
        "privilegesRequired": cvss.get("privilegesRequired"),
        "userInteraction": cvss.get("userInteraction"),
        "scope": cvss.get("scope"),
        "confidentialityImpact": cvss.get("confidentialityImpact"),
        "integrityImpact": cvss.get("integrityImpact"),
        "availabilityImpact": cvss.get("availabilityImpact"),
        "cwes": ";".join(cwes) if cwes else None,
        "description": descr[:1000],
        "references": refs,
        "tags": tags,
        "full_json": v,
    }

if uploaded_file and start_query:
    assets = pd.read_csv(uploaded_file, dtype=str)
    cpe_list = assets["cpeName"].dropna().unique()
    st.write(f"{len(cpe_list):,} unique CPEs to query")

    rows = []
    progress_bar = st.progress(0)
    status_text = st.empty()

    for idx, cpe in enumerate(cpe_list, start=1):
        if idx % progress_every == 0 or idx == 1:
            status_text.text(f"Processing {idx}/{len(cpe_list)}: {cpe[:70]}…")
        vulns = fetch_cves_for_cpe(cpe)
        if vulns:
            for vuln in vulns:
                rows.append(flatten(vuln, cpe))
        else:
            rows.append({
                "cveID": None, "cpeName": cpe, "published": None, "last_modified": None,
                "vectorString": None, "baseScore": None, "baseSeverity": None,
                "attackVector": None, "attackComplexity": None, "privilegesRequired": None,
                "userInteraction": None, "scope": None, "confidentialityImpact": None,
                "integrityImpact": None, "availabilityImpact": None, "cwes": None,
                "description": "NO CVEs FOUND FOR THIS ASSET", "references": None,
                "tags": "NO CVEs", "full_json": None
            })
        progress_bar.progress(idx / len(cpe_list))

    df = pd.DataFrame(rows).drop_duplicates(subset=["cveID", "cpeName"]).reset_index(drop=True)
    st.success(f"Done! {df.shape[0]:,} CVE–CPE rows collected")
    st.dataframe(df)
    st.download_button("Download Results as CSV", df.to_csv(index=False), "cve_results.csv")
