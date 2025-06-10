import os
import time
import csv
import requests
import pandas as pd
import streamlit as st
from pathlib import Path
from datetime import datetime

# --- Configuration ---
api_url_cve = "https://services.nvd.nist.gov/rest/json/cves/2.0"
api_url_cpe = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
rate_secs = 1.2
per_page = 2000
progress_every = 25
header = ['WrittenAt', 'Title', 'cpeName']

# --- Streamlit UI Elements ---
st.title("CPE Inventory + CVE Risk Scoring Tool")

api_key = st.text_input("Enter your NVD API key", type="password")
mode = st.radio("Select an action:", ["Search & Save CPEs", "Run CVE Query"])

# Initialize session state for CPE list
if 'cpe_session_list' not in st.session_state:
    st.session_state.cpe_session_list = []

# --- F1: CPE Inventory Module ---
def search_cpe_names(keyword):
    all_results = []
    start_index = 0
    results_per_page = 100
    headers = {"apiKey": api_key}
    while True:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }
        response = requests.get(api_url_cpe, params=params, headers=headers)
        if response.status_code != 200:
            st.error(f"Error fetching data for '{keyword}': {response.status_code} - {response.text}")
            break
        data = response.json()
        cpe_matches = data.get('products', [])
        if not cpe_matches:
            break
        for item in cpe_matches:
            metadata = item.get('cpe', {}).get('titles', [])
            title = next((t['title'] for t in metadata if t.get('lang') == 'en'), metadata[0]['title'] if metadata else '')
            cpe_uri = item.get('cpe', {}).get('cpeName', '')
            vendor = item.get('cpe', {}).get('cpeName', '').split(':')[3] if 'cpeName' in item.get('cpe', {}) else ''
            if cpe_uri:
                all_results.append({'title': title, 'cpeName': cpe_uri, 'vendor': vendor})
        total_results = data.get('totalResults', 0)
        start_index += results_per_page
        if start_index >= total_results:
            break
        time.sleep(rate_secs)
    return all_results

if mode == "Search & Save CPEs":
    keyword_input = st.text_input("Enter comma-separated keywords:")
    if 'search_results' not in st.session_state:
        st.session_state.search_results = []

    if st.button("Search") and keyword_input:
        st.session_state.search_results.clear()
        search_keywords = [kw.strip() for kw in keyword_input.split(',') if kw.strip()]
        for keyword in search_keywords:
            st.write(f"Searching: **{keyword}**")
            matches = search_cpe_names(keyword)
            st.write(f"**{len(matches)}** result(s) found for '{keyword}'")
            st.session_state.search_results.extend(matches)

    if st.session_state.search_results:
        df_results = pd.DataFrame(st.session_state.search_results)
        st.write("### Search Results")
        selected_rows = st.data_editor(
            df_results[['title', 'cpeName', 'vendor']],
            use_container_width=True,
            num_rows="dynamic",
            hide_index=True,
            column_config={"cpeName": "CPE URI"},
            key="selected_cpes_editor",
            disabled=["title", "vendor"]
        )
        selected_cpes = selected_rows['cpeName'].tolist()

        if selected_cpes:
            st.session_state.cpe_session_list.extend(selected_cpes)
            final_df = df_results[df_results['cpeName'].isin(selected_cpes)]
            st.download_button("Download Results as CSV", final_df.to_csv(index=False), "saved_cpes.csv")

# --- F2: CVE Query Module ---
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
        r = requests.get(api_url_cve, headers=headers, params=params, timeout=30)
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

if mode == "Run CVE Query" and api_key:
    cpe_list = st.session_state.cpe_session_list
    if not cpe_list:
        uploaded_file = st.file_uploader("Upload your CPE whitelist CSV", type=["csv"])
        if uploaded_file is not None:
            assets = pd.read_csv(uploaded_file, dtype=str)
            cpe_list = assets["cpeName"].dropna().unique().tolist()
    if cpe_list:
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
    else:
        st.warning("Please upload a CPE whitelist or perform a search in 'Search & Save CPEs' mode.")
