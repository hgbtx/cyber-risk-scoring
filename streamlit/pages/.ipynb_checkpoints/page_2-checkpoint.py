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
import time            # Pause execution for rate limiting
import requests        # HTTP requests library
import pandas as pd    # DataFrame manipulation
import streamlit as st # Streamlit UI framework
from streamlit.runtime.scriptrunner import RerunException  # For manual reruns

# Configuration
api_url_cpe = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
api_url_cve = "https://services.nvd.nist.gov/rest/json/cves/2.0"
rate_secs = 1.2
per_page = 2000
progress_every = 25

# Main page content
st.markdown("# CPE/CVE Retrieval Tool")
st.sidebar.markdown("# CPE/CVE Retrieval Tool")

# API key input
api_key = st.secrets["NVD_API_KEY"]
mode = st.radio("Select an action:", ("Search & Save CPEs", "Run CVE Query"))

# Session state initialization
if 'search_results' not in st.session_state:
    st.session_state.search_results = []
if 'cpe_session_list' not in st.session_state:
    st.session_state.cpe_session_list = []
if 'cpe_title_map' not in st.session_state:
    st.session_state.cpe_title_map = {}

# --- Helper: Search CPE API ---
def search_cpe_names(keyword: str) -> list[dict]:
    results = []
    start = 0
    headers = {"apiKey": api_key}
    while True:
        params = {"keywordSearch": keyword, "resultsPerPage": 100, "startIndex": start}
        resp = requests.get(api_url_cpe, params=params, headers=headers)
        if resp.status_code != 200:
            st.error(f"Error fetching CPEs: {resp.status_code}")
            break
        data = resp.json()
        items = data.get('products', [])
        if not items:
            break
        for entry in items:
            cpe = entry.get('cpe', {})
            titles = cpe.get('titles', [])
            title = next((t['title'] for t in titles if t.get('lang')=='en'), titles[0]['title'] if titles else '')
            uri = cpe.get('cpeName','')
            vendor = uri.split(':')[3] if uri else ''
            if uri:
                results.append({'title': title, 'cpeName': uri, 'vendor': vendor})
        total = data.get('totalResults', 0)
        start += 100
        if start >= total:
            break
        time.sleep(rate_secs)
    return results

# --- Module: Search & Manage CPEs ---
if mode == "Search & Save CPEs":
    # Upload existing whitelist
    uploaded = st.file_uploader("Upload your CPE whitelist CSV", type=["csv"] )
    if uploaded:
        df_up = pd.read_csv(uploaded, dtype=str)
        for uri in df_up.get('cpeName', []).dropna().unique():
            if uri not in st.session_state.cpe_session_list:
                st.session_state.cpe_session_list.append(uri)
                title = df_up.loc[df_up['cpeName']==uri, 'Title'].iat[0] if 'Title' in df_up.columns else uri
                st.session_state.cpe_title_map[uri] = title
        st.success(f"Appended {len(df_up)} CPE(s) from CSV.")

    # Search form (supports Enter key)
    with st.form('search_form'):
        keywords = st.text_input("Enter comma-separated keywords to search:")
        search_btn = st.form_submit_button("Search")
    if search_btn and keywords:
        st.session_state.search_results.clear()
        for kw in [k.strip() for k in keywords.split(',') if k.strip()]:
            st.write(f"Searching: **{kw}**")
            matches = search_cpe_names(kw)
            st.write(f"**{len(matches)}** result(s)")
            st.session_state.search_results.extend(matches)

    # Clear search
    if st.button("Clear Search Results"):
        st.session_state.search_results.clear()
        st.success("Search results cleared.")

    # Display search results with append option
    if st.session_state.search_results:
        df = pd.DataFrame(st.session_state.search_results)
        df['append'] = False
        st.write("### Search Results: Select to Add to Whitelist")
        edited = st.data_editor(
            df[['append','title','cpeName','vendor']], use_container_width=True,
            hide_index=True, key='search_editor', disabled=['title','vendor']
        )
        to_append = edited.loc[edited['append'], 'cpeName'].tolist()
        if st.button("Add to CPE Whitelist") and to_append:
            count = 0
            for uri in to_append:
                if uri not in st.session_state.cpe_session_list:
                    st.session_state.cpe_session_list.append(uri)
                    st.session_state.cpe_title_map[uri] = df.loc[df['cpeName']==uri, 'title'].iat[0]
                    count += 1
            st.success(f"Appended {count} CPE(s) to whitelist.")

    # Whitelist management (includes removal)
    if st.session_state.cpe_session_list:
        st.write("### CPE Whitelist")
        wl_df = pd.DataFrame([
            {'Title': st.session_state.cpe_title_map[c], 'cpeName': c}
            for c in st.session_state.cpe_session_list
        ])
        wl_df['remove'] = False
        with st.form('remove_form'):
            edited_wl = st.data_editor(
                wl_df[['remove','Title','cpeName']], use_container_width=True,
                hide_index=True, key='whitelist_editor', disabled=['Title','cpeName']
            )
            remove_btn = st.form_submit_button("Remove CPE(s) --click twice")
        if remove_btn:
            to_remove = edited_wl.loc[edited_wl['remove'], 'cpeName'].tolist()
            removed_count = 0
            for uri in to_remove:
                if uri in st.session_state.cpe_session_list:
                    st.session_state.cpe_session_list.remove(uri)
                    st.session_state.cpe_title_map.pop(uri, None)
                    removed_count += 1
            st.success(f"Removed {removed_count} CPE(s) from whitelist.")

        # Provide download
        final_wl = pd.DataFrame([
            {'Title': st.session_state.cpe_title_map[c], 'cpeName': c}
            for c in st.session_state.cpe_session_list
        ])
        st.download_button("Download Whitelist as CSV", final_wl.to_csv(index=False), file_name="whitelist.csv")

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
    cvss31 = metrics.get("cvssMetricV31", [{}])[0]
    cvss30 = metrics.get("cvssMetricV30", [{}])[0]
    cvss_data = cvss31.get("cvssData", {}) or cvss30.get("cvssData", {})
    exploit = cvss31.get("exploitabilityScore") or cvss30.get("exploitabilityScore")
    impact = cvss31.get("impactScore") or cvss30.get("impactScore")
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
        "title": st.session_state.cpe_title_map.get(cpe_uri, ""),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vectorString": cvss_data.get("vectorString"),
        "baseScore": cvss_data.get("baseScore"),
        "baseSeverity": cvss_data.get("baseSeverity"),
        "attackVector": cvss_data.get("attackVector"),
        "attackComplexity": cvss_data.get("attackComplexity"),
        "privilegesRequired": cvss_data.get("privilegesRequired"),
        "userInteraction": cvss_data.get("userInteraction"),
        "scope": cvss_data.get("scope"),
        "confidentialityImpact": cvss_data.get("confidentialityImpact"),
        "integrityImpact": cvss_data.get("integrityImpact"),
        "availabilityImpact": cvss_data.get("availabilityImpact"),
        "exploitabilityScore": exploit,
        "impactScore": impact,
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
                    "cveID": None, "cpeName": cpe, "title": st.session_state.cpe_title_map.get(cpe, ""),
                    "published": None, "last_modified": None, "vectorString": None, "baseScore": None,
                    "baseSeverity": None, "attackVector": None, "attackComplexity": None,
                    "privilegesRequired": None, "userInteraction": None, "scope": None,
                    "confidentialityImpact": None, "integrityImpact": None, "availabilityImpact": None,
                    "exploitabilityScore": None, "impactScore": None,
                    "cwes": None, "description": "NO CVEs FOUND FOR THIS ASSET", "references": None,
                    "tags": "NO CVEs", "full_json": None
                })
            progress_bar.progress(idx / len(cpe_list))

        df = pd.DataFrame(rows).drop_duplicates(subset=["cveID", "cpeName"]).reset_index(drop=True)

        # Display both whitelist and CVE results in tabs
        tab_wl, tab_res = st.tabs(["CPE Whitelist", "CVE Results"])

        with tab_wl:
            st.write("### Current CPE Whitelist")
            wl_df = pd.DataFrame([
                {'Title': st.session_state.cpe_title_map[c], 'cpeName': c}
                for c in st.session_state.cpe_session_list
            ])
            st.dataframe(wl_df)
            st.download_button("Download Whitelist as CSV", wl_df.to_csv(index=False), file_name="whitelist.csv")

        with tab_res:
            st.success(f"Done! {df.shape[0]:,} CVE–CPE rows collected")
            st.dataframe(df)
            st.download_button("Download Results as CSV", df.to_csv(index=False), "cve_results.csv")
    else:
        st.warning("Please upload a CPE whitelist or perform a search in 'Search & Save CPEs' mode.")

