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
import streamlit as st
import csv
import time
import requests
import os
from pathlib import Path
from datetime import datetime

# --- config -----------------------------------------------------------
api_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
api_key = os.getenv("NVD_api_key")
rate_secs = 1.2
whitelist = Path("data/cpe_whitelist.csv")
header = ['WrittenAt', 'Title', 'cpeName']
UNDO_LOG = Path("data/cpe_undo_log.csv")
undo_header = ['UnwrittenAt', 'Title', 'cpeName']
# ----------------------------------------------------------------------

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
        response = requests.get(api_url, params=params, headers=headers)
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
            if cpe_uri:
                all_results.append({'title': title, 'cpeName': cpe_uri})
        total_results = data.get('totalResults', 0)
        start_index += results_per_page
        if start_index >= total_results:
            break
        time.sleep(rate_secs)
    return all_results

def write_entries_to_csv(entries, path, header):
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists() or os.path.getsize(path) == 0
    now = datetime.now().isoformat(timespec='milliseconds')
    rows_to_write = [[now, e['title'], e['cpeName']] for e in entries]
    with open(path, "a", newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if write_header:
            writer.writerow(header)
        writer.writerows(rows_to_write)
    return now, len(rows_to_write)

def log_removal_to_undo_log(removed_rows, undo_log, undo_header):
    undo_log.parent.mkdir(parents=True, exist_ok=True)
    undo_write_header = not undo_log.exists() or os.path.getsize(undo_log) == 0
    now = datetime.now().isoformat(timespec='milliseconds')
    rows_to_log = [[now, title, cpename] for _, title, cpename in removed_rows]
    with open(undo_log, "a", newline='', encoding='utf-8') as undofile:
        undowriter = csv.writer(undofile)
        if undo_write_header:
            undowriter.writerow(undo_header)
        undowriter.writerows(rows_to_log)

def undo_last_write(path, header, undo_log, undo_header):
    if not path.exists():
        st.warning("No whitelist file found.")
        return
    with open(path, "r", encoding='utf-8') as infile:
        lines = list(csv.reader(infile))
    if lines and lines[0] == header:
        header_row = lines[0]
        data_rows = lines[1:]
    else:
        header_row = header
        data_rows = lines
    if not data_rows:
        st.info("No record(s) found.")
        return
    last_written_at = data_rows[-1][0]
    rows_to_remove = [row for row in data_rows if row[0] == last_written_at]
    if not rows_to_remove:
        st.info("No record batch found.")
        return
    remaining_rows = [row for row in data_rows if row[0] != last_written_at]
    with open(path, "w", newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(header_row)
        writer.writerows(remaining_rows)
    log_removal_to_undo_log(rows_to_remove, undo_log, undo_header)
    st.success(f"Undid last write: removed {len(rows_to_remove)} rows.")

# --- Streamlit UI ---
st.title("CPE Inventory Tool")

mode = st.radio("Select an action:", ["Search & Save", "Undo Last Write"])

if mode == "Undo Last Write":
    if st.button("Undo Now"):
        undo_last_write(whitelist, header, UNDO_LOG, undo_header)

elif mode == "Search & Save":
    keyword_input = st.text_input("Enter comma-separated keywords:")
    if st.button("Search") and keyword_input:
        search_keywords = [kw.strip() for kw in keyword_input.split(',') if kw.strip()]
        all_results = []
        for keyword in search_keywords:
            st.write(f"Searching: **{keyword}**")
            matches = search_cpe_names(keyword)
            st.write(f"**{len(matches)}** result(s) found for '{keyword}'")
            for match in matches:
                st.write(f"• **{match['title']}**\n  - {match['cpeName']}")
            all_results.extend(matches)
        if all_results:
            if st.button(f"Save {len(all_results)} result(s) to file"):
                now, nrows = write_entries_to_csv(all_results, whitelist, header)
                st.success(f"{nrows} results saved at {now}")
