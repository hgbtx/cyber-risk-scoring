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
import time
import requests
import pandas as pd
import numpy as np

# --- CPE/CVE Retrieval Configuration ---
API_URL_CPE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
API_URL_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_SECS = 1.2
PER_PAGE = 2000
PROGRESS_EVERY = 25


def search_cpe_names(keyword: str, api_key: str) -> list[dict]:
    """
    Search NVD for CPE names matching a keyword.
    """
    results = []
    start = 0
    headers = {"apiKey": api_key}
    while True:
        params = {"keywordSearch": keyword, "resultsPerPage": PER_PAGE, "startIndex": start}
        response = requests.get(API_URL_CPE, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        cpes = data.get("results", [])
        if not cpes:
            break
        results.extend(cpes)
        start += PER_PAGE
        if len(results) % PROGRESS_EVERY == 0:
            print(f"Retrieved {len(results)} CPEs so far...")
        time.sleep(RATE_SECS)
    return results


def fetch_cves_for_cpe(cpe_uri: str, api_key: str) -> list[dict]:
    """
    Fetch CVEs associated with a given CPE URI.
    """
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return []
    cpe_query = ":".join(parts[:6]) if parts[5] == "*" else cpe_uri
    results = []
    start = 0
    headers = {"apiKey": api_key}
    while True:
        params = {"cpeMatchString": cpe_query, "resultsPerPage": PER_PAGE, "startIndex": start}
        response = requests.get(API_URL_CVE, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        cve_items = data.get("results", [])
        if not cve_items:
            break
        results.extend(cve_items)
        start += PER_PAGE
        time.sleep(RATE_SECS)
    return results


def flatten(cve_item: dict, cpe_uri: str) -> dict:
    """
    Flatten a CVE item into a dict with key metrics and associated CPE URI.
    """
    flattened = {
        "cve_id": cve_item.get("cve", {}).get("CVE_data_meta", {}).get("ID"),
        "description": cve_item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value"),
        "references": [ref.get("url") for ref in cve_item.get("cve", {}).get("references", {}).get("reference_data", [])],
        "cpe_uri": cpe_uri,
    }
    metrics = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
    flattened.update({
        "baseScore": metrics.get("baseScore"),
        "exploitabilityScore": metrics.get("exploitabilityScore"),
        "impactScore": metrics.get("impactScore"),
        "vectorString": metrics.get("vectorString"),
    })
    return flattened


# --- Risk Scoring Formulas ---

def weighted_average_score(row, weights=None):
    """
    Calculate a weighted average of CVSS components.
    """
    if weights is None:
        weights = {'baseScore': 0.5, 'exploitabilityScore': 0.25, 'impactScore': 0.25}
    vals = [(row.get(col), w) for col, w in weights.items() if pd.notnull(row.get(col))]
    if not vals:
        return np.nan
    total_weight = sum(w for _, w in vals)
    return round(sum(v * w for v, w in vals) / total_weight, 2)


def multiplicative_risk_score(row):
    """
    Calculate risk as product of normalized CVSS components.
    """
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    if any(pd.isnull(v) for v in vals):
        return np.nan
    vals_norm = [v / 10.0 for v in vals]
    return round(np.prod(vals_norm) * 10, 2)


def worst_case_score(row):
    """
    Return the maximum of available CVSS component scores.
    """
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    vals = [v for v in vals if pd.notnull(v)]
    return max(vals) if vals else np.nan


def simple_mean_score(row):
    """
    Compute arithmetic mean of CVSS component scores.
    """
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    vals = [v for v in vals if pd.notnull(v)]
    if not vals:
        return np.nan
    return round(sum(vals) / len(vals), 2)
