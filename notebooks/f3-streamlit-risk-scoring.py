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
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os

# --- RISK FORMULAS ---
def weighted_average_score(row, weights=None):
    if weights is None:
        weights = {'baseScore': 0.5, 'exploitabilityScore': 0.25, 'impactScore': 0.25}
    vals = [(row.get(col), w) for col, w in weights.items() if pd.notnull(row.get(col))]
    if not vals:
        return np.nan
    score = sum(v * w for v, w in vals)
    total_weight = sum(w for _, w in vals)
    return round(score / total_weight, 2)

def multiplicative_risk_score(row):
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    if any(pd.isnull(v) for v in vals):
        return np.nan
    vals_norm = [v / 10.0 for v in vals]
    score = np.prod(vals_norm) * 10
    return round(score, 2)

def worst_case_score(row):
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    vals = [v for v in vals if pd.notnull(v)]
    if not vals:
        return np.nan
    return max(vals)

def simple_mean_score(row):
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    vals = [v for v in vals if pd.notnull(v)]
    if not vals:
        return np.nan
    return round(np.mean(vals), 2)

formula_map = {
    'Weighted Average': weighted_average_score,
    'Multiplicative': multiplicative_risk_score,
    'Worst Case (Max)': worst_case_score,
    'Simple Mean': simple_mean_score,
}

agg_map = {
    'Max': 'max',
    'Mean': 'mean',
    'Median': 'median',
    'Sum': 'sum',
}

def count_high_risk(series, threshold=7.0):
    return (series >= threshold).sum()

# --- MAIN APP ---
st.title("Cyber Risk Scoring Tool")

uploaded_file = st.file_uploader("Upload your vulnerability CSV file", type="csv")

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    for col in ['baseScore', 'exploitabilityScore', 'impactScore']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    formula = st.selectbox("Select Risk Scoring Formula", list(formula_map.keys()))
    aggregation = st.selectbox("Select Aggregation Method", list(agg_map.keys()))
    highrisk_threshold = st.slider("Set High Risk CVE Threshold", 0.0, 10.0, 7.0, 0.1)

    # Risk scoring and summary
    df['riskScore'] = df.apply(formula_map[formula], axis=1)
    group = df.groupby(['Title', 'cpeName'])
    agg_df = group['riskScore'].agg(agg_map[aggregation]).reset_index()
    agg_df = agg_df.rename(columns={'riskScore': f'{aggregation}RiskScore'})

    highrisk_df = group['riskScore'].apply(lambda x: (x >= highrisk_threshold).sum()).reset_index()
    highrisk_df = highrisk_df.rename(columns={'riskScore': f'countHighRiskCVEs (>{highrisk_threshold})'})

    summary = pd.merge(agg_df, highrisk_df, on='cpeName', how='left')
    summary['Title'] = summary['Title_x']
    summary.drop(columns=['Title_x', 'Title_y'], inplace=True, axis=1, errors='ignore')
    summary.insert(0, "Title", summary.pop("Title"))

    st.subheader("Asset-level Risk Summary")
    st.dataframe(summary.head(20))

    st.download_button(
        label="Download Asset Summary as CSV",
        data=summary.to_csv(index=False),
        file_name='asset_risk_summary.csv',
        mime='text/csv'
    )

    st.subheader("CVE-level Vulnerabilities Summary")
    vuln_df = df[['Title', 'cpeName', 'cveID', 'riskScore']]
    st.dataframe(vuln_df.head(20))

    st.download_button(
        label="Download CVE Summary as CSV",
        data=vuln_df.to_csv(index=False),
        file_name='cve_vuln_summary.csv',
        mime='text/csv'
    )

    st.subheader("Distribution of Severity Levels")
    severity_counts = df['baseSeverity'].value_counts()
    fig1, ax1 = plt.subplots()
    severity_counts.plot(kind='pie', autopct='%1.1f%%', startangle=140, ax=ax1)
    ax1.set_title("Distribution of Severity Levels")
    ax1.set_ylabel("")
    st.pyplot(fig1)

    st.subheader("Top 20 Assets by Risk Score")
    top_assets = summary.sort_values(by=f'{aggregation}RiskScore', ascending=False).head(20)
    heatmap_data = top_assets.set_index('Title')[[f'{aggregation}RiskScore']]
    fig2, ax2 = plt.subplots(figsize=(2, 10))
    sns.heatmap(heatmap_data, annot=True, cmap='YlOrRd', cbar=True, ax=ax2)
    ax2.set_title(f"Heatmap: Top 20 Assets by {aggregation} Risk Score (Formula: {formula})")
    ax2.set_xlabel(f"{aggregation} Risk Score")
    ax2.set_ylabel("Asset (Title)")
    st.pyplot(fig2)

    if 'published' in df.columns:
        df['published'] = pd.to_datetime(df['published'], errors='coerce')
        df['month'] = df['published'].dt.to_period('M').astype(str)
        df['year'] = df['published'].dt.year
        years = sorted(df['year'].dropna().unique())
        if years:
            min_year, max_year = int(min(years)), int(max(years))
            year_range = st.slider("Select Year Range", min_value=min_year, max_value=max_year, value=(min_year, max_year))

            df_filtered = df[(df['year'] >= year_range[0]) & (df['year'] <= year_range[1])]
            monthly_cves = df_filtered.groupby(['month', 'Title'])['cveID'].nunique().unstack(fill_value=0)
            if not monthly_cves.empty:
                st.subheader("Monthly Count of New CVEs per Asset")
                fig3, ax3 = plt.subplots(figsize=(14, 7))
                monthly_cves.plot(ax=ax3)
                ax3.set_title(f"Monthly Count of New CVEs per Asset ({year_range[0]}-{year_range[1]})")
                ax3.set_ylabel("Number of New CVEs")
                ax3.set_xlabel("Month")
                ax3.legend(title='Asset', bbox_to_anchor=(1.05, 1), loc='upper left')
                st.pyplot(fig3)
            else:
                st.info(f"No data available for the selected year range: {year_range[0]}-{year_range[1]}")
        else:
            st.warning("No valid years found in the data.")

