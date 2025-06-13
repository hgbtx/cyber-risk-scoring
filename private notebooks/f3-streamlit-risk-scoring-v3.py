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
# streamlit_risk_scoring_app.py

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os

# --- Helper Functions ---
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

# --- Main App ---
st.title("Cyber Risk Scoring Dashboard")

uploaded_file = st.file_uploader("Upload CVE Dataset CSV", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    for col in ['baseScore', 'exploitabilityScore', 'impactScore']:
        df[col] = pd.to_numeric(df.get(col), errors='coerce')

    if 'published' in df.columns:
        df['published'] = pd.to_datetime(df['published'], errors='coerce')
        df['month'] = df['published'].dt.to_period('M').astype(str)
        df['year'] = df['published'].dt.year

        min_year, max_year = df['year'].min(), df['year'].max()
        year_range = st.slider("Select Year Range", min_value=int(min_year), max_value=int(max_year), value=(int(min_year), int(max_year)))

        # Time Series Plot
        df_filtered = df[(df['year'] >= year_range[0]) & (df['year'] <= year_range[1])]
        monthly_cves = df_filtered.groupby(['month', 'Title'])['cveID'].nunique().unstack(fill_value=0)
        if not monthly_cves.empty:
            st.line_chart(monthly_cves)

        # Risk Score Computation
        formula = st.selectbox("Select Risk Formula", list(formula_map.keys()))
        aggregation = st.selectbox("Select Aggregation Method", list(agg_map.keys()))
        highrisk_threshold = st.slider("High Risk CVE Threshold", 0.0, 10.0, 7.0, 0.1)

        df['riskScore'] = df.apply(formula_map[formula], axis=1)

        grouped = df.groupby(['Title', 'cpeName'])
        agg_df = grouped['riskScore'].agg(agg_map[aggregation]).reset_index()
        agg_df = agg_df.rename(columns={'riskScore': f'{aggregation}RiskScore'})
        highrisk_df = grouped['riskScore'].apply(lambda x: (x >= highrisk_threshold).sum()).reset_index()
        highrisk_df = highrisk_df.rename(columns={'riskScore': f'countHighRiskCVEs (>{highrisk_threshold})'})

        summary = pd.merge(agg_df, highrisk_df, on='cpeName', how='left')
        summary.insert(0, "Title", summary.pop("Title"))

        st.subheader("Asset-Level Risk Summary")
        st.dataframe(summary)

        st.subheader("Top 20 CVE-Level Risk Scores")
        top_cves = df[['Title', 'cpeName', 'cveID', 'riskScore']].sort_values(by='riskScore', ascending=False).head(20)
        st.dataframe(top_cves)

        st.subheader("Severity Level Distribution")
        if 'baseSeverity' in df.columns:
            severity_counts = df['baseSeverity'].value_counts()
            fig1, ax1 = plt.subplots()
            ax1.pie(severity_counts, labels=severity_counts.index, autopct='%1.1f%%', startangle=140)
            ax1.set_title("Distribution of Severity Levels")
            st.pyplot(fig1)

        st.subheader("Top 20 Assets Heatmap")
        top_assets = summary.sort_values(by=f'{aggregation}RiskScore', ascending=False).head(20)
        heatmap_data = top_assets.set_index('Title')[[f'{aggregation}RiskScore']]
        fig2, ax2 = plt.subplots(figsize=(2, 10))
        sns.heatmap(heatmap_data, annot=True, cmap='YlOrRd', ax=ax2)
        st.pyplot(fig2)

    else:
        st.warning("The uploaded dataset must include a 'published' column with datetime values.")

