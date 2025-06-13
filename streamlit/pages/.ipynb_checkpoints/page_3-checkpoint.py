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
import streamlit as st  # Import Streamlit for building interactive web applications
import pandas as pd  # Import pandas for data manipulation and analysis
import numpy as np  # Import numpy for numerical operations
import matplotlib.pyplot as plt  # Import matplotlib for creating static plots
import seaborn as sns  # Import seaborn for enhanced statistical visualizations
import math  # Import math for calculating legend row count

# --- RISK FORMULAS ---  # Define functions to calculate various risk scores per vulnerability record

def weighted_average_score(row, weights=None):
    # Calculate a weighted average of available CVSS components
    if weights is None:
        weights = {'baseScore': 0.5, 'exploitabilityScore': 0.25, 'impactScore': 0.25}
    vals = [(row.get(col), w) for col, w in weights.items() if pd.notnull(row.get(col))]
    if not vals:
        return np.nan
    score = sum(v * w for v, w in vals)
    total_weight = sum(w for _, w in vals)
    return round(score / total_weight, 2)


def multiplicative_risk_score(row):
    # Calculate risk as product of normalized CVSS components
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    if any(pd.isnull(v) for v in vals):
        return np.nan
    vals_norm = [v / 10.0 for v in vals]
    score = np.prod(vals_norm) * 10
    return round(score, 2)


def worst_case_score(row):
    # Return the maximum of available CVSS component scores
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    vals = [v for v in vals if pd.notnull(v)]
    if not vals:
        return np.nan
    return max(vals)


def simple_mean_score(row):
    # Compute arithmetic mean of available CVSS component scores
    vals = [row.get(col) for col in ['baseScore', 'exploitabilityScore', 'impactScore']]
    vals = [v for v in vals if pd.notnull(v)]
    if not vals:
        return np.nan
    return round(np.mean(vals), 2)

# Map user-friendly formula names to functions
formula_map = {
    'Weighted Average': weighted_average_score,
    'Multiplicative': multiplicative_risk_score,
    'Worst Case (Max)': worst_case_score,
    'Simple Mean': simple_mean_score,
}

# Map aggregation options to pandas aggregation methods
agg_map = {
    'Max': 'max',
    'Mean': 'mean',
    'Median': 'median',
    'Sum': 'sum',
}

# --- MAIN APP ---  # Configure the Streamlit dashboard layout and controls
# Main page content
st.markdown("# Risk Scoring Dashboard")
st.sidebar.markdown("# Risk Scoring Dashboard")
st.write(
    "### Not sure what combination of risk formula, aggregation method, or risk tolerance threshold is right for you?\n\n"
    "#### Check out this convenient table to help you get started!\n\n"
)
st.divider()
st.write(
    "### _Common Risk Philosophies_"
)

base = os.path.dirname(__file__)
csv_path = os.path.join(base, "data", "risk_philosophy.csv")
risk_philosophy = pd.read_csv(csv_path)
st.table(risk_philosophy)



# Sidebar controls for uploading data and selecting parameters
st.sidebar.header("Controls")
uploaded_file = st.sidebar.file_uploader("Upload Vulnerability CSV", type="csv")
formula = st.sidebar.selectbox("Risk Scoring Formula", list(formula_map.keys()))
aggregation = st.sidebar.selectbox("Aggregation Method", list(agg_map.keys()))
highrisk_threshold = st.sidebar.slider(
    "High Risk CVE Threshold", 0.0, 10.0, 7.0, 0.1
)

# Process uploaded file once available
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    for col in ['baseScore', 'exploitabilityScore', 'impactScore']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df['riskScore'] = df.apply(formula_map[formula], axis=1)
    group = df.groupby('Title')
    agg_df = (
        group['riskScore']
        .agg(agg_map[aggregation])
        .reset_index()
        .rename(columns={'riskScore': f'{aggregation}RiskScore'})
    )
    highrisk_df = (
        group['riskScore']
        .apply(lambda x: (x >= highrisk_threshold).sum())
        .reset_index()
        .rename(columns={'riskScore': f'HighRiskCount(>{highrisk_threshold})'})
    )
    summary = pd.merge(agg_df, highrisk_df, on='Title')

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Asset Summary", "CVE Summary", "Heatmap", "Severity Distribution", "Time Series"
    ])

    with tab1:
        st.subheader("Asset-level Risk Summary")
        st.dataframe(summary)
        st.download_button(
            label="Download Asset Summary CSV",
            data=summary.to_csv(index=False),
            file_name='asset_risk_summary.csv',
            mime='text/csv'
        )

    with tab2:
        st.subheader("CVE-level Vulnerabilities Summary")
        vuln_df = df[['Title', 'cveID', 'riskScore']]
        st.dataframe(vuln_df)
        st.download_button(
            label="Download CVE Summary CSV",
            data=vuln_df.to_csv(index=False),
            file_name='cve_vuln_summary.csv',
            mime='text/csv'
        )

    with tab3:
        st.subheader(f"Top 20 Assets by {aggregation} Risk Score")
        top_assets = (
            summary.sort_values(by=f'{aggregation}RiskScore', ascending=False)
            .head(20)
            .set_index('Title')
        )
        fig, ax = plt.subplots(figsize=(6, 6))
        sns.heatmap(top_assets[[f'{aggregation}RiskScore']], annot=True, cmap='YlOrRd', cbar=True, ax=ax)
        ax.set_ylabel("Asset")
        ax.set_xlabel(f"{aggregation} Risk Score")
        st.pyplot(fig)

    with tab4:
        st.subheader("Distribution of Severity Levels")
        if 'baseSeverity' in df.columns:
            severity_counts = df['baseSeverity'].value_counts()
            severity_df = severity_counts.reset_index()
            severity_df.columns = ['Severity', 'Count']
            st.subheader("Severity Level Data")
            st.dataframe(severity_df)
            fig, ax = plt.subplots()
            severity_counts.plot(kind='pie', autopct='%1.1f%%', startangle=140, ax=ax)
            ax.set_ylabel("")
            st.pyplot(fig)
        else:
            st.info("No 'baseSeverity' column found in data.")

    with tab5:
        st.subheader("Monthly Count of New CVEs per Asset")
        if 'published' in df.columns and 'baseSeverity' in df.columns:
            df['published'] = pd.to_datetime(df['published'], errors='coerce')
            df['month'] = df['published'].dt.to_period('M').astype(str)
            df['year'] = df['published'].dt.year

            years = sorted(df['year'].dropna().unique())
            if years:
                min_year, max_year = years[0], years[-1]
                year_range = st.slider(
                    "Select Year Range", int(min_year), int(max_year), (int(min_year), int(max_year))
                )
                df_f = df[(df['year'] >= year_range[0]) & (df['year'] <= year_range[1])]

                base = df_f.groupby(['month', 'Title'])['cveID'].nunique().reset_index(name='New CVEs')
                sev = df_f.groupby(['month', 'Title', 'baseSeverity'])['cveID'].nunique().unstack(fill_value=0)
                for col in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if col not in sev.columns:
                        sev[col] = 0
                monthly_df = base.merge(sev.reset_index(), on=['month', 'Title']).sort_values(['Title', 'month'])
                monthly_df['New CVEs MoM %'] = monthly_df.groupby('Title')['New CVEs'].pct_change().round(4) * 100
                for col in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    monthly_df[f'{col} MoM %'] = monthly_df.groupby('Title')[col].pct_change().round(4) * 100

                ts_pivot = monthly_df.pivot(index='month', columns='Title', values='New CVEs').fillna(0)

                assets = sorted(ts_pivot.columns)
                # Use multiselect for asset selection
                selected_assets = st.multiselect(
                    "Select Assets to Display", options=assets, default=assets
                )

                if not selected_assets:
                    st.warning("Please select at least one asset to display.")
                else:
                    ts_filtered = ts_pivot[selected_assets]
                    # Compute legend wrap parameters
                    max_cols = 2  # Maximum columns per legend row
                    labels = ts_filtered.columns.tolist()
                    rows = math.ceil(len(labels) / max_cols)
                    # Create mosaic with dynamic legend row height
                    fig, ax_dict = plt.subplot_mosaic(
                        [["chart", "chart"], ["legend", "legend"]],
                        figsize=(10, 6),
                        gridspec_kw={'height_ratios': [8, rows]}
                    )
                    # Plot time series lines without internal legend
                    ts_filtered.plot(ax=ax_dict['chart'], legend=False)
                    ax_dict['chart'].set_xlabel("Month")
                    ax_dict['chart'].set_ylabel("Number of New CVEs")

                    # Prepare legend in bottom subplot
                    handles, _ = ax_dict['chart'].get_legend_handles_labels()
                    ax_dict['legend'].axis('off')  # Hide axes for legend area
                    ax_dict['legend'].legend(
                        handles,
                        labels,
                        title='Asset',
                        loc='center',
                        ncol=max_cols,
                        mode='expand',
                        borderaxespad=0.
                    )
                    # Adjust layout to prevent overlap
                    fig.tight_layout()
                    fig.subplots_adjust(hspace=0.2)
                    st.pyplot(fig)

                    filtered_monthly = monthly_df[monthly_df['Title'].isin(selected_assets)]
                    st.subheader("Time Series Data")
                    st.dataframe(filtered_monthly[[
                        'month', 'Title', 'New CVEs', 'New CVEs MoM %',
                        'CRITICAL', 'CRITICAL MoM %', 'HIGH', 'HIGH MoM %',
                        'MEDIUM', 'MEDIUM MoM %', 'LOW', 'LOW MoM %'
                    ]])
            else:
                st.warning("No valid publication years in data.")
        else:
            st.info("Required columns ('published', 'baseSeverity') not available for time series.")

