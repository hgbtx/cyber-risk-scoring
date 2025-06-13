import streamlit as st  # Import Streamlit for interactive web apps
import pandas as pd  # Import pandas for data manipulation
import numpy as np  # Import numpy for numerical operations
import matplotlib.pyplot as plt  # Import matplotlib for static plotting
import seaborn as sns  # Import seaborn for advanced visualizations

# --- RISK FORMULAS ---  # Define risk scoring functions
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

# --- MAIN APP ---  # Streamlit dashboard configuration
st.title("Cyber Risk Scoring Dashboard")

# Persistent controls in sidebar for minimal scrolling
st.sidebar.header("Controls")
uploaded_file = st.sidebar.file_uploader("Upload Vulnerability CSV", type="csv")
formula = st.sidebar.selectbox("Risk Scoring Formula", list(formula_map.keys()))
aggregation = st.sidebar.selectbox("Aggregation Method", list(agg_map.keys()))
highrisk_threshold = st.sidebar.slider("High Risk CVE Threshold", 0.0, 10.0, 7.0, 0.1)

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    for col in ['baseScore', 'exploitabilityScore', 'impactScore']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Compute per-row risk scores
    df['riskScore'] = df.apply(formula_map[formula], axis=1)
    # Aggregate at Asset (Title) level without cpeName
    group = df.groupby('Title')
    agg_df = group['riskScore'].agg(agg_map[aggregation]).reset_index().rename(columns={'riskScore': f'{aggregation}RiskScore'})
    highrisk_df = group['riskScore'].apply(lambda x: (x >= highrisk_threshold).sum()).reset_index().rename(columns={'riskScore': f'HighRiskCount(>{highrisk_threshold})'})
    summary = pd.merge(agg_df, highrisk_df, on='Title')  # Merge on just Title

    # Construct tabs for each view
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
        top_assets = summary.sort_values(by=f'{aggregation}RiskScore', ascending=False).head(20).set_index('Title')
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
                year_range = st.slider("Select Year Range", int(min_year), int(max_year), (int(min_year), int(max_year)))
                df_f = df[(df['year'] >= year_range[0]) & (df['year'] <= year_range[1])]
                # Pivot table for counts
                base = df_f.groupby(['month', 'Title'])['cveID'].nunique().reset_index(name='New CVEs')
                sev = df_f.groupby(['month', 'Title', 'baseSeverity'])['cveID'].nunique().unstack(fill_value=0)
                # Ensure severity columns present
                for col in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if col not in sev.columns:
                        sev[col] = 0
                # Merge
                monthly_df = base.merge(sev.reset_index(), on=['month', 'Title'])
                # Sort for MoM calculation
                monthly_df = monthly_df.sort_values(['Title', 'month'])
                # Compute MoM % for New CVEs and each severity
                monthly_df['New CVEs MoM %'] = monthly_df.groupby('Title')['New CVEs'].pct_change().round(4) * 100
                for col in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    monthly_df[f'{col} MoM %'] = monthly_df.groupby('Title')[col].pct_change().round(4) * 100
                # Display chart first
                ts_pivot = monthly_df.pivot(index='month', columns='Title', values='New CVEs').fillna(0)
                fig, ax = plt.subplots(figsize=(10, 5))
                ts_pivot.plot(ax=ax)
                ax.set_xlabel("Month")
                ax.set_ylabel("Number of New CVEs")
                ax.legend(title='Asset', bbox_to_anchor=(1.05, 1), loc='upper left')
                st.pyplot(fig)
                # Display underlying data
                st.subheader("Time Series Data")
                st.dataframe(monthly_df[['month', 'Title', 'New CVEs', 'New CVEs MoM %',
                                         'CRITICAL', 'CRITICAL MoM %', 'HIGH', 'HIGH MoM %',
                                         'MEDIUM', 'MEDIUM MoM %', 'LOW', 'LOW MoM %']])
            else:
                st.warning("No valid publication years in data.")
        else:
            st.info("Required columns ('published', 'baseSeverity') not available for time series.")
