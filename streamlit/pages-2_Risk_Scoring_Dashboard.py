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
import matplotlib.pyplot as plt
from utils.shared_functions import (
    weighted_average_score,
    multiplicative_risk_score,
    worst_case_score,
    simple_mean_score
)

# Page Configuration
st.set_page_config(page_title="Risk Scoring Dashboard", layout="wide")

# Title and Description
st.title("Cyber Risk Scoring Dashboard")
st.markdown(
    """
    Leverage multiple scoring methodologies to quantify vulnerability risk.  
    Upload your CVE results CSV to analyze and visualize scoring distributions.
    """
)

# File Upload
uploaded_file = st.file_uploader(
    label="Upload CVE Results CSV",
    type=["csv"],
    help="CSV generated from Asset Inventory & CVE Retrieval page"
)

if uploaded_file:
    # Data Ingestion
    df = pd.read_csv(uploaded_file)

    # Compute Scores
    df['weighted_score'] = df.apply(weighted_average_score, axis=1)
    df['multiplicative_score'] = df.apply(multiplicative_risk_score, axis=1)
    df['worst_case_score'] = df.apply(worst_case_score, axis=1)
    df['simple_mean_score'] = df.apply(simple_mean_score, axis=1)

    # Display Dataframe with Scores
    st.subheader("Scored CVE Dataset")
    st.dataframe(df)
    st.download_button(
        "Download Scored Results as CSV",
        df.to_csv(index=False),
        file_name="scored_cve_results.csv",
        mime="text/csv"
    )

    # Visualization Selector
    st.subheader("Score Distribution Visualization")
    score_option = st.selectbox(
        "Select Score Metric for Visualization:",
        [
            'weighted_score',
            'multiplicative_score',
            'worst_case_score',
            'simple_mean_score'
        ]
    )

    # Render Histogram
    fig, ax = plt.subplots()
    df[score_option].hist(ax=ax)
    ax.set_title(f"{score_option.replace('_', ' ').title()} Distribution")
    ax.set_xlabel("Score")
    ax.set_ylabel("Frequency")
    st.pyplot(fig)

else:
    st.info("Awaiting CSV upload to compute and visualize risk scores.")

