import streamlit as st

# --- Streamlit UI Setup ---
st.set_page_config(layout="wide")

# Define the pages
main_page = st.Page("home.py", title="Home")
page_2 = st.Page("page_2.py", title="CPE/CVE Retrieval Tool")
page_3 = st.Page("page_3.py", title="Risk Scoring Dashboard")

# Set up navigation
pg = st.navigation([main_page, page_2, page_3])

# Run the selected page
pg.run()