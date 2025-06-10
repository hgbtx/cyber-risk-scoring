import streamlit as st
import pandas as pd
import requests

st.title("Asset Inventory (NIST CPE Search)")

search_term = st.text_input("Search for an asset (e.g., 'Windows 10', 'Cisco'):")

def search_cpe(keyword):
    url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keyword={keyword}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        cpes = []
        # Look for results in 'matches' (the current NIST API field)
        for item in data.get('matches', []):
            cpe_name = item.get('cpe23Uri', 'N/A')
            titles = item.get('titles', [])
            # Try to get the English title if available
            title = next((t['title'] for t in titles if t.get('lang') == 'en'), titles[0]['title'] if titles else cpe_name)
            cpes.append({
                "CPE Name": cpe_name,
                "Title": title,
            })
        return pd.DataFrame(cpes)
    else:
        st.error(f"Error fetching CPEs from NIST API. Status code: {response.status_code}")
        return pd.DataFrame()

if search_term:
    df = search_cpe(search_term)
    if not df.empty:
        st.write("Select CPE(s) to add to your inventory:")
        selected = st.multiselect("Choose CPEs:", df["CPE Name"])
        if selected:
            selected_df = df[df["CPE Name"].isin(selected)]
            st.dataframe(selected_df)
            if st.button("Save to CSV"):
                selected_df.to_csv("selected_cpes.csv", index=False)
                st.success("Saved to selected_cpes.csv!")
    else:
        st.info("No CPEs found for that search term.")

st.markdown("---")
st.info("Search for assets, select relevant CPEs, and save your inventory.")