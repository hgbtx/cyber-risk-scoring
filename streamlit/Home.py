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
def main():
    # Landing page header
    st.title("Cyber Risk Intelligence Platform")
    
    # Executive summary and navigation hints
    st.markdown(
        """
        Welcome to the unified platform.  
        Use the sidebar to navigate between:
        - **Asset Inventory & CVE Retrieval**
        - **Risk Scoring Dashboard**
        """
    )

if __name__ == "__main__":
    main()
