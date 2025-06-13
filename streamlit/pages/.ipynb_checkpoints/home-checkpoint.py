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

# Main page content
# st.image(r"C:\Users\hgbtx\Desktop\MIS433\final-project\cyber-risk-scoring\img\csf_wheel_v3.png")
st.sidebar.markdown("# Home")
st.write(
    "## NIST Cybersecurity Framework (CSF)\n"
    ">>_Cybersecurity risks are expanding constantly, and managing those risks must be a continuous process. This is true regardless of whether an organization is just beginning to confront its" "cybersecurity challenges or whether it has been active for many years with a sophisticated, well-resourced cybersecurity team._\n\n"
    ">>\- _[NIST](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)_\n\n"
    ">>_Cybersecurity is the guardian of our digital realm, preserving the confidentiality, integrity and availability of our data. It\'s the defensive frontline protecting supply chains," "physical infrastructure and external networks against unauthorized access and lurking threats.  Organizations that prioritize cyber resilience are better equipped to withstand attacks," "minimize operational disruptions, and maintain trust with stakeholders._\n\n"
    ">>\- _[Accenture](https://www.accenture.com/us-en/insights/cyber-security-index)_\n\n"
    "Organizations must have a framework for how they deal with both attempted and successful cyberattacks. One well-respected model, the NIST Cybersecurity Framework (CSF), explains how to" "identify attacks, protect systems, detect and respond to threats, and recover from successful attacks.\n\n" 
    "Prioritizing cyber resilency starts with understanding an organization\'s current cybersecurity risks. This is achieved via the \"Identify\" function of the CSF and broken down into three (3) main categories:\n"
    "* __Asset Management__:  \"Assets (e.g., data, hardware, software, systems, facilities, services, people) that enable the organization to achieve business purposes are identified and managed consistent with their relative importance to organizational objectives and the organization\'s risk strategy\" ([ID.AM](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=Asset%20Management%20(ID.AM)%3A%20Assets%20(e.g.%2C%20data%2C%20hardware%2C%20software%2C%20systems%2C%20facilities%2C%20services%2C%20people)%20that%20enable%20the%20organization%20to%20achieve%20business%20purposes%20are%20identified%20and%20managed%20consistent%20with%20their%20relative%20importance%20to%20organizational%20objectives%20and%20the%20organization%27s%20risk%20strategy))\n"
    "* __Risk Assessment__: \"The cybersecurity risk to the organization, assets, and individuals is understood by the organization\" ([ID.RA](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=Risk%20Assessment%20(ID.RA)%3A%20The%20cybersecurity%20risk%20to%20the%20organization%2C%20assets%2C%20and%20individuals%20is%20understood%20by%20the%20organization))\n"
    "* __Improvement__:  \"Improvements to organizational cybersecurity risk management processes, procedures and activities are identified across all CSF Functions\" ([ID.IM](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=Improvement%20(ID.IM)%3A%20Improvements%20to%20organizational%20cybersecurity%20risk%20management%20processes%2C%20procedures%20and%20activities%20are%20identified%20across%20all%20CSF%20Functions))\n"
)
# st.image(r"C:\Users\hgbtx\Desktop\MIS433\final-project\cyber-risk-scoring\img\csf_categories.png")