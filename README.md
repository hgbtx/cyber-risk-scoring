# Cyber Risk Scoring

Overview of Application Concepts

## Table of Contents

1. Introduction
    * Background and motivation
    * Topic selection justification
2. Data Description
    * Dataset source and collection process
    * Key variables, statistics (# rows and columns), and relevance to your project
3. Data Analysis
    * Summary of analysis results, including charts and insights
    * Key findings supporting application
4. Application Design
    * Main components of application:
        * dataset
        * APIs
        * OpenAI
    * Architecture or workflow diagram to show integration
5. Functions
    * Function 1
        * Purpose and user interaction
        * Integration of dataset, external API, and OpenAI
        * Use case screenshots showing outputs
    * Function 2
        * Purpose and user interaction
        * Integration of dataset, external API, and OpenAI
        * Use case screenshots showing outputs
    * Function 3
        * Purpose and user interaction
        * Integration of dataset, external API, and OpenAI
        * Use case screenshots showing outputs
6. Summary
    * Project goals, results, & value recap
    * Potential future enhancements
    * Key lessons learned

## Source Code - Notebook(s)

__Link:__ 

## 1. Introduction

### Background and motivation



### Topic selection justification



## 2. Data Description

### Dataset source

Data for this project was extracted using a framework provided by ManavKhambhayata & Ananya Verma at: \
https://www.kaggle.com/code/manavkhambhayata/cve-2024-database-extraction-framework/notebook

Modifications to the above framework were tailored to meet the specific needs of this project. The modified framework can be found at: \
https://github.com/hgbtx/cyber-risk-scoring/blob/main/notebooks/data-ingestion.ipynb

### Collection process

A static dataset was collected using the above-mentioned extraction framework and acts as the base dataset for the risk score model.

Initial Load: ingest a static dataset using the NVD API

Ongoing Sync:
* Use NVD API endpoint https://services.nvd.nist.gov/rest/json/cves/2.0 with startIndex & resultsPerPage to page through updates. 
* Extract fields: 
* Asset Mapping: Parse cpeMatchString to categorize CVEs into business-relevant asset groups (e.g., OS, web servers, databases)

### Key variables, statistics (# rows and columns), and relevance to your project



## 3. Data Analysis

### Analysis Results Summary (including charts and insights)



### Key Findings Supporting Application

* Heatmap: asset vs. RiskScore
* Bar Chart: Top 10 assets by score
* Time Series: monthly count of new CVEs per asset
* Pie Chart: distribution of severity levels (Critical/High/Medium/Low)

## 4. Application Design

### Dataset Design



### NIST's CVE (Common Vulnerabilities and Exposures) API



### OpenAI API



### Architecture/Workflow Diagram (to show integration)



## 5. Functions

### Function 1. Risk Scoring

For each asset category:
* Max Severity = highest CVSS base score
* Avg Severity = mean CVSS base score
* Vuln Count = total CVEs
* Composite Risk Score (normalized 0–1)

### Function 2. NVD API for Ongoing Access to Latest Vulnerabilities

_(Optional)_ VirusTotal API to flag which CVEs have known active exploits.

### OpenAI Features

1. Explain My Top Risk
    * Input: asset name
    * Output: “These CVEs pose the highest risk because…”, plus mitigation hints
2. Mitigation Roadmap
    * Input: list of high-risk CVEs or asset
    * Output: prioritized step-by-step action plan (patch, config hardening, monitoring)
3. Risk Trend Insights
    * Input: date range
    * Output: emerging risk patterns (e.g., “Web servers saw a 40% spike in Critical CVEs in Q1 2025…”)

## 6. Summary
















