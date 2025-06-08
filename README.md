# Still Needed
* Key variables, statistics (# rows and columns), and relevance to your project
* Summary of analysis results, including charts and insights
* Architecture or workflow diagram to show integration
* Use case screenshots showing outputs for each feature
5. Summary
    * Project goals, results, & value recap
    * Key lessons learned

# 1. Introduction

![csfwheel](../img/csf_wheel_v3.png)

## NIST Cybersecurity Framework (CSF)

***

>>_Cybersecurity risks are expanding constantly, and managing those risks must be a continuous process. This is true regardless of whether an organization is just beginning to confront its cybersecurity challenges or whether it has been active for many years with a sophisticated, well-resourced cybersecurity team._
>>
>>\- _[NIST](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)_

>>_Cybersecurity is the guardian of our digital realm, preserving the confidentiality, integrity and availability of our data. It's the defensive frontline protecting supply chains, physical infrastructure and external networks against unauthorized access and lurking threats.  Organizations that prioritize cyber resilience are better equipped to withstand attacks, minimize operational disruptions, and maintain trust with stakeholders._\
\
\- _[Accenture](https://www.accenture.com/us-en/insights/cyber-security-index)_

Organizations must have a framework for how they deal with both attempted and successful cyberattacks. One well-respected model, the NIST Cybersecurity Framework (CSF), explains how to identify attacks, protect systems, detect and respond to threats, and recover from successful attacks. 

Like NIST's CSF, the intended audience for this application tool include individuals:
>>_responsible for developing and leading cybersecurity programs and/or involved in managing risk — including executives, boards of directors, acquisition professionals, technology professionals, risk managers, lawyers, human resources specialists, and cybersecurity and risk management auditors — to guide their cybersecurity-related decisions._\
\
\- _[National Institute of Standards and Technology (NIST)](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)_

Prioritizing cyber resilency starts with understanding an organization's current cybersecurity risks. This is achieved via the "Identify" function of the CSF and broken down into three (3) main categories:
* __Asset Management__:  "Assets (e.g., data, hardware, software, systems, facilities, services, people) that enable the organization to achieve business purposes are identified and managed consistent with their relative importance to organizational objectives and the organization's risk strategy" ([ID.AM](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=Asset%20Management%20(ID.AM)%3A%20Assets%20(e.g.%2C%20data%2C%20hardware%2C%20software%2C%20systems%2C%20facilities%2C%20services%2C%20people)%20that%20enable%20the%20organization%20to%20achieve%20business%20purposes%20are%20identified%20and%20managed%20consistent%20with%20their%20relative%20importance%20to%20organizational%20objectives%20and%20the%20organization%27s%20risk%20strategy))
* __Risk Assessment__: "The cybersecurity risk to the organization, assets, and individuals is understood by the organization" ([ID.RA](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=Risk%20Assessment%20(ID.RA)%3A%20The%20cybersecurity%20risk%20to%20the%20organization%2C%20assets%2C%20and%20individuals%20is%20understood%20by%20the%20organization))
* __Improvement__:  "Improvements to organizational cybersecurity risk management processes, procedures and activities are identified across all CSF Functions" ([ID.IM](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=Improvement%20(ID.IM)%3A%20Improvements%20to%20organizational%20cybersecurity%20risk%20management%20processes%2C%20procedures%20and%20activities%20are%20identified%20across%20all%20CSF%20Functions))

![csfwheel](../img/csf_categories.png)

## Project Objective 
------

#### Prototype a tool that supports _asset management_ and _risk assessment_ within the __Identify__ function of NIST's Cybersecurity Framework.
\
The tool will support _asset management_ by:
* ingesting user-defined common platform enumerations (CPE) using NIST's CPE API to inventory
    * "hardware managed by the organization" ([ID.AM-01](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.AM%2D01%3A%20Inventories%20of%20hardware%20managed%20by%20the%20organization%20are%20maintained))
    * "software, services, and systems managed by the organization" by  ([ID.AM-02](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.AM%2D02%3A%20Inventories%20of%20software%2C%20services%2C%20and%20systems%20managed%20by%20the%20organization%20are%20maintained))
    * "services provided by suppliers" ([ID.AM-04](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.AM%2D04%3A%20Inventories%20of%20services%20provided%20by%20suppliers%20are%20maintained))
* prioritizing assets "based on classification, criticality, resources, and impact on the mission" ([ID.AM-05](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.AM%2D05%3A%20Assets%20are%20prioritized%20based%20on%20classification%2C%20criticality%2C%20resources%2C%20and%20impact%20on%20the%20mission))

The tool will support _risk assessment_ by:
* identifying, validating, and recording "vulnerabilities in assets" using NIST's Common Vulnerabilities & Exploitations (CVE) API ([ID.RA-01](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D01%3A%20Vulnerabilities%20in%20assets%20are%20identified%2C%20validated%2C%20and%20recorded); [ID.RA-02](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D02%3A%20Cyber%20threat%20intelligence%20is%20received%20from%20information%20sharing%20forums%20and%20sources))
* analyzing vulnerablity risks via: ([ID.RA-04](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D04%3A%20Potential%20impacts%20and%20likelihoods%20of%20threats%20exploiting%20vulnerabilities%20are%20identified%20and%20recorded); [ID.RA-06](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D06%3A%20Risk%20responses%20are%20chosen%2C%20prioritized%2C%20planned%2C%20tracked%2C%20and%20communicated); [ID.RA-07](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D07%3A%20Changes%20and%20exceptions%20are%20managed%2C%20assessed%20for%20risk%20impact%2C%20recorded%2C%20and%20tracked); [ID.RA-08](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D08%3A%20Processes%20for%20receiving%2C%20analyzing%2C%20and%20responding%20to%20vulnerability%20disclosures%20are%20established); [ID.RA-09](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D09%3A%20The%20authenticity%20and%20integrity%20of%20hardware%20and%20software%20are%20assessed%20prior%20to%20acquisition%20and%20use)):
    * mapping CVE severity scores for user defined CPEs
    * computing a composite risk score per asset/business unit
* uses an AI assistant to ([ID.RA-04](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D04%3A%20Potential%20impacts%20and%20likelihoods%20of%20threats%20exploiting%20vulnerabilities%20are%20identified%20and%20recorded); [ID.RA-06](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D06%3A%20Risk%20responses%20are%20chosen%2C%20prioritized%2C%20planned%2C%20tracked%2C%20and%20communicated); [ID.RA-07](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D07%3A%20Changes%20and%20exceptions%20are%20managed%2C%20assessed%20for%20risk%20impact%2C%20recorded%2C%20and%20tracked); [ID.RA-08](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D08%3A%20Processes%20for%20receiving%2C%20analyzing%2C%20and%20responding%20to%20vulnerability%20disclosures%20are%20established); [ID.RA-09](https://csrc.nist.gov/Projects/Cybersecurity-Framework/Filters#/csf/filters:~:text=ID.RA%2D09%3A%20The%20authenticity%20and%20integrity%20of%20hardware%20and%20software%20are%20assessed%20prior%20to%20acquisition%20and%20use)):
    * summarize highest-risk vulnerablities
    * generate mitigation roadmap

## Data Description

The core dataset driving this application is user-defined. Each user supplies a customized whitelist of software products to ingest CPEs using Feature 1 of the tool. In other words, the application itself generates the dataset at runtime rather than relying on a fixed third-party file. This bakes in versatility as a core component.

#### Why This Approach
* __Tailored Relevance__: Users see only vulnerabilities that apply to their stack—no noise from unrelated products.
* __Privacy__: Because the whitelist is entered directly into the app and never leaves the tenancy, no proprietary system details are exposed to third parties.
* __Freshness on Demand__: The ETL job re-runs automatically whenever the whitelist changes, so the dataset is always in sync with the user’s current environment. <--- in an ideal world
* __Pedagogical Fit__: Demonstrates the full “Extract → Transform → Load” pattern even though the extract phase starts with user data rather than a public file.

## Key Features of the Application Tool
***
- Aggregate count, avg CVSS, max CVSS.
- Min-max normalise and combine (50 % max, 30 % avg, 20 % count) into a 0–1 composite score.

Feature ID | Feature Name | Key Component(s) | What it does |
| ------------ | ------------| ------------| ------------|
| F1 | __Asset Inventory__ | CPE API, Save to File, User Input Required | • Prompts end-user to keyword search an asset (e.g. software, operating system component, hardware)<br>• Returns a list of CPEs (includes partial matches)<br>• Prompts user to save/append list to CSV file<br>• Returns to keyword search prompt<br>• User types 'exit' to terminate search |
| F2 | __Vulnerabilities Identification__ | CVE API, Save to File, User Input Required | • Loads CSV file generated in F1<br>• Returns a list of CVEs<br>• Prompts user to save/append to file |
| F3 | __Risk Evaluation__ | Risk Scoring Module, Performs Risk Calculation, Appends to File | • Loads file generated in F1<br>• computing a composite risk score per asset/business unit<br>• Adds/appends risk score columns to file <br>• maps CVE severity scores for user defined assets |
| F4 | __Mitigation Recommendations__ | OpenAI API, 4o mini GPT, generates recommendations | Given the top-N CVEs for an asset:<br>• produce plain-English impact summaries and step-by-step mitigation roadmaps. |

#### __(ETL)__: _Extract = get it, Tranform = fix it, Load = store it_ 

| Stage | What happens | In the cyber-risk project tool |
| ------------ | ------------ | ------------ |
| **Extract**| Pull raw data from one or more source systems.| • Call the CPE API to ingest user-defined CPEs<br>• Call the NVD CVE REST API and read CPE whitelist CSV. |
| **Transform** | Clean, normalize, filter, or enrich the data so it’s useful downstream. Typical tasks include type-casting, deduping, deriving new fields, joining look-up tables, and calculating metrics. | • Flatten the nested JSON returned by NVD.<br>• Deduplicate identical CVEs.<br>• Join each CVE to an *asset\_group* from your mapping table. <-- in an ideal world<br>• Calculate helper columns such as *baseScore* or *severity bucket*. |
| **Load**| Write the transformed data into a target store (database, parquet file, cloud warehouse) where analytics or apps can use it efficiently. | Persist the cleaned DataFrame to **`smb_cves.parquet`** so your Pandas risk-scoring step and Streamlit dashboard can read it in milliseconds. <-- in an ideal world  


## Potential Future Enhancements

### Higher Level Architecture

| Layer                         | Key Components                                              | Responsibilities                                                                                                                                                            |
| ----------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Data Sources**              | *CPE Whitelist (CSV)*, *NVD CVE REST API*                   | Provide the authoritative list of software (whitelist) and the raw vulnerability data.                                                                                      |
| **Ingestion & ETL**           | `fetch_cves` Python script, Cron/Task Scheduler             | - Pull CVEs for each CPE in batches (2 000 rows/page).<br>- Respect NVD rate-limits (50 req/30 s with an API key).<br>- Persist results as incremental parquet files.       |
| **Storage**                   | `smb_cves.parquet`, mapping tables (`asset_group`, weights) | Compact, columnar storage for fast Pandas scans; lookup tables keep business metadata separate from raw data.                                                               |
| **Processing & Risk Scoring** | Pandas pipeline, “Risk Score Calculator” module             | - Join CVEs ⇄ asset groups.<br>- Aggregate *count*, *avg CVSS*, *max CVSS*.<br>- Min-max normalise and combine (50 % max, 30 % avg, 20 % count) into a 0–1 composite score. |
| **OpenAI Services**           | GPT-4o mini                                                 | Given the top-N CVEs for an asset, produce plain-English impact summaries and step-by-step mitigation roadmaps.                                                             |
| **User Interface**            | Jupyter Notebook (HTML export), github repository  | Live charts, drop-downs for asset selection, buttons that trigger OpenAI explanations; notebook doubles as an auditable data journal.                                       |

### Design Principles
* Modular ETL – the fetcher is a self-contained script, so swapping NVD for another feed (e.g., VulnDB) only touches one module.
* Stateless Front-End – Streamlit pulls live parquet data at page-load; no additional server state is required.
* Reproducibility – Every transformation is expressed in notebook cells and committed to version control; anyone can re-run from raw CSV/parquet.
* Security – API keys are injected at runtime via environment variables; no secrets in code or repos.
* Extensibility – To add a new scoring dimension (e.g., exploit-in-the-wild), drop a column into the metrics DataFrame and adjust the weight vector.

### Data Flow
* __Whitelist → ETL__ Scheduler launches the Python ingestion script once a day (or on-demand during demos).
* __ETL → Storage__ Each run appends new/modified CVEs to smb_cves.parquet; duplicates are removed on write.
* __Storage → Processing__ Pandas aggregates the parquet rows and mapping tables into a per-asset metrics DataFrame.
* __Processing → OpenAI/UI__
    * The risk-score table feeds both the bar/heat-map visualisations and the GPT prompts.
    * GPT responses are streamed back into the dashboard for end-users.
* __UI → Notebook/Slides__ Users can export the notebook to HTML or capture screenshots for executive slides.

Documentation, code, data, and images for this project can be found on my github repository:  [hgbtx/cyber-risk-scoring](https://github.com/hgbtx/cyber-risk-scoring/blob/main)
