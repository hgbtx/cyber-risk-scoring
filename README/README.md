# 1. Introduction

![csf_wheel_v3.png](c274d183-4442-4ec4-9cca-8754e8215f14.png)

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

![csf_categories.png](f58afce7-646b-4482-9d71-702d9fd354b8.png)

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

The core dataset driving this application is user-defined. Each user ingests CPEs using F1 (Asset Inventory Module) of the tool to generate personalized datasets. In other words, the application itself generates the dataset at runtime rather than relying on a fixed third-party file. This bakes in versatility as a core component.

#### Why This Approach
* __Tailored Relevance__: Users see only vulnerabilities that apply to their stack—no noise from unrelated products.
* __Privacy__: Because the whitelist is entered directly into the app and never leaves the tenancy, no proprietary system details are exposed to third parties.

## Key Features of the Application Tool
***
Feature ID | Module Name | Key Component(s) | What it does |
|--------- |------------ |----------------- |------------- |
| F1 | __Asset Inventory__ | CPE API, Save to File, User Input Required | • Prompts end-user to keyword search an asset (e.g. software, operating system component, hardware)<br>• Returns a list of CPEs (includes partial matches)<br>• Prompts user to save/append list to CSV file<br>• Returns to keyword search prompt<br>• User types 'exit' to terminate search |
| F2 | __Vulnerabilities Identification__ | CVE API, Save to File, User Input Required | • Loads CSV file generated in F1<br>• Returns a list of CVEs<br>• Prompts user to save/append to file |
| F3 | __Risk Evaluation__ | Risk Scoring Module, Performs Risk Calculation, Appends to File | • Loads file generated in F1<br>• computing a composite risk score per asset/business unit<br>• Adds/appends risk score columns to file <br>• maps CVE severity scores for user defined assets |
| F4 | __Mitigation Recommendations__ | OpenAI API, 4o mini GPT, generates recommendations | Given the top-N CVEs for an asset:<br>• produce plain-English impact summaries and step-by-step mitigation roadmaps. |

The following datasets will be used for the purposes of demonstrating the application tool features:


```python
import pandas as pd

assets = pd.read_csv('../data/cpe_whitelist.csv')
assets
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>WrittenAt</th>
      <th>Title</th>
      <th>cpeName</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>2025-06-08T18:58:54.485</td>
      <td>Tableau Desktop 2021.1</td>
      <td>cpe:2.3:a:tableau:tableau_desktop:2021.1:*:*:*...</td>
    </tr>
    <tr>
      <th>1</th>
      <td>2025-06-08T18:59:05.725</td>
      <td>Adobe Acrobat Reader 20.004.30006 Classic Edition</td>
      <td>cpe:2.3:a:adobe:acrobat_reader:20.004.30006:*:...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>2025-06-08T18:59:17.606</td>
      <td>Oracle SuiteCommerce Advanced</td>
      <td>cpe:2.3:a:oracle:suitecommerce_advanced:-:*:*:...</td>
    </tr>
    <tr>
      <th>3</th>
      <td>2025-06-08T18:59:17.606</td>
      <td>Oracle SuiteCommerce Advanced 2020.1.4</td>
      <td>cpe:2.3:a:oracle:suitecommerce_advanced:2020.1...</td>
    </tr>
    <tr>
      <th>4</th>
      <td>2025-06-08T18:59:27.454</td>
      <td>Alteryx Server 2022.1.1.42590</td>
      <td>cpe:2.3:a:alteryx:alteryx_server:2022.1.1.4259...</td>
    </tr>
    <tr>
      <th>5</th>
      <td>2025-06-08T21:55:41.178</td>
      <td>Fortinet FortiGate 7000</td>
      <td>cpe:2.3:h:fortinet:fortigate_7000:-:*:*:*:*:*:*:*</td>
    </tr>
    <tr>
      <th>6</th>
      <td>2025-06-08T22:01:52.494</td>
      <td>Workday 31.2</td>
      <td>cpe:2.3:a:workday:workday:31.2:*:*:*:*:*:*:*</td>
    </tr>
    <tr>
      <th>7</th>
      <td>2025-06-08T22:04:13.394</td>
      <td>Alfresco Enterprise 4.1.6.13</td>
      <td>cpe:2.3:a:alfresco:alfresco:4.1.6.13:*:*:*:ent...</td>
    </tr>
    <tr>
      <th>8</th>
      <td>2025-06-08T22:06:35.432</td>
      <td>Oracle Database 19c Enterprise Edition</td>
      <td>cpe:2.3:a:oracle:database:19c:*:*:*:enterprise...</td>
    </tr>
    <tr>
      <th>9</th>
      <td>2025-06-08T22:06:53.654</td>
      <td>Oracle Database Vault 19c</td>
      <td>cpe:2.3:a:oracle:database_vault:19c:*:*:*:*:*:*:*</td>
    </tr>
    <tr>
      <th>10</th>
      <td>2025-06-08T22:07:10.617</td>
      <td>Oracle Database Server 19c</td>
      <td>cpe:2.3:a:oracle:database_server:19c:*:*:*:*:*...</td>
    </tr>
    <tr>
      <th>11</th>
      <td>2025-06-08T22:07:33.052</td>
      <td>Oracle Database Recovery Manager 19c</td>
      <td>cpe:2.3:a:oracle:database_recovery_manager:19c...</td>
    </tr>
    <tr>
      <th>12</th>
      <td>2025-06-08T22:12:59.597</td>
      <td>Microsoft Exchange Server 2019</td>
      <td>cpe:2.3:a:microsoft:exchange_server:2019:-:*:*...</td>
    </tr>
    <tr>
      <th>13</th>
      <td>2025-06-08T22:12:59.597</td>
      <td>Microsoft Exchange Server 2019 Cumulative Upda...</td>
      <td>cpe:2.3:a:microsoft:exchange_server:2019:cumul...</td>
    </tr>
  </tbody>
</table>
</div>




```python
vulnerabilities = pd.read_csv('../data/vuln_catalogue_v1.csv')
print("Total rows:", len(vulnerabilities))
vulnerabilities.head(3)
```

    Total rows: 442
    




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>Unnamed: 0</th>
      <th>cveID</th>
      <th>cpeName</th>
      <th>published</th>
      <th>last_modified</th>
      <th>vectorString</th>
      <th>baseScore</th>
      <th>baseSeverity</th>
      <th>attackVector</th>
      <th>attackComplexity</th>
      <th>...</th>
      <th>userInteraction</th>
      <th>scope</th>
      <th>confidentialityImpact</th>
      <th>integrityImpact</th>
      <th>availabilityImpact</th>
      <th>cwes</th>
      <th>description</th>
      <th>references</th>
      <th>tags</th>
      <th>full_json</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>0</td>
      <td>NaN</td>
      <td>cpe:2.3:a:tableau:tableau_desktop:2021.1:*:*:*...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NO CVEs FOUND FOR THIS ASSET</td>
      <td>NaN</td>
      <td>NO CVEs</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>1</th>
      <td>1</td>
      <td>CVE-2021-39836</td>
      <td>cpe:2.3:a:adobe:acrobat_reader:20.004.30006:*:...</td>
      <td>2021-09-29T16:15:08.513</td>
      <td>2024-11-21T06:20:20.730</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</td>
      <td>7.8</td>
      <td>HIGH</td>
      <td>LOCAL</td>
      <td>LOW</td>
      <td>...</td>
      <td>REQUIRED</td>
      <td>UNCHANGED</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>CWE-416</td>
      <td>Acrobat Reader DC versions 2021.005.20060 (and...</td>
      <td>https://helpx.adobe.com/security/products/acro...</td>
      <td>Release Notes, Vendor Advisory, Release Notes,...</td>
      <td>{'cve': {'id': 'CVE-2021-39836', 'sourceIdenti...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>2</td>
      <td>CVE-2021-39837</td>
      <td>cpe:2.3:a:adobe:acrobat_reader:20.004.30006:*:...</td>
      <td>2021-09-29T16:15:08.573</td>
      <td>2024-11-21T06:20:20.890</td>
      <td>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</td>
      <td>7.8</td>
      <td>HIGH</td>
      <td>LOCAL</td>
      <td>LOW</td>
      <td>...</td>
      <td>REQUIRED</td>
      <td>UNCHANGED</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>CWE-416</td>
      <td>Acrobat Reader DC versions 2021.005.20060 (and...</td>
      <td>https://helpx.adobe.com/security/products/acro...</td>
      <td>Release Notes, Vendor Advisory, Release Notes,...</td>
      <td>{'cve': {'id': 'CVE-2021-39837', 'sourceIdenti...</td>
    </tr>
  </tbody>
</table>
<p>3 rows × 21 columns</p>
</div>



Documentation, code, data, and images for this project can be found on my github repository:  [hgbtx/cyber-risk-scoring](https://github.com/hgbtx/cyber-risk-scoring/blob/main)
