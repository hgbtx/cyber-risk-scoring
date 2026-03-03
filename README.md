<p align="center">
  <img src="static/img/mogoo.svg" alt="vulnscore logo" width="150">
</p>

<h1 align="center">vulnscore, m.a.r.s.</h1>
<h2 align="center">multi-asset risk scoring</h2>

<p align="center">Cybersecurity risk assessment &amp; vulnerability management platform</p>

---

## About

vulnscore is a web-based tool for identifying, scoring, and tracking cybersecurity vulnerabilities across an organization's asset inventory. It searches the NIST National Vulnerability Database for CPE/CVE data, calculates multi-factor priority scores, and manages remediation through a role-based ticket workflow.

<p align="center">
  <img src="img/csf_wheel_v3.png" alt="NIST CSF Wheel — Identify, Protect, Detect, Respond, Recover (inner: Govern)" width="300">
</p>

> *Cybersecurity risks are expanding constantly, and managing those risks must be a continuous process. This is true regardless of whether an organization is just beginning to confront its cybersecurity challenges or whether it has been active for many years with a sophisticated, well-resourced cybersecurity team.*
>
> — [NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)

The application aligns with the **Identify** function of the NIST Cybersecurity Framework, covering three core categories: **Asset Management** (ID.AM), **Risk Assessment** (ID.RA), and **Improvement** (ID.IM).

## Features

- **CPE/CVE Search** — query the NIST NVD 2.0 API for products and known vulnerabilities
- **Asset Directory** — manage an inventory of organizational assets and their associated CPEs
- **17-Factor Priority Scoring** — weighted cumulative scoring incorporating CVSS, EPSS, KEV, and attack characteristics
- **8 Interactive Charts** — risk matrix, threat velocity, attack surface, and more — all exportable as PNG/PDF
- **Ticket CRUD with SoD Workflow** — create, assign, resolve, and archive remediation tickets with separation-of-duty enforcement
- **Role-Based Access Control** — 5 hierarchical roles with 23+ granular admin-configurable permissions across 4 categories
- **KEV / EPSS Integration** — real-time Known Exploited Vulnerabilities catalog and Exploit Prediction Scoring System data
- **OTP-Based User Onboarding** — admins generate one-time passwords; users set credentials on first login
- **CLI Admin Tools** — create users, promote roles, reset OTPs, and more from the command line

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Flask, SQLite3 (raw SQL, no ORM), Werkzeug |
| **Frontend** | Vanilla JS (ES6+), HTML5/CSS3, Chart.js, Font Awesome 6.5, noUiSlider |
| **APIs** | NIST NVD 2.0 (CPE/CVE), FIRST EPSS (exploit prediction) |
| **Python** | 3.14+ |

## Quick Start

**Prerequisites:** Python 3.14+

```bash
# Install dependencies
pip install -r requirements.txt

# Create an admin account
python manage.py create-admin --username admin --password <pwd>

# Start the server (http://0.0.0.0:5000)
python app.py
```

## Environment Variables

Create a `.env` file in the project root:

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NIST NVD API key (increases rate limits) |
| `SECRET_KEY` | Flask session secret (auto-generated if missing) |
| `ANTHROPIC_API_KEY` | Claude API key |

## CLI Commands

All commands are run via `manage.py`:

```bash
python manage.py create-admin --username <name> --password <pwd>
python manage.py create-user --username <name> --role <role>
python manage.py promote --username <name> --role <role>
python manage.py reset-otp --username <name>
python manage.py delete-user --username <name>
```

## Priority Scoring

Vulnerability priority scores are calculated from 17 cumulative factors — no normalization is applied:

| Factor | Condition | Points |
|--------|-----------|--------|
| KEV Listed | In NIST KEV catalog | +1000 |
| EPSS | > 50% | +500 |
| EPSS | > 10% | +200 |
| CVE Age | < 30 days | +100 |
| CVE Age | 30–90 days | +50 |
| CVSS Base | ≥ 9.0 (Critical) | +50 |
| CVSS Base | ≥ 7.0 (High) | +30 |
| CVSS Base | ≥ 4.0 (Medium) | +10 |
| Attack Vector | Network | +25 |
| Attack Vector | Adjacent | +10 |
| Privileges Required | None | +20 |
| Privileges Required | Low | +10 |
| User Interaction | None | +15 |
| Attack Complexity | Low | +10 |
| Confidentiality Impact | High | +8 |
| Integrity Impact | High | +8 |
| Availability Impact | High | +8 |

## Charts

Eight interactive visualizations, all supporting PNG/PDF export and dashboard drag-and-drop:

1. **Risk Matrix** — bubble scatter of asset risk posture (vuln count vs priority score)
2. **Threat Velocity** — mixed line+bar time-series of exploit activity trends
3. **Attack Surface** — stacked bar of vulnerability distribution across assets
4. **Priority Breakdown** — horizontal stacked bar of score components
5. **Remediation Pipeline** — concentric doughnut of ticket workflow stages
6. **CIA Triad** — grouped bar of confidentiality/integrity/availability impact
7. **EPSS Distribution** — scatter of exploit prediction scores
8. **CWE Clusters** — bubble chart of weakness category relationships

## Roles & Permissions

| Level | Role | Description |
|-------|------|-------------|
| 1 | Viewer | Read-only access |
| 2 | Tier 1 Analyst | Create/resolve/accept tickets |
| 3 | Tier 2 Analyst | Enhanced: can reopen tickets |
| 4 | Manager | Full operational: delete/archive/reassign |
| 5 | Admin | Complete system access + user management |

23+ granular permissions across 4 categories (Search, Asset Directory, myCharts, myTickets) are configurable per role via the admin panel.

## Ticket Workflow

```
Open → In Progress → Resolved → Archived
```

**Separation-of-duty rules:**

- The ticket owner (user who created the ticket) must be a different user than the ticket acceptor (user who accepted the ticket)
- A user cannot accept a ticket more than once, therefore a reassigned ticket cannot be accepted by a user that has previously accepted that ticket
- If a user resolves a ticket, that user cannot also accept resolution of the ticket
- Mentions in comments (`@username`) auto-add collaborators

## Project Structure

```
app.py              # Flask app — all routes
db.py               # SQLite schema, init_db(), get_db()
auth_helpers.py     # @login_required, @require_role, check_ownership
manage.py           # CLI: create-admin, create-user, promote, reset-otp, delete-user
templates/
  index.html        # Single-page application shell
static/
  styles.css        # Main stylesheet
  auth.js           # Login/OTP/password flows
  state.js          # Global app state
  search.js         # CPE search
  cve.js            # CVE display and filtering
  charts.js         # Risk visualization (Chart.js)
  tickets.js        # Ticket CRUD and workflow
  admin.js          # Admin panel
  manage.js         # User/asset management
  filters.js        # CVSS/EPSS/date filtering
  export.js         # Report export
  tabs.js           # Tab navigation
  panel.js          # Panel UI
```
