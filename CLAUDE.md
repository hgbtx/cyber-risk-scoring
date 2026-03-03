# Cyber Risk Scoring — Claude Code Guidance

Cybersecurity risk assessment and vulnerability management platform. Searches CPE/CVE data via NIST NVD API, calculates priority scores, manages assets and remediation tickets with role-based access.

## Quick Start

```bash
pip install -r requirements.txt
python manage.py create-admin --username admin --password <pwd>
python app.py  # runs on http://0.0.0.0:5000
```

## Lint Commands

```bash
python -m ruff check .        # Python linting (no tests exist)
npx eslint static/*.js        # JS linting
```

## Tech Stack

- **Backend:** Flask, SQLite3 (raw SQL, no ORM), Werkzeug (password hashing), APScheduler
- **Frontend:** Vanilla JS (ES6+), HTML5/CSS3, Chart.js, Font Awesome 6.5, noUiSlider — no bundler
- **APIs:** NIST NVD 2.0 (CPE/CVE), FIRST EPSS (exploit prediction)

## Architecture

### Backend (`app.py`)
- Monolithic (~3200 lines), organized by comment-delimited sections
- Route prefix convention: `/auth/*`, `/api/*`, `/db/*`, `/math/*`, `/admin/*`, `/notifications/*`
- Background scheduler (APScheduler) handles periodic CVE rescans
- Single-tenant: `org_id = 1` hardcoded throughout

### Database (`db.py`)
- Raw SQL schema; migrations via try/except `ALTER TABLE` (no migration framework)
- Connection-per-request via `get_db()` — caller must close the connection
- Parameterized queries only (no string interpolation)

### Frontend
- SPA: single `index.html` shell with 13 JS files sharing global scope (no ES modules/imports)
- **JS load order matters** (defined in `index.html`):
  `state.js` → `admin.js` → `notifications.js` → `auth.js` → `panel.js` → `tabs.js` → `search.js` → `charts.js` → `cve.js` → `filters.js` → `export.js` → `tickets.js` → `manage.js`
- Cross-file JS dependencies documented in `eslint.config.mjs` globals section

## Key Patterns

- **Auth decorators:** `@login_required` (defined in `app.py`), `@require_role('role')` (in `auth_helpers.py`)
- **CSRF:** `X-CSRF-Token` header required on all mutating requests; token obtained via `getCsrfToken()` from `state.js`
- **API responses:** always `{'error': 'message'}` with appropriate HTTP status codes on failure
- **Priority score max:** `1744`, hardcoded in both `state.js:69` and `app.py` — must stay in sync
- **Rate limiting:** 1.2s delay between NVD API requests

## Environment Variables (`.env`)

- `NVD_API_KEY` — NIST NVD API key
- `SECRET_KEY` — Flask session secret (auto-generated if missing)
- `ANTHROPIC_API_KEY` — Claude API key

## Git Conventions

- `.gitignore` uses an **inverted allowlist pattern** (`*` to ignore all, then `!` to re-include specific files). Add new tracked files explicitly.
- Branch naming: `claude/<descriptor>` for feature branches

## CLI Commands (`manage.py`)

```bash
python manage.py create-admin --username <name> --password <pwd>
python manage.py create-user  --username <name> --role <role>
python manage.py promote      --username <name> --role <role>
python manage.py reset-otp    --username <name>
python manage.py delete-user  --username <name>
```

## Project Structure

```
app.py              # Flask app — all routes (~3200 lines)
db.py               # SQLite schema, init_db(), get_db()
auth_helpers.py     # @login_required, @require_role, check_ownership
manage.py           # CLI user management
templates/
  index.html        # SPA shell — defines JS load order
static/
  styles.css        # Main stylesheet
  state.js          # Global state, shared vars/functions, CSRF helpers
  admin.js          # Admin panel + DEFAULT_PERMISSIONS
  notifications.js  # Notification polling and rendering
  auth.js           # Login/OTP/password flows
  panel.js          # Panel UI
  tabs.js           # Tab navigation
  search.js         # CPE search
  charts.js         # Risk visualization (Chart.js)
  cve.js            # CVE display and filtering
  filters.js        # CVSS/EPSS/date filtering
  export.js         # Report export
  tickets.js        # Ticket CRUD and workflow
  manage.js         # User/asset management
```
