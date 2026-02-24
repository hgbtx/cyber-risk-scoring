# Cyber Risk Scoring

Cybersecurity risk assessment and vulnerability management platform. Searches CPE/CVE data via NIST NVD API, calculates priority scores, manages assets and remediation tickets with role-based access.

## Quick Start

```bash
python manage.py create-admin --username admin --password <pwd>
python app.py  # runs on http://0.0.0.0:5000
```

## Tech Stack

- **Backend:** Flask, SQLite3 (raw SQL, no ORM), Werkzeug (password hashing)
- **Frontend:** Vanilla JS (ES6+), HTML5/CSS3, Chart.js, Font Awesome 6.5, noUiSlider
- **APIs:** NIST NVD 2.0 (CPE/CVE), FIRST EPSS (exploit prediction)
- **Python:** 3.14+

## Project Structure

```
app.py              # Flask app — all routes (~1566 lines)
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
  dragdrop.js       # Drag-and-drop
  tabs.js           # Tab navigation
  panel.js          # Panel UI
```

## Architecture

- **SPA:** Single `index.html` template with modular JS files per feature
- **Auth:** OTP-based onboarding (admin generates OTP → user sets password) + standard password login
- **Roles:** viewer (1) → tier 1 analyst (2) → tier 2 analyst (3) → manager (4) → admin (5)
- **DB:** SQLite with connection-per-request (`get_db()`), parameterized queries, soft deletes, JSON columns for complex data
- **Caching:** KEV catalog cache (24h TTL), CPE metadata cache in DB

## Key Patterns

- Routes use `@login_required` and `@require_role('role')` decorators
- API endpoints: `/api/*` (external APIs), `/db/*` (CRUD), `/math/*` (scoring), `/admin/*` (admin ops)
- All mutations via POST, reads via GET; JSON request/response with `jsonify()`
- Error responses: `{'error': 'message'}` with appropriate HTTP status codes
- External API calls are rate-limited (1.2s between NVD requests)
- Frontend state centralized in `state.js`; async/await for all API calls

## Environment Variables (.env)

- `NVD_API_KEY` — NIST NVD API key
- `SECRET_KEY` — Flask session secret (auto-generated if missing)
- `ANTHROPIC_API_KEY` — Claude API key

## Git Conventions

- Branch naming: `claude/<descriptor>` for feature branches
- PR workflow with merge commits into `main`
- Commit messages: descriptive, task-oriented (e.g., "Implement end-to-end permission sync flow")

## CLI Commands (manage.py)

```bash
python manage.py create-admin --username <name> --password <pwd>
python manage.py create-user --username <name> --role <role>
python manage.py promote --username <name> --role <role>
python manage.py reset-otp --username <name>
python manage.py delete-user --username <name>
```
