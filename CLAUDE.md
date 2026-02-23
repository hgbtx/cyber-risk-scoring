# CLAUDE.md — Cyber Risk Scoring

This file documents the codebase structure, development conventions, and key workflows for AI assistants working on this project.

---

## Project Overview

A cybersecurity risk assessment web application implementing the **Identify** function of the NIST Cybersecurity Framework (CSF). It enables organizations to inventory assets via Common Platform Enumerations (CPEs), aggregate vulnerability data from government APIs (NVD, EPSS, CISA KEV), calculate composite risk scores, and manage remediation workflows via AI-generated tickets (Anthropic Claude API).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite3 (`app.db`) |
| Frontend | Vanilla JavaScript, custom CSS |
| Auth | Flask sessions, OTP + password hash (werkzeug) |
| Charts | Chart.js, noUiSlider |
| Icons | Font Awesome 6.5.0 |
| AI | Anthropic Claude API (haiku-4-5 model) |
| External APIs | NVD CPE/CVE, FIRST EPSS, CISA KEV |

**No Node.js, no build step, no frontend framework.** The frontend is plain JS loaded directly by Flask's template.

---

## Codebase Structure

```
cyber-risk-scoring/
├── app.py              # Main Flask app — all 40+ API endpoints (1566 lines)
├── auth_helpers.py     # RBAC decorators and ownership checks (54 lines)
├── db.py               # SQLite schema init and get_db() helper (213 lines)
├── manage.py           # CLI tool for user/account management (164 lines)
├── app.db              # SQLite database (auto-created on first run)
├── static/
│   ├── styles.css      # All application styling (1053 lines)
│   ├── state.js        # Global client-side state variables (209 lines)
│   ├── auth.js         # Login/logout UI and session handling (168 lines)
│   ├── search.js       # CPE search UI with pagination (309 lines)
│   ├── cve.js          # CVE display, folders, detail panels (676 lines)
│   ├── charts.js       # Risk charts and visualization (311 lines)
│   ├── tickets.js      # Ticket CRUD and collaboration (700 lines)
│   ├── admin.js        # Admin user/policy management UI (301 lines)
│   ├── filters.js      # Search result filters (194 lines)
│   ├── export.js       # CSV/JSON export (87 lines)
│   ├── dragdrop.js     # Drag-and-drop for assets (93 lines)
│   ├── manage.js       # Asset directory management (131 lines)
│   ├── tabs.js         # Tab navigation (53 lines)
│   └── panel.js        # Right panel collapse/expand (27 lines)
└── templates/
    └── index.html      # Single-page app shell (585 lines)
```

### Key Architectural Notes

- **Single-page application**: `index.html` is the only HTML template. All UI state lives in JS.
- **No frontend build pipeline**: JS files are loaded via `<script>` tags in `index.html`. Changes take effect immediately on reload.
- **`state.js` is the source of truth** for all client-side data (search results, CVE data, active assets, tickets, user info).
- **`app.py` is monolithic**: All routes, helpers, and configuration live in one file organized by `#===SECTION===` comment headers.

---

## Environment Setup

### Required Environment Variables

Create a `.env` file in the project root:

```
SECRET_KEY=your-flask-secret-key
NVD_API_KEY=your-nvd-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key
```

- `SECRET_KEY`: Flask session secret. Auto-generated (ephemeral) if omitted — sessions won't survive restarts.
- `NVD_API_KEY`: Get from https://nvd.nist.gov/developers/request-an-api-key. Without it, NVD API calls are rate-limited to 5 req/30s.
- `ANTHROPIC_API_KEY`: Required for ticket generation (F4 Next Steps).

### Python Dependencies

No `requirements.txt` exists. Install manually:

```bash
pip install flask requests python-dotenv werkzeug
```

### Running the Application

```bash
python app.py
```

Starts Flask at `http://0.0.0.0:5000` in debug mode. The database (`app.db`) is auto-initialized via `init_db()` on first run.

---

## User Management (CLI)

All user provisioning is done via `manage.py`, not the web UI (except admin panel for existing users):

```bash
# Create initial admin
python manage.py create-admin --username <user> --password <pass>

# Create user with OTP (they set their own password on first login)
python manage.py create-user --username <user> --role <role>

# Change a user's role
python manage.py promote --username <user> --role <role>

# Generate a new OTP for a user
python manage.py reset-otp --username <user>

# Delete a user
python manage.py delete-user --username <user>
```

Valid roles: `viewer`, `tier 1 analyst`, `tier 2 analyst`, `manager`, `admin`

---

## Authentication Flow

1. Admin creates user via `manage.py` — generates a 12-char OTP (format: `XXXX-XXXX-XXXX`)
2. User logs in with username + OTP via `/auth/verify-otp`
3. If `must_change_password = 1`, user is prompted to set a password via `/auth/set-password`
4. Subsequent logins use username + password via `/auth/login`
5. OTP expires after 72 hours by default (configurable in `org_policies`)

Session data stored in Flask session: `user_id`, `username`, `role`

---

## Role-Based Access Control (RBAC)

Roles are hierarchical with numeric levels:

| Role | Level |
|---|---|
| viewer | 1 |
| tier 1 analyst | 2 |
| tier 2 analyst | 3 |
| manager | 4 |
| admin | 5 |

### How to Enforce Permissions

Use the `@require_role` decorator from `auth_helpers.py`:

```python
from auth_helpers import require_role

@app.route('/some/endpoint', methods=['POST'])
@login_required
@require_role('manager')  # requires manager or higher
def some_endpoint():
    ...
```

Use `@login_required` (defined in `app.py`) for endpoints that just need any authenticated user.

Check resource ownership with `check_ownership(resource_type, resource_id, user_id)` from `auth_helpers.py`.

---

## API Endpoint Reference

All endpoints are in `app.py`. Organized by section:

### Authentication (`/auth/...`)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/auth/verify-otp` | None | OTP login step 1 |
| POST | `/auth/set-password` | Any | Set initial password |
| POST | `/auth/login` | None | Password login |
| POST | `/auth/logout` | Any | End session |
| GET | `/auth/me` | Any | Current user info |
| GET | `/auth/my-permissions` | Any | User's permission set |

### CVE/CPE Search (`/api/...`)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/search` | Any | NVD CPE keyword search |
| POST | `/api/fetch-cves` | Any | Fetch CVEs for a CPE |
| POST | `/api/get_kev_list` | Any | CISA KEV list (daily cache) |

### Risk Scoring (`/math/...`)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/math/priority-scoring` | Any | CVE priority score calculation |
| POST | `/math/risk-formulas` | Any | Apply risk formula to CVE set |
| POST | `/math/aggregation-methods` | Any | Aggregate scores per asset |
| POST | `/math/risk-threshold` | Any | Filter by risk threshold |

### Asset Management (`/db/...`)
| Method | Endpoint | Auth | Min Role |
|---|---|---|---|
| POST | `/db/save-assets` | Yes | tier 1 analyst |
| POST | `/db/archived-assets` | Yes | manager |
| POST | `/db/deleted-assets` | Yes | admin |
| GET | `/db/load-assets` | Yes | viewer |
| GET | `/db/load-archived-assets` | Yes | viewer |
| POST | `/db/load-cpe-cache` | Yes | viewer |

### Ticket Management (`/db/...`)
| Method | Endpoint | Min Role | Description |
|---|---|---|---|
| POST | `/db/save-tickets` | Any auth | Create/update tickets |
| GET | `/db/load-tickets` | viewer | Load user's tickets |
| POST | `/db/ticket-status` | tier 1 analyst | Change status |
| POST | `/db/ticket-delete` | manager | Delete ticket |
| POST | `/db/ticket-acceptance` | tier 1 analyst | Accept ticket |
| POST | `/db/ticket-resolution` | manager | Resolve ticket |
| POST | `/db/ticket-reassign` | manager | Reassign ticket |
| POST | `/db/ticket-comment` | viewer | Add comment |
| POST | `/db/ticket-comment-fix` | manager | Edit comment |
| POST | `/db/ticket-reopen` | manager | Reopen resolved |
| POST | `/db/ticket-archive` | tier 1 analyst | Archive ticket |
| GET | `/db/ticket-stats` | viewer | Ticket statistics |

### Admin (`/admin/...`)
| Method | Endpoint | Min Role | Description |
|---|---|---|---|
| GET | `/admin/users` | admin | List all users |
| POST | `/admin/users/create` | admin | Create user |
| POST | `/admin/users/update-role` | admin | Change role |
| POST | `/admin/users/reset-otp` | admin | Reset OTP |
| POST | `/admin/users/delete` | admin | Delete user |
| GET/POST | `/admin/policies` | admin | Org policies |
| GET/POST | `/admin/permissions` | admin | Role permissions |

---

## Database Schema

SQLite database at `./app.db`. Initialized by `db.py:init_db()` which is called at Flask startup.

**Tables:**

| Table | Primary Key | Purpose |
|---|---|---|
| `users` | `id` | User accounts, auth, roles |
| `organizations` | `id` | Multi-tenant orgs (default: "Default", id=1) |
| `org_policies` | `id` | Per-org config (OTP expiry, permissions JSON) |
| `roles` | `id` | Role name/level seed data |
| `assets` | `cpeName` | Inventoried CPE assets (stores raw JSON) |
| `archivedAssets` | `id` | Archive state tracking for assets |
| `cpe_cache` | `cpeName` | Cache of CPE API responses |
| `tickets` | `id` | Remediation tickets |
| `resolvedTickets` | `id` | Resolution records |
| `acceptedTickets` | `id` | Acceptance records |
| `archivedTickets` | `id` | Archive state for tickets |
| `commentTickets` | `id` | Ticket comments (supports edits via `isFixed`) |
| `reassignedTickets` | `id` | Reassignment log |
| `deletedTickets` | `id` | Deletion audit trail |
| `ticketActivity` | `id` | Full audit log of all ticket actions |
| `statusTickets` | `id` | Current ticket status (Open/In Progress/etc.) |
| `ticketCollaborators` | `id` | Multi-user collaboration on tickets |

**Key relationships:**
- `assets.user_id` → `users.id` (CASCADE DELETE)
- `tickets.user_id` → `users.id` (CASCADE DELETE)
- All ticket sub-tables → `tickets.id` (CASCADE DELETE)
- `users.org_id` → `organizations.id`

**Schema migrations** are handled inline in `db.py:init_db()` with bare `try/except` blocks (e.g., adding `isFixed`/`fixed` columns to `commentTickets`).

**Data stored as JSON blobs**: `assets.cpeData`, `assets.cveData`, and `org_policies.permissions_json` are serialized JSON strings, not normalized columns.

---

## External API Integration

### NVD (NIST National Vulnerability Database)
- CPE Search: `https://services.nvd.nist.gov/rest/json/cpes/2.0`
- CVE Lookup: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Rate limit: 1.2 seconds between calls (`rate_secs = 1.2` in `app.py`)
- Pagination: fetches up to 2000 results per call (`per_page = 2000`)
- Requires `NVD_API_KEY` env var for higher rate limits

### FIRST EPSS
- URL: `https://api.first.org/data/v1/epss`
- Batched in groups of 100 CVE IDs per request

### CISA KEV (Known Exploited Vulnerabilities)
- Fetched on demand, cached in-memory for 86,400 seconds (daily)
- Cache vars: `kev_cache` (set), `kev_cache_time` (epoch), `KEV_CACHE_TTL`

### Anthropic Claude API
- Used for AI-generated ticket descriptions in F4 (Next Steps)
- Model: `claude-haiku-4-5`
- Key: `ANTHROPIC_API_KEY` env var → `llm_api_key` in `app.py`

---

## Risk Scoring System

The priority/risk score is a composite calculated in `/math/priority-scoring` from CVE data fields:
- CVSS base score
- EPSS score (exploit prediction probability)
- KEV status (binary flag for known active exploits)
- CVSS exploitability and impact sub-scores

**Risk formula options** (configured per-session by user in Charts tab):

| Formula | Use Case |
|---|---|
| Weighted Average | Balanced/pragmatic monitoring |
| Multiplicative | Conservative — requires multi-dimensional threat |
| Max | Worst-case — any single severe CVE triggers |
| Simple Mean | Cumulative or outlier-resistant views |

**Aggregation methods** for per-asset scores: `max`, `mean`, `median`, `sum`, `count`

---

## Frontend Architecture

### State Management (`state.js`)
All application state is global variables in `state.js`. Key state objects:
- `searchResults` — current CPE search results
- `assetData` — CPEs dragged into the Assets folder
- `cveData` — CVE results keyed by CPE name
- `ticketData` — loaded tickets
- `currentUser` — session user info and permissions

### Tab Structure
Tabs: Search (F1), CVE Details (F2), Charts (F3), Next Steps (F4), Asset Directory, myTickets, Admin

Tab switching is handled by `tabs.js`. Each tab has a corresponding JS module.

### Left Panel
- Filter options (Search tab active) or Chart options (Charts tab active)
- Asset folder for dropped CPEs with running CVE count
- Managed by `filters.js`, `dragdrop.js`, `manage.js`

### Right Panel
- Displays CPE info and/or full CVE detail
- Auto-expands on CVE click (CVE Details tab) or chart data point click
- Manually collapsible via `panel.js`
- Known issue: contents do not persist when switching tabs

---

## Code Conventions

### Python (`app.py`)
- Sections delimited with `#===SECTION===` comment headers
- Sub-sections with `#---SUBSECTION---` comments
- Authentication decorator order: `@app.route` → `@login_required` → `@require_role`
- All DB queries use parameterized SQL (`?` placeholders) — no string formatting
- Responses always use `jsonify()`; errors include `{'error': '...'}` with appropriate HTTP status code
- `get_db()` returns a connection with `row_factory = sqlite3.Row` (dict-like access)
- Always call `conn.close()` after database operations

### JavaScript
- Module pattern: each JS file exports functions and attaches event listeners on `DOMContentLoaded`
- Async/await for all fetch calls to backend endpoints
- DOM elements cached at module top
- No linting or formatting config exists (no `.eslintrc`, no `.prettierrc`)

### CSS
- CSS custom properties for theming (defined at `:root`)
- Color palette: `#57534E` (dark stone), `#be7a15` (gold), `#F5F5F4` (light stone)
- Flexbox-based layout throughout
- No CSS preprocessor (plain CSS)

---

## Known Issues and Limitations

Per `README.md` and code comments:

1. **Search by exact `cpe_name` returns no results** — NVD API limitation; search by keyword instead (vendor, product, version)
2. **Asset folder does not persist on page reload** (`Ctrl+R`) — client-side state only; use Account (F7) to persist
3. **Chart options not yet implemented** — Left panel chart config is placeholder
4. **Right panel contents don't persist per tab** — switching tabs clears the panel
5. **F7 Account features** — partially implemented; some features TBD
6. **`check_ownership` in `auth_helpers.py`** — currently only checks direct ownership, not org-level policies

---

## Development Workflow

There is no automated test suite, linter, or CI/CD pipeline. Development process:

1. Edit Python files → restart `python app.py`
2. Edit JS/CSS files → hard refresh browser (`Ctrl+Shift+R`)
3. Schema changes → add migration block in `db.py:init_db()` using `try/except ALTER TABLE`
4. New users → use `manage.py` CLI

### Adding a New API Endpoint

1. Add route in `app.py` in the appropriate `#===SECTION===` block
2. Apply `@login_required` and `@require_role('role-name')` as needed
3. Use `get_db()` for DB access, always close connection
4. Return `jsonify({...})` for success, `jsonify({'error': '...'})` for errors

### Adding a New Database Table

1. Add `CREATE TABLE IF NOT EXISTS` block inside `db.py:init_db()` within the `conn.executescript(...)` call
2. Add seed data after the executescript if needed (see roles/organizations pattern)
3. For columns added to existing tables, add a `try/except ALTER TABLE` migration block after the executescript

### Adding Frontend Features

1. Add logic to the appropriate JS module (`cve.js`, `tickets.js`, etc.) or create a new file
2. Add `<script src="...">` in `templates/index.html`
3. Update `state.js` if new global state is needed
4. Keep DOM manipulation in the feature's JS module; do not reach across modules

---

## Git Setup

- Remote: `http://local_proxy@127.0.0.1:42219/git/hgbtx/cyber-risk-scoring`
- Main branch: `master`
- Feature/AI branches: `claude/...` prefix
