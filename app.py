#=====================
# IMPORTS & CONFIG
#=====================

from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)

import time, requests, os, json, re, secrets, string
from datetime import datetime
from dotenv import load_dotenv
from db import get_db, init_db
from functools import wraps
from auth_helpers import require_role, require_permission, get_role_level
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
app.secret_key = os.getenv('SECRET_KEY', os.urandom(32).hex())
nvd_api_key = os.getenv('NVD_API_KEY')
nvd_api_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
epss_api_url = "https://api.first.org/data/v1/epss"
llm_api_key = os.getenv("ANTHROPIC_API_KEY")
rate_secs = 1.2
per_page = 2000
progress_every = 25

kev_cache = set()
kev_cache_time = 0
KEV_CACHE_TTL = 86400  # refresh daily

#=====================
# HELPERS
#=====================

#---PARSE MENTIONS (myTickets)
def parse_mentions(text):
    """Extract @username mentions from comment text."""
    return re.findall(r'@(\w+)', text)

#---PARSE DATE HELPER---
def parse_date(date_str):
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except:
        return datetime(2000, 1, 1)

#=====================
# AUTHENTICATION
#=====================

@app.before_request
def refresh_session_role():
    uid = session.get('user_id')
    if uid:
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (uid,)).fetchone()
        conn.close()
        if user:
            session['role'] = user['role']
        else:
            session.clear()

def get_current_user_id():
    return session.get('user_id')

def generate_otp(length=12):
    alphabet = string.ascii_uppercase + string.digits
    raw = ''.join(secrets.choice(alphabet) for _ in range(length))
    return '-'.join(raw[i:i+4] for i in range(0, length, 4))

#---AUTHENTICATION ENDPOINTS---
@app.route('/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json or {}
    username = data.get('username', '').strip()
    otp = data.get('otp', '')
    if not username or not otp:
        return jsonify({'error': 'Username and one-time password are required.'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if not user or not user['otp_hash']:
        return jsonify({'error': 'Invalid username or one-time password.'}), 401
    if not check_password_hash(user['otp_hash'], otp):
        return jsonify({'error': 'Invalid username or one-time password.'}), 401
    if user['otp_expires_at']:
        expiry = datetime.fromisoformat(user['otp_expires_at'])
        if datetime.now() > expiry:
            return jsonify({'error': 'One-time password has expired. Contact your administrator.'}), 401
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    return jsonify({'success': True, 'must_change_password': bool(user['must_change_password'])})

@app.route('/auth/set-password', methods=['POST'])
def set_password():
    data = request.json or {}
    password = data.get('password', '')
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400
    uid = get_current_user_id()
    pw_hash = generate_password_hash(password)
    conn = get_db()
    conn.execute(
        'UPDATE users SET password_hash = ?, otp_hash = NULL, otp_expires_at = NULL, must_change_password = 0 WHERE id = ?',
        (pw_hash, uid)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if not user or not user['password_hash'] or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid username or password.'}), 401
    if user['must_change_password']:
        return jsonify({'error': 'Please use the New User login to set your password.'}), 403
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    return jsonify({'success': True, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/auth/me', methods=['GET'])
def auth_me():
    uid = get_current_user_id()
    if not uid:
        return jsonify({'authenticated': False}), 401
    conn = get_db()
    user = conn.execute('SELECT id, username, role FROM users WHERE id = ?', (uid,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'authenticated': False}), 401
    return jsonify({'authenticated': True, 'user': dict(user)})

#=====================
# FRONTEND ENDPOINTS
#=====================

#---FLASK SERVES HTML---
@app.route('/')
def home():
    return render_template('index.html') 

#---KEV CACHING---
@app.route('/api/get_kev_list', methods=['POST'])
@require_permission('Search', 'Perform searches')
def get_kev_list():
    global kev_cache, kev_cache_time
    if time.time() - kev_cache_time > KEV_CACHE_TTL or not kev_cache:
        kev_cache = fetch_kev_ids()
        kev_cache_time = time.time()
    return kev_cache

#=====================
# API ENDPOINTS
#=====================

#---NVD CPE FETCH---
@app.route('/api/search', methods=['POST'])
@require_permission('Search', 'Perform searches')
def search_cpe_names():
    '''A function that calls the NVD API to return CPE results.'''
    keyword = request.json.get('searchTerm', '')
    cpe_match_string = request.json.get('cpeMatchString', '')
    all_results = []
    start_index = 0
    results_per_page = 100
    headers = {"apiKey": nvd_api_key}
    while True:
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }
        if cpe_match_string:
            params["cpeMatchString"] = cpe_match_string
        elif keyword:
            params["keywordSearch"] = keyword
        else:
            break
        response = requests.get(nvd_api_url, params=params, headers=headers)        
        if response.status_code != 200:
            print(f"Error fetching data for '{keyword}': {response.status_code} - {response.text}")
            break
        data = response.json()
        cpe_matches = data.get('products', [])
        if not cpe_matches:
            break
        indexed_matches = -1
        for item in cpe_matches:
            indexed_matches += 1
            cpe_obj = item.get('cpe', {})
            metadata = cpe_obj.get('titles', [])
            title = next((t['title'] for t in metadata if t.get('lang') == 'en'), metadata[0]['title'] if metadata else '')
            cpe_uri = cpe_obj.get('cpeName', '')
            if cpe_uri:
                all_results.append({
                    'index': indexed_matches,
                    'title': title,
                    'cpeName': cpe_uri,
                    'cpeData': cpe_obj
                })
        total_results = data.get('totalResults', 0)
        start_index += results_per_page
        if start_index >= total_results:
            break
        time.sleep(rate_secs)
    # Cache CPE data from search results
    if all_results:
        conn = get_db()
        for r in all_results:
            conn.execute('''
                INSERT INTO cpe_cache (cpeName, cpeData, fetched_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(cpeName)
                DO UPDATE SET cpeData=excluded.cpeData, fetched_at=CURRENT_TIMESTAMP
            ''', (r['cpeName'], json.dumps(r.get('cpeData', {}))))
        conn.commit()
        conn.close()
    return jsonify(all_results)

#---CPE QUERY: NVD CVE FETCH---
def fetch_cves_for_cpe(cpe_uri: str) -> list[dict]:
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return []
    cpe_query = ":".join(parts[:6]) if parts[5] == "*" else cpe_uri
    all_items, start = [], 0
    headers = {"apiKey": nvd_api_key}
    while True:
        params = {
            "cpeName": cpe_query,
            "resultsPerPage": per_page,
            "startIndex": start,
        }
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            print(f"⚠️ {cpe_query[:70]} → {r.status_code}")
            break
        data = r.json()
        items = data.get("vulnerabilities", [])
        all_items.extend(items)
        start += per_page
        if start >= data.get("totalResults", 0) or not items:
            break
        time.sleep(rate_secs)
    return all_items

#---NVD CVE FETCH---
@app.route('/api/fetch-cves', methods=['POST'])
def api_fetch_cves():
    data = request.json
    cpe_uri = data.get('cpeUri')
    
    if cpe_uri:
        cves = fetch_cves_for_cpe(cpe_uri)
        kev_list = get_kev_list()

        # Fetch EPSS scores for all CVEs
        cve_ids = [cve.get('cve', {}).get('id', '') for cve in cves if cve.get('cve', {}).get('id')]
        epss_scores = fetch_epss_scores(cve_ids)

        for cve in cves:
            cve_id = cve.get('cve', {}).get('id', '')
            cve['priorityScore'] = priority_score(cve, kev_list, epss_scores)
            cve['hasKev'] = cve_id in kev_list
            cve['epssScore'] = epss_scores.get(cve_id, 0)
        return jsonify({'success': True, 'count': len(cves), 'vulnerabilities': cves})
    
    return jsonify({'error': 'No CPE URI provided'}), 400

#---FETCH KEV ID VIA NVD API---
def fetch_kev_ids() -> set:
    """Fetch all CVE IDs in CISA's KEV catalog via NVD API."""
    kev_ids = set()
    start = 0
    headers = {"apiKey": nvd_api_key}
    while True:
        params = {
            "hasKev": "",
            "resultsPerPage": per_page,
            "startIndex": start,
        }
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            break
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cve", {}).get("id", "")
            if cve_id:
                kev_ids.add(cve_id)
        start += per_page
        if start >= data.get("totalResults", 0):
            break
        time.sleep(rate_secs)
    return kev_ids

#---EPSS SCORE FETCH---
@app.route('/api/fetch-epss', methods=['POST'])
def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns dict mapping CVE-ID -> EPSS probability score.
    """
    if not cve_ids:
        return {}
    
    epss_scores = {}
    batch_size = 100  # API handles multiple CVEs per request
    
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        cve_param = ",".join(batch)
        
        params = {"cve": cve_param}
        try:
            r = requests.get(epss_api_url, params=params, timeout=30)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve", "")
                    epss = float(item.get("epss", 0))
                    if cve_id:
                        epss_scores[cve_id] = epss
            time.sleep(0.5)  # Rate limiting
        except Exception as e:
            print(f"Error fetching EPSS for batch: {e}")
            continue
    
    return epss_scores

#=====================
# PRIORITY SCORING
#=====================
@app.route('/math/priority-scoring', methods=['POST'])
def priority_score(cve, kev_list, epss_scores):
    """
    A way to determine which CVEs deserve priority when numerous 
    CVEs are returned for a given CPE.
    """
    priority = 0

    cve_data = cve.get('cve', {})
    cve_id = cve_data.get('id', '')
    
    cvss31 = cve_data.get('metrics', {}).get('cvssMetricV31', [{}])
    cvss_data = cvss31[0].get('cvssData', {}) if cvss31 else {}
    
    base_score = cvss_data.get('baseScore', 0)
    attack_vector = cvss_data.get('attackVector', '')
    attack_complexity = cvss_data.get('attackComplexity', '')
    privileges = cvss_data.get('privilegesRequired', '')
    user_interaction = cvss_data.get('userInteraction', '')
    confidentiality_impact = cvss_data.get('confidentialityImpact', '')
    integrity_impact = cvss_data.get('integrityImpact', '')
    availability_impact = cvss_data.get('availabilityImpact', '')
    
    # Tier 1: Critical immediate threats
    if cve_id in kev_list:
        priority += 1000
    
    # EPSS score (if available)
    if epss_scores and cve_id in epss_scores:
        epss = epss_scores[cve_id]
        if epss > 0.5:  # >50% exploitation probability
            priority += 500
        elif epss > 0.1:  # >10%
            priority += 200
    
    # CVE Age - newer CVEs often exploited faster
    published_date = parse_date(cve_data.get('published', ''))
    days_old = (datetime.now(tz=published_date.tzinfo) - published_date).days
    if days_old < 30:
        priority += 100  # Very recent
    elif days_old < 90:
        priority += 50
    
    # CVSS granularity
    if base_score >= 9.0:
        priority += 50
    elif base_score >= 7.0:
        priority += 30
    elif base_score >= 4.0:
        priority += 10
    
    # Attack Prerequisites
    if attack_vector == "NETWORK":
        priority += 25
    elif attack_vector == "ADJACENT":
        priority += 10
        
    if privileges == "NONE":
        priority += 20
    elif privileges == "LOW":
        priority += 10
    
    if user_interaction == "NONE":
        priority += 15
    
    if attack_complexity == "LOW":
        priority += 10
    
    # Impact scores
    if confidentiality_impact == "HIGH":
        priority += 8
    if integrity_impact == "HIGH":
        priority += 8
    if availability_impact == "HIGH":
        priority += 8
    
    return priority

#=====================
# RISK FORMULAS
#=====================
@app.route('/math/risk-formulas', methods=['POST'])
def weighted_average_score(values, weights):
    return sum(v * w for v, w in zip(values, weights)) / sum(weights)
def multiplicative_risk_score(values, weights):
    # Normalize weights
    total_weight = sum(weights)
    normalized_weights = [w / total_weight for w in weights]
    
    # Calculate product of value^weight
    result = 1
    for value, weight in zip(values, normalized_weights):
        result *= value ** weight
    
    return result

def max_score(values):
    return max(values) if values else 0

def simple_mean_score(values):
    return sum(values) / len(values) if values else 0

#=====================
# AGGREGATION METHODS
#=====================
@app.route('/math/aggregation-methods', methods=['POST'])
def max_agg(values):
    return max_score(values)

def mean_agg(values):
    return simple_mean_score(values)

def median_agg(values):
    return sorted(values)[len(values)//2] if values else 0

def sum_agg(values):
    return sum(values)

#=====================
# RISK THRESHOLD
#=====================
@app.route('/math/risk-threshold', methods=['POST'])
def count_high_risk(series, threshold=7.0):
    return (series >= threshold).sum()

#====================
# DATABASE ENDPOINTS
#====================

#---LOAD CPE CACHE---
@app.route('/db/load-cpe-cache', methods=['POST'])
@require_permission('Search', 'Viewable Search tab')
def load_cpe_cache():
    cpe_names = request.json.get('cpeNames', [])
    if not cpe_names:
        return jsonify({})

    conn = get_db()
    placeholders = ','.join('?' * len(cpe_names))
    rows = conn.execute(
        f'SELECT cpeName, cpeData FROM cpe_cache WHERE cpeName IN ({placeholders})',
        cpe_names
    ).fetchall()
    conn.close()

    result = {}
    for r in rows:
        try:
            result[r['cpeName']] = json.loads(r['cpeData'])
        except (json.JSONDecodeError, TypeError):
            result[r['cpeName']] = {}
    return jsonify(result)

#=====================
# ASSET DB ENDPOINTS
#=====================

#---SAVE ASSETS---
@app.route('/db/save-assets', methods=['POST'])
@require_permission('Asset Directory', 'Save assets')
def save_assets():
    uid = get_current_user_id()
    assets = request.json.get('assets', [])
    conn = get_db()

    # Upsert each asset (preserves existing IDs)
    incoming_cpes = set()
    for a in assets:
        incoming_cpes.add(a['cpeName'])
        conn.execute('''
            INSERT INTO assets (user_id, cpeName, title, cpeData, cveData)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, cpeName)
            DO UPDATE SET title=excluded.title, cpeData=excluded.cpeData, cveData=excluded.cveData
        ''', (uid, a['cpeName'], a.get('title',''), json.dumps(a.get('cpeData',{})), json.dumps(a.get('cveData',{}))))

    # Remove assets no longer present
    if incoming_cpes:
        placeholders = ','.join('?' * len(incoming_cpes))
        conn.execute(f'DELETE FROM assets WHERE user_id = ? AND cpeName NOT IN ({placeholders})',
                     (uid, *incoming_cpes))
    else:
        conn.execute('DELETE FROM assets WHERE user_id = ?', (uid,))

    conn.commit()
    conn.close()
    return jsonify({'success': True})

#---ARCHIVE ASSETS---
@app.route('/db/archived-assets', methods=['POST'])
@require_permission('Asset Directory', 'Archive assets')
def archive_asset():
    uid = get_current_user_id()
    data = request.json or {}
    cpe_name = data.get('cpeName')
    is_archived = data.get('isArchived', 1)

    if not cpe_name:
        return jsonify({'error': 'cpeName is required'}), 400

    conn = get_db()
    asset = conn.execute('SELECT id FROM assets WHERE user_id = ? AND cpeName = ?', (uid, cpe_name)).fetchone()
    if not asset:
        conn.close()
        return jsonify({'error': 'Asset not found'}), 404

    archived_ts = None
    if is_archived:
        archived_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')

    existing = conn.execute('SELECT id FROM archivedAssets WHERE asset_id = ? AND user_id = ?', (asset['id'], uid)).fetchone()
    if existing:
        conn.execute(
            'UPDATE archivedAssets SET archived = ?, isArchived = ? WHERE asset_id = ? AND user_id = ?',
            (archived_ts, int(is_archived), asset['id'], uid)
        )
    else:
        conn.execute(
            'INSERT INTO archivedAssets (asset_id, user_id, archived, isArchived) VALUES (?, ?, ?, ?)',
            (asset['id'], uid, archived_ts, int(is_archived))
        )

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'cpeName': cpe_name, 'isArchived': is_archived, 'archived': archived_ts})

#---LOAD ASSETS---
@app.route('/db/load-assets', methods=['GET'])
@require_permission('Asset Directory', 'Viewable Asset Directory tab')
def load_assets():
    uid = get_current_user_id()
    role = session.get('role', 'viewer')
    conn = get_db()
    policy = conn.execute('SELECT asset_sharing_mode FROM org_policies LIMIT 1').fetchone()
    sharing_mode = policy['asset_sharing_mode'] if policy else 'private'

    if sharing_mode == 'visible':
        rows = conn.execute('SELECT * FROM assets').fetchall()
    elif sharing_mode == 'collaborative' and get_role_level(role) >= get_role_level('analyst'):
        rows = conn.execute('SELECT * FROM assets').fetchall()
    elif sharing_mode == 'private' and get_role_level(role) >= get_role_level('manager'):
        rows = conn.execute('SELECT * FROM assets').fetchall()
    else:
        rows = conn.execute('SELECT * FROM assets WHERE user_id = ?', (uid,)).fetchall()

    conn.close()
    return jsonify([{
        'cpeName': r['cpeName'],
        'title': r['title'],
        'cpeData': json.loads(r['cpeData']),
        'cveData': json.loads(r['cveData'])
    } for r in rows])

#---LOAD ARCHIVED ASSETS---
@app.route('/db/load-archived-assets', methods=['GET'])
@require_permission('Asset Directory', 'Viewable Asset Directory tab')
def load_archived_assets():
    uid = get_current_user_id()
    role = session.get('role', 'viewer')
    conn = get_db()
    policy = conn.execute('SELECT asset_sharing_mode FROM org_policies LIMIT 1').fetchone()
    sharing_mode = policy['asset_sharing_mode'] if policy else 'private'

    if sharing_mode == 'visible':
        rows = conn.execute('''
            SELECT assets.cpeName FROM archivedAssets
            JOIN assets ON archivedAssets.asset_id = assets.id
            WHERE archivedAssets.isArchived = 1
        ''').fetchall()
    elif sharing_mode == 'collaborative' and get_role_level(role) >= get_role_level('analyst'):
        rows = conn.execute('''
            SELECT assets.cpeName FROM archivedAssets
            JOIN assets ON archivedAssets.asset_id = assets.id
            WHERE archivedAssets.isArchived = 1
        ''').fetchall()
    elif sharing_mode == 'private' and get_role_level(role) >= get_role_level('manager'):
        rows = conn.execute('''
            SELECT assets.cpeName FROM archivedAssets
            JOIN assets ON archivedAssets.asset_id = assets.id
            WHERE archivedAssets.isArchived = 1
        ''').fetchall()
    else:
        rows = conn.execute('''
            SELECT assets.cpeName FROM archivedAssets
            JOIN assets ON archivedAssets.asset_id = assets.id
            WHERE archivedAssets.user_id = ? AND archivedAssets.isArchived = 1
        ''', (uid,)).fetchall()

    conn.close()
    return jsonify([r['cpeName'] for r in rows])

#=====================
# TICKET DB ENDPOINTS
#=====================

#---CREATE TICKETS---
@app.route('/db/save-tickets', methods=['POST'])
@require_permission('myTickets', 'Create tickets')
def save_tickets():
    uid = get_current_user_id()
    tickets = request.json.get('tickets', [])
    conn = get_db()

    incoming_ids = set()
    for t in tickets:
        tid = t.get('id')
        is_resolved = int(t.get('isResolved') or 0)
        if tid:
            incoming_ids.add(tid)
            conn.execute('''
                INSERT INTO tickets (id, user_id, description, feature, created, isResolved)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id)
                DO UPDATE SET description=excluded.description, feature=excluded.feature, isResolved=excluded.isResolved
            ''', (tid, uid, t['description'], t['feature'], t['created'], is_resolved))
        else:
            cursor = conn.execute(
                'INSERT INTO tickets (user_id, description, feature, created, isResolved) VALUES (?, ?, ?, ?, ?)',
                (uid, t['description'], t['feature'], t['created'], is_resolved)
            )
            incoming_ids.add(cursor.lastrowid)

    id_list = tuple(incoming_ids) or (0,)
    placeholders = ','.join('?' * len(id_list))
    conn.execute(f'DELETE FROM tickets WHERE user_id = ? AND id NOT IN ({placeholders})',
                 (uid, *id_list))

    conn.commit()
    conn.close()
    return jsonify({'success': True})

#---TICKET STATUS---
@app.route('/db/ticket-status', methods=['POST'])
@require_permission('myTickets', 'Update ticket status')
def ticket_status():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')
    status = data.get('status')

    if not ticket_id or not status:
        return jsonify({'error': 'ticket_id and status are required'}), 400

    conn = get_db()
    ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    updated_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')

    existing = conn.execute('SELECT id FROM statusTickets WHERE ticket_id = ?', (ticket_id,)).fetchone()
    if existing:
        conn.execute(
            'UPDATE statusTickets SET status = ?, user_id = ?, updated = ? WHERE ticket_id = ?',
            (status, uid, updated_ts, ticket_id)
        )
    else:
        conn.execute(
            'INSERT INTO statusTickets (ticket_id, user_id, status, updated) VALUES (?, ?, ?, ?)',
            (ticket_id, uid, status, updated_ts)
        )

    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, uid, f'Status changed to {status}', updated_ts)
    )

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'ticket_id': ticket_id, 'status': status, 'updated': updated_ts})

#---DELETE TICKET---
def ticket_delete():
    pass

#---ACCEPT TICKET---
@app.route('/db/ticket-acceptance', methods=['POST'])
@require_permission('myTickets', 'Accept tickets')
def ticket_acceptance():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400

    conn = get_db()
    ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    # Check if already accepted
    existing = conn.execute('SELECT id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'Ticket already accepted'}), 409

    accepted_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
    conn.execute(
        'INSERT INTO acceptedTickets (ticket_id, user_id, accepted, isAccepted) VALUES (?, ?, ?, 1)',
        (ticket_id, uid, accepted_ts)
    )

    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, uid, 'Accepted', accepted_ts)
    )

    conn.commit()

    username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']
    conn.close()
    return jsonify({'success': True, 'ticket_id': ticket_id, 'accepted': accepted_ts, 'accepted_by': username})

#---RESOLVE TICKET---
@app.route('/db/ticket-resolution', methods=['POST'])
@require_permission('myTickets', 'Resolve tickets')
def ticket_resolution():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')
    is_resolved = data.get('isResolved', 0)

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400

    conn = get_db()
    ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404
    
    accepted = conn.execute(
        'SELECT user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()
    if not accepted:
        conn.close()
        return jsonify({'error': 'Ticket must be accepted before resolving'}), 400
    if accepted['user_id'] != get_current_user_id():
        conn.close()
        return jsonify({'error': 'Only the accepting user can resolve this ticket'}), 403

    resolved_ts = None
    if is_resolved:
        resolved_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')

    existing = conn.execute('SELECT id FROM resolvedTickets WHERE ticket_id = ?', (ticket_id,)).fetchone()
    if existing:
        conn.execute(
            'UPDATE resolvedTickets SET resolved = ?, isResolved = ? WHERE ticket_id = ?',
            (resolved_ts, int(is_resolved), ticket_id)
        )
    else:
        conn.execute(
            'INSERT INTO resolvedTickets (ticket_id, resolved, isResolved) VALUES (?, ?, ?)',
            (ticket_id, resolved_ts, int(is_resolved))
        )

    action = 'Resolved' if is_resolved else 'Reopened'
    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, get_current_user_id(), action, resolved_ts or datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p'))
    )

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'ticket_id': ticket_id, 'isResolved': is_resolved, 'resolved': resolved_ts})

#---REASSIGN TICKET---
@app.route('/db/ticket-reassign', methods=['POST'])
@require_permission('myTickets', 'Reassign tickets')
def ticket_reassign():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400

    conn = get_db()
    ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    # Only the current acceptor can reassign
    accepted = conn.execute(
        'SELECT id, user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()
    if not accepted or accepted['user_id'] != uid:
        conn.close()
        return jsonify({'error': 'Only the accepting user can reassign this ticket'}), 403

    reassigned_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
    username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

    # Clear the acceptance
    conn.execute(
        'UPDATE acceptedTickets SET isAccepted = 0 WHERE ticket_id = ? AND user_id = ?',
        (ticket_id, uid)
    )

    # Clear any resolution tied to this ticket
    conn.execute(
        'UPDATE resolvedTickets SET isResolved = 0, resolved = NULL WHERE ticket_id = ?',
        (ticket_id,)
    )

    # Log the reassignment
    conn.execute(
        'INSERT INTO reassignedTickets (ticket_id, user_id, reassigned) VALUES (?, ?, ?)',
        (ticket_id, uid, reassigned_ts)
    )

    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, uid, 'Reassigned', reassigned_ts)
    )

    conn.commit()
    conn.close()
    return jsonify({
        'success': True, 'ticket_id': ticket_id,
        'reassigned': reassigned_ts, 'reassigned_by': username
    })

#---COMMENT TICKET---
@app.route('/db/ticket-comment', methods=['POST'])
@require_permission('myTickets', 'Comment tickets')
def ticket_comment():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')
    comment_desc = data.get('comment_description', '').strip()

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400
    if not comment_desc:
        return jsonify({'error': 'Comment cannot be empty'}), 400

    conn = get_db()
    ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    # Acceptor OR collaborator can comment
    accepted = conn.execute(
        'SELECT id, user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()

    is_acceptor = accepted and accepted['user_id'] == uid
    is_collaborator = conn.execute(
        'SELECT id FROM ticketCollaborators WHERE ticket_id = ? AND user_id = ?', (ticket_id, uid)
    ).fetchone() is not None

    if not is_acceptor and not is_collaborator:
        conn.close()
        return jsonify({'error': 'Only the accepting user or a collaborator can comment on this ticket'}), 403

    commented_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
    username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

    accepted_id = accepted['id'] if accepted else None
    conn.execute(
        'INSERT INTO commentTickets (ticket_id, accepted_id, user_id, commented, comment_description) VALUES (?, ?, ?, ?, ?)',
        (ticket_id, accepted_id, uid, commented_ts, comment_desc)
    )

    # Parse @mentions and add collaborators
    mentions = parse_mentions(comment_desc)
    new_collaborators = []
    for username in mentions:
        mentioned_user = conn.execute(
            'SELECT id, username FROM users WHERE username = ?', (username,)
        ).fetchone()
        if mentioned_user and mentioned_user['id'] != uid and (not accepted or mentioned_user['id'] != accepted['user_id']):
            existing = conn.execute(
                'SELECT id FROM ticketCollaborators WHERE ticket_id = ? AND user_id = ?',
                (ticket_id, mentioned_user['id'])
            ).fetchone()
            if not existing:
                conn.execute(
                    'INSERT INTO ticketCollaborators (ticket_id, user_id, added_by, added) VALUES (?, ?, ?, ?)',
                    (ticket_id, mentioned_user['id'], uid, commented_ts)
                )
                conn.execute(
                    'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
                    (ticket_id, uid, f'Collaborator added: {mentioned_user["username"]}', commented_ts)
                )
                new_collaborators.append(mentioned_user['username'])

    conn.commit()
    conn.close()
    return jsonify({
        'success': True, 'ticket_id': ticket_id,
        'commented': commented_ts, 'comment_by': username,
        'comment_description': comment_desc,
        'new_collaborators': new_collaborators
    })

#---FIX COMMENT---
@app.route('/db/ticket-comment-fix', methods=['POST'])
@require_permission('myTickets', 'Fix comment tickets')
def ticket_comment_fix():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')
    comment_id = data.get('comment_id')

    if not ticket_id or not comment_id:
        return jsonify({'error': 'ticket_id and comment_id are required'}), 400

    conn = get_db()

# Verify ticket exists and this user is the ticket owner OR a collaborator
    ticket = conn.execute('SELECT id, user_id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    is_owner = ticket['user_id'] == uid
    is_collaborator = conn.execute(
        'SELECT id FROM ticketCollaborators WHERE ticket_id = ? AND user_id = ?', (ticket_id, uid)
    ).fetchone() is not None

    if not is_owner and not is_collaborator:
        conn.close()
        return jsonify({'error': 'Only the ticket owner or a collaborator can mark comments as fixed'}), 403

    comment = conn.execute('SELECT id FROM commentTickets WHERE id = ? AND ticket_id = ?', (comment_id, ticket_id)).fetchone()
    if not comment:
        conn.close()
        return jsonify({'error': 'Comment not found'}), 404

    fixed_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
    username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

    conn.execute(
        'UPDATE commentTickets SET isFixed = 1, fixed = ? WHERE id = ?',
        (fixed_ts, comment_id)
    )

    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, uid, 'Comment marked as Fixed', fixed_ts)
    )

    conn.commit()
    conn.close()
    return jsonify({
        'success': True, 'ticket_id': ticket_id, 'comment_id': comment_id,
        'fixed': fixed_ts, 'fixed_by': username
    })

#---REOPEN TICKET---
def ticket_reopen():
    pass

#---ARCHIVE TICKET---
@app.route('/db/ticket-archive', methods=['POST'])
@require_permission('myTickets', 'Delete tickets')
def ticket_archive():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')
    is_archived = data.get('isArchived', 0)

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400

    conn = get_db()
    ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    # Only the acceptor can archive
    accepted = conn.execute(
        'SELECT id, user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()
    if not accepted or accepted['user_id'] != uid:
        conn.close()
        return jsonify({'error': 'Only the accepting user can archive this ticket'}), 403

    archived_ts = None
    if is_archived:
        archived_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')

    existing = conn.execute('SELECT id FROM archivedTickets WHERE ticket_id = ?', (ticket_id,)).fetchone()
    if existing:
        conn.execute(
            'UPDATE archivedTickets SET archived = ?, isArchived = ? WHERE ticket_id = ?',
            (archived_ts, int(is_archived), ticket_id)
        )
    else:
        conn.execute(
            'INSERT INTO archivedTickets (ticket_id, accepted_id, user_id, archived, isArchived) VALUES (?, ?, ?, ?, ?)',
            (ticket_id, accepted['id'], uid, archived_ts, int(is_archived))
        )

    action = 'Archived' if is_archived else 'Unarchived'
    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, uid, action, archived_ts or datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p'))
    )

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'ticket_id': ticket_id, 'isArchived': is_archived, 'archived': archived_ts})

#---LOAD TICKETS---
@app.route('/db/load-tickets', methods=['GET'])
@require_permission('myTickets', 'Viewable myTickets tab')
def load_tickets():
    conn = get_db()
    rows = conn.execute('''
        SELECT tickets.*, users.username AS creator_email,
            resolvedTickets.resolved AS rt_resolved,
            resolvedTickets.isResolved AS rt_isResolved,
            acceptedTickets.accepted AS at_accepted,
            acceptedTickets.isAccepted AS at_isAccepted,
            acceptors.username AS accepted_by_email,
            archivedTickets.archived AS at_archived,
            archivedTickets.isArchived AS at_isArchived,
            statusTickets.status AS st_status
        FROM tickets
        JOIN users ON tickets.user_id = users.id
        LEFT JOIN resolvedTickets ON resolvedTickets.ticket_id = tickets.id
        LEFT JOIN acceptedTickets ON acceptedTickets.ticket_id = tickets.id AND acceptedTickets.isAccepted = 1
        LEFT JOIN users AS acceptors ON acceptedTickets.user_id = acceptors.id
        LEFT JOIN archivedTickets ON archivedTickets.ticket_id = tickets.id
        LEFT JOIN statusTickets ON statusTickets.ticket_id = tickets.id
    ''').fetchall()

    # Fetch all comments with commenter username
    comment_rows = conn.execute('''
        SELECT commentTickets.id AS comment_id, commentTickets.ticket_id, commentTickets.commented,
            commentTickets.comment_description, commentTickets.isFixed, commentTickets.fixed,
            users.username AS comment_by
        FROM commentTickets
        JOIN users ON commentTickets.user_id = users.id
        ORDER BY commentTickets.id ASC
    ''').fetchall()

    # Group comments by ticket_id
    comments_map = {}
    for c in comment_rows:
        tid = c['ticket_id']
        if tid not in comments_map:
            comments_map[tid] = []
        comments_map[tid].append({
            'id': c['comment_id'],
            'comment_by': c['comment_by'],
            'commented': c['commented'],
            'comment_description': c['comment_description'],
            'isFixed': bool(c['isFixed']),
            'fixed': c['fixed']
        })

    activity_rows = conn.execute('''
        SELECT ticketActivity.ticket_id, ticketActivity.action,
            ticketActivity.timestamp, users.username AS action_by
        FROM ticketActivity
        JOIN users ON ticketActivity.user_id = users.id
        ORDER BY ticketActivity.id ASC
    ''').fetchall()

    activity_map = {}
    for a in activity_rows:
        tid = a['ticket_id']
        if tid not in activity_map:
            activity_map[tid] = []
        activity_map[tid].append({
            'action': a['action'],
            'action_by': a['action_by'],
            'timestamp': a['timestamp']
        })

        # Fetch collaborators per ticket
        collab_rows = conn.execute('''
            SELECT ticketCollaborators.ticket_id, users.username AS collaborator_email
            FROM ticketCollaborators
            JOIN users ON ticketCollaborators.user_id = users.id
        ''').fetchall()

        collab_map = {}
        for c in collab_rows:
            tid = c['ticket_id']
            if tid not in collab_map:
                collab_map[tid] = []
            collab_map[tid].append(c['collaborator_email'])

    conn.close()
    return jsonify([{
        'id': r['id'],
        'user_id': r['user_id'],
        'creator_email': r['creator_email'],
        'description': r['description'],
        'feature': r['feature'],
        'created': r['created'],
        'resolved': r['rt_resolved'] if r['rt_isResolved'] else None,
        'isResolved': bool(r['rt_isResolved']) if r['rt_isResolved'] is not None else bool(r['isResolved']),
        'accepted': r['at_accepted'] if r['at_isAccepted'] else None,
        'isAccepted': bool(r['at_isAccepted']) if r['at_isAccepted'] is not None else False,
        'accepted_by': r['accepted_by_email'] if r['at_isAccepted'] else None,
        'resolved_by': r['accepted_by_email'] if r['rt_isResolved'] else None,
        'isArchived': bool(r['at_isArchived']) if r['at_isArchived'] is not None else False,
        'archived': r['at_archived'] if r['at_isArchived'] else None,
        'comments': comments_map.get(r['id'], []),
        'activity': activity_map.get(r['id'], []),
        'status': r['st_status'] or 'Open',
        'collaborators': collab_map.get(r['id'], [])
    } for r in rows])

#---TICKET STATS---
@app.route('/db/ticket-stats', methods=['GET'])
@require_permission('myTickets', 'Viewable myTickets tab')
def ticket_stats():
    conn = get_db()

# Counts by status (derived from state tables, not just statusTickets)
    archived_count = conn.execute('''
        SELECT COUNT(*) AS c FROM archivedTickets WHERE isArchived = 1
    ''').fetchone()['c']

    resolved_count = conn.execute('''
        SELECT COUNT(DISTINCT t.id) AS c FROM tickets t
        LEFT JOIN resolvedTickets r ON r.ticket_id = t.id
        LEFT JOIN archivedTickets a ON a.ticket_id = t.id
        WHERE r.isResolved = 1 OR a.isArchived = 1
    ''').fetchone()['c']

    in_progress_count = conn.execute('''
        SELECT COUNT(*) AS c FROM tickets t
        JOIN statusTickets s ON s.ticket_id = t.id
        LEFT JOIN resolvedTickets r ON r.ticket_id = t.id
        LEFT JOIN archivedTickets a ON a.ticket_id = t.id
        WHERE s.status = 'In Progress'
            AND COALESCE(r.isResolved, 0) = 0
            AND COALESCE(a.isArchived, 0) = 0
    ''').fetchone()['c']

    total_count = conn.execute('SELECT COUNT(*) AS c FROM tickets').fetchone()['c']
    open_count = total_count - resolved_count - in_progress_count

    by_status = {
        'Open': open_count,
        'In Progress': in_progress_count,
        'Resolved': resolved_count,
        'Archived': archived_count
    }

    # Counts by feature
    by_feature = conn.execute('''
        SELECT feature, COUNT(*) AS count
        FROM tickets
        GROUP BY feature
        ORDER BY count DESC
    ''').fetchall()

    # Per-person workload (accepted tickets, not archived)
    by_person = conn.execute('''
        SELECT u.username, COUNT(*) AS count
        FROM acceptedTickets at2
        JOIN users u ON at2.user_id = u.id
        JOIN tickets t ON at2.ticket_id = t.id
        LEFT JOIN archivedTickets a ON a.ticket_id = t.id
        WHERE at2.isAccepted = 1 AND COALESCE(a.isArchived, 0) = 0
        GROUP BY u.username
        ORDER BY count DESC
    ''').fetchall()

    # Resolution rate
    total = conn.execute('''
        SELECT COUNT(*) AS c FROM tickets
    ''').fetchone()['c']

    resolved = conn.execute('''
        SELECT COUNT(DISTINCT t.id) AS c FROM tickets t
        LEFT JOIN resolvedTickets r ON r.ticket_id = t.id
        LEFT JOIN archivedTickets a ON a.ticket_id = t.id
        WHERE r.isResolved = 1 OR a.isArchived = 1
    ''').fetchone()['c']

    # Aging: open tickets with days since creation
    aging = conn.execute('''
        SELECT t.id, t.created, COALESCE(s.status, 'Open') AS status
        FROM tickets t
        LEFT JOIN statusTickets s ON s.ticket_id = t.id
        LEFT JOIN archivedTickets a ON a.ticket_id = t.id
        WHERE COALESCE(s.status, 'Open') IN ('Open', 'In Progress')
            AND COALESCE(a.isArchived, 0) = 0
    ''').fetchall()

    conn.close()

    return jsonify({
        'by_status': by_status,
        'by_feature': {r['feature']: r['count'] for r in by_feature},
        'by_person': {r['username']: r['count'] for r in by_person},
        'resolution': {'resolved': resolved, 'total': total},
        'aging': [{'id': r['id'], 'created': r['created'], 'status': r['status']} for r in aging]
    })

#=====================
# ADMIN ENDPOINTS
#=====================

@app.route('/admin/users', methods=['GET'])
@require_role('admin')
def admin_list_users():
    conn = get_db()
    users = conn.execute('SELECT id, username, role, must_change_password, created_at FROM users').fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/admin/users/create', methods=['POST'])
@require_role('admin')
def admin_create_user():
    data = request.json or {}
    username = data.get('username', '').strip()
    role = data.get('role', 'viewer')
    valid_roles = ('viewer', 'analyst', 'manager', 'admin')
    if not username:
        return jsonify({'error': 'Username is required.'}), 400
    if role not in valid_roles:
        return jsonify({'error': f'Role must be one of {valid_roles}'}), 400

    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        conn.close()
        return jsonify({'error': 'Username already exists.'}), 409

    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    policy = conn.execute('SELECT otp_expiry_hours FROM org_policies LIMIT 1').fetchone()
    expiry_hours = policy['otp_expiry_hours'] if policy else 72
    from datetime import timedelta
    expires_at = (datetime.now() + timedelta(hours=expiry_hours)).isoformat()

    conn.execute(
        'INSERT INTO users (username, otp_hash, otp_expires_at, role, must_change_password) VALUES (?, ?, ?, ?, ?)',
        (username, otp_hash, expires_at, role, 1)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'username': username, 'role': role, 'otp': otp, 'expires_at': expires_at}), 201

@app.route('/admin/users/update-role', methods=['POST'])
@require_role('admin')
def admin_update_role():
    data = request.json or {}
    username = data.get('username', '').strip()
    role = data.get('role', '')
    valid_roles = ('viewer', 'analyst', 'manager', 'admin')
    if role not in valid_roles:
        return jsonify({'error': f'Role must be one of {valid_roles}'}), 400
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found.'}), 404
    conn.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'username': username, 'role': role})

@app.route('/admin/users/reset-otp', methods=['POST'])
@require_role('admin')
def admin_reset_otp():
    data = request.json or {}
    username = data.get('username', '').strip()
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found.'}), 404

    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    policy = conn.execute('SELECT otp_expiry_hours FROM org_policies LIMIT 1').fetchone()
    expiry_hours = policy['otp_expiry_hours'] if policy else 72
    from datetime import timedelta
    expires_at = (datetime.now() + timedelta(hours=expiry_hours)).isoformat()

    conn.execute(
        'UPDATE users SET otp_hash = ?, otp_expires_at = ?, must_change_password = 1, password_hash = NULL WHERE username = ?',
        (otp_hash, expires_at, username)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'username': username, 'otp': otp, 'expires_at': expires_at})

@app.route('/admin/users/delete', methods=['POST'])
@require_role('admin')
def admin_delete_user():
    data = request.json or {}
    username = data.get('username', '').strip()
    conn = get_db()
    user = conn.execute('SELECT id, role FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found.'}), 404
    if user['role'] == 'admin':
        count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        if count <= 1:
            conn.close()
            return jsonify({'error': 'Cannot delete the only admin account.'}), 400
    conn.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'username': username})

@app.route('/admin/policies', methods=['GET'])
@require_role('admin')
def admin_get_policies():
    conn = get_db()
    policy = conn.execute('SELECT * FROM org_policies LIMIT 1').fetchone()
    conn.close()
    return jsonify(dict(policy) if policy else {})

@app.route('/admin/policies', methods=['POST'])
@require_role('admin')
def admin_update_policies():
    data = request.json or {}
    uid = get_current_user_id()
    conn = get_db()
    conn.execute('''
        UPDATE org_policies SET
            asset_sharing_mode = COALESCE(?, asset_sharing_mode),
            sod_enforcement = COALESCE(?, sod_enforcement),
            otp_expiry_hours = COALESCE(?, otp_expiry_hours),
            updated_at = ?,
            updated_by = ?
        WHERE id = 1
    ''', (
        data.get('asset_sharing_mode'),
        data.get('sod_enforcement'),
        data.get('otp_expiry_hours'),
        datetime.now().isoformat(),
        uid
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/permissions', methods=['GET'])
@require_role('admin')
def get_permissions():
    conn = get_db()
    rows = conn.execute(
        'SELECT category, permission, role, access_level FROM role_permissions ORDER BY id'
    ).fetchall()
    conn.close()
    result = {}
    for r in rows:
        cat = r['category']
        perm = r['permission']
        role = r['role']
        if cat not in result:
            result[cat] = {}
        if perm not in result[cat]:
            result[cat][perm] = {}
        result[cat][perm][role] = r['access_level']
    return jsonify(result)

@app.route('/admin/permissions', methods=['POST'])
@require_role('admin')
def update_permission():
    data = request.get_json()
    category = data.get('category')
    permission = data.get('permission')
    role = data.get('role')
    access_level = data.get('access_level')

    valid_levels = ['blocked', 'read only', 'read/write', 'managerial approval', 'admin approval']
    if access_level not in valid_levels:
        return jsonify({'error': 'Invalid access level'}), 400

    conn = get_db()
    conn.execute(
        '''INSERT INTO role_permissions (category, permission, role, access_level, updated_at, updated_by)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(category, permission, role)
            DO UPDATE SET access_level = excluded.access_level,
                        updated_at = excluded.updated_at,
                        updated_by = excluded.updated_by''',
        (category, permission, role, access_level, session.get('user_id'))
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

#===========
# MAIN
#===========

def main():
    init_db()
    app.run(host='0.0.0.0', debug=True, port=5000)

if __name__ == '__main__':
    main()
