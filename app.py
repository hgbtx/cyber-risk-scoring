#=====================
# IMPORTS & CONFIG
#=====================

from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)

import time, requests, os, json
from datetime import datetime
from dotenv import load_dotenv
from db import get_db, init_db
from functools import wraps
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
# AUTHENTICATION
#=====================

#---AUTHENTICATION HELPERS---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def get_current_user_id():
    return session.get('user_id')

#---AUTHENTICATION ENDPOINTS---
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400
    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
        conn.close()
        return jsonify({'error': 'An account with that email already exists.'}), 409
    pw_hash = generate_password_hash(password)
    cursor = conn.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, pw_hash))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    session['user_id'] = user_id
    session['email'] = email
    session['role'] = 'analyst'
    return jsonify({'success': True, 'user': {'id': user_id, 'email': email, 'role': 'analyst'}}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid email or password.'}), 401
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['role'] = user['role']
    return jsonify({'success': True, 'user': {'id': user['id'], 'email': user['email'], 'role': user['role']}})

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
    user = conn.execute('SELECT id, email, role FROM users WHERE id = ?', (uid,)).fetchone()
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

#---PARSE DATE HELPER---
def parse_date(date_str):
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except:
        return datetime(2000, 1, 1)

#---KEV CACHING---
@app.route('/api/get_kev_list', methods=['POST'])
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def load_assets():
    uid = get_current_user_id()
    conn = get_db()
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
@login_required
def load_archived_assets():
    uid = get_current_user_id()
    conn = get_db()
    rows = conn.execute('''
        SELECT assets.cpeName
        FROM archivedAssets
        JOIN assets ON archivedAssets.asset_id = assets.id
        WHERE archivedAssets.user_id = ? AND archivedAssets.isArchived = 1
    ''', (uid,)).fetchall()
    conn.close()
    return jsonify([r['cpeName'] for r in rows])

#=====================
# TICKET DB ENDPOINTS
#=====================

#---SAVE TICKETS---
@app.route('/db/save-tickets', methods=['POST'])
@login_required
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

#---DELETE TICKET---
# @app.route('/db/ticket-delete', methods=['POST'])
# @login_required
def ticket_delete():
    pass

#---ACCEPT TICKET---
@app.route('/db/ticket-acceptance', methods=['POST'])
@login_required
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
        (ticket_id, uid, 'accepted', accepted_ts)
    )

    conn.commit()

    email = conn.execute('SELECT email FROM users WHERE id = ?', (uid,)).fetchone()['email']
    conn.close()
    return jsonify({'success': True, 'ticket_id': ticket_id, 'accepted': accepted_ts, 'accepted_by': email})

#---RESOLVE TICKET---
@app.route('/db/ticket-resolution', methods=['POST'])
@login_required
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

    action = 'resolved' if is_resolved else 'reopened'
    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, get_current_user_id(), action, resolved_ts or datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p'))
    )

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'ticket_id': ticket_id, 'isResolved': is_resolved, 'resolved': resolved_ts})

#---REASSIGN TICKET---
@app.route('/db/ticket-reassign', methods=['POST'])
@login_required
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
    email = conn.execute('SELECT email FROM users WHERE id = ?', (uid,)).fetchone()['email']

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
        (ticket_id, uid, 'reassigned', reassigned_ts)
    )

    conn.commit()
    conn.close()
    return jsonify({
        'success': True, 'ticket_id': ticket_id,
        'reassigned': reassigned_ts, 'reassigned_by': email
    })

#---COMMENT TICKET---
@app.route('/db/ticket-comment', methods=['POST'])
@login_required
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

    # Only the current acceptor can comment
    accepted = conn.execute(
        'SELECT id, user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()
    if not accepted or accepted['user_id'] != uid:
        conn.close()
        return jsonify({'error': 'Only the accepting user can comment on this ticket'}), 403

    commented_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
    email = conn.execute('SELECT email FROM users WHERE id = ?', (uid,)).fetchone()['email']

    conn.execute(
        'INSERT INTO commentTickets (ticket_id, accepted_id, user_id, commented, comment_description) VALUES (?, ?, ?, ?, ?)',
        (ticket_id, accepted['id'], uid, commented_ts, comment_desc)
    )

    conn.commit()
    conn.close()
    return jsonify({
        'success': True, 'ticket_id': ticket_id,
        'commented': commented_ts, 'comment_by': email,
        'comment_description': comment_desc
    })

#---REOPEN TICKET---
# @app.route('/db/ticket-reopen', methods=['POST'])
# @login_required
def ticket_reopen():
    pass

#---ARCHIVE TICKET---
@app.route('/db/ticket-archive', methods=['POST'])
@login_required
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

    action = 'archived' if is_archived else 'unarchived'
    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, uid, action, archived_ts or datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p'))
    )

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'ticket_id': ticket_id, 'isArchived': is_archived, 'archived': archived_ts})

#---LOAD TICKETS---
@app.route('/db/load-tickets', methods=['GET'])
@login_required
def load_tickets():
    conn = get_db()
    rows = conn.execute('''
        SELECT tickets.*, users.email AS creator_email,
            resolvedTickets.resolved AS rt_resolved,
            resolvedTickets.isResolved AS rt_isResolved,
            acceptedTickets.accepted AS at_accepted,
            acceptedTickets.isAccepted AS at_isAccepted,
            acceptors.email AS accepted_by_email,
            archivedTickets.archived AS at_archived,
            archivedTickets.isArchived AS at_isArchived
        FROM tickets
        JOIN users ON tickets.user_id = users.id
        LEFT JOIN resolvedTickets ON resolvedTickets.ticket_id = tickets.id
        LEFT JOIN acceptedTickets ON acceptedTickets.ticket_id = tickets.id AND acceptedTickets.isAccepted = 1
        LEFT JOIN users AS acceptors ON acceptedTickets.user_id = acceptors.id
        LEFT JOIN archivedTickets ON archivedTickets.ticket_id = tickets.id
    ''').fetchall()

    # Fetch all comments with commenter email
    comment_rows = conn.execute('''
        SELECT commentTickets.ticket_id, commentTickets.commented,
            commentTickets.comment_description, users.email AS comment_by
        FROM commentTickets
        JOIN users ON commentTickets.user_id = users.id
        ORDER BY commentTickets.id ASC
    ''').fetchall()
    conn.close()

    # Group comments by ticket_id
    comments_map = {}
    for c in comment_rows:
        tid = c['ticket_id']
        if tid not in comments_map:
            comments_map[tid] = []
        comments_map[tid].append({
            'comment_by': c['comment_by'],
            'commented': c['commented'],
            'comment_description': c['comment_description']
        })

    activity_rows = conn.execute('''
        SELECT ticketActivity.ticket_id, ticketActivity.action,
            ticketActivity.timestamp, users.email AS action_by
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
    } for r in rows])

#===========
# MAIN
#===========

def main():
    init_db()
    app.run(host='0.0.0.0', debug=True, port=5000)

if __name__ == '__main__':
    main()
    