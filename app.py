#---CONFIGURATION---
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

##---AUTHENTICATION HELPERS---
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

# ---CVE PRIORITY SCORING---
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

#---RISK FORMULAS---
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

#---AGGREGATION METHODS---
@app.route('/math/aggregation-methods', methods=['POST'])
def max_agg(values):
    return max_score(values)

def mean_agg(values):
    return simple_mean_score(values)

def median_agg(values):
    return sorted(values)[len(values)//2] if values else 0

def sum_agg(values):
    return sum(values)

#---RISK THRESHOLD---
@app.route('/math/risk-threshold', methods=['POST'])
def count_high_risk(series, threshold=7.0):
    return (series >= threshold).sum()

#---DATABASE ENDPOINTS---
@app.route('/db/save-assets', methods=['POST'])
def save_assets():
    assets = request.json.get('assets', [])
    conn = get_db()
    conn.execute('DELETE FROM assets')
    for a in assets:
        conn.execute(
            'INSERT OR REPLACE INTO assets (cpeName, title, cpeData, cveData) VALUES (?, ?, ?, ?)',
            (a['cpeName'], a.get('title',''), json.dumps(a.get('cpeData',{})), json.dumps(a.get('cveData',{})))
        )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/db/load-assets', methods=['GET'])
def load_assets():
    conn = get_db()
    rows = conn.execute('SELECT * FROM assets').fetchall()
    conn.close()
    return jsonify([{
        'cpeName': r['cpeName'],
        'title': r['title'],
        'cpeData': json.loads(r['cpeData']),
        'cveData': json.loads(r['cveData'])
    } for r in rows])

@app.route('/db/save-tickets', methods=['POST'])
def save_tickets():
    tickets = request.json.get('tickets', [])
    conn = get_db()
    conn.execute('DELETE FROM tickets')
    for t in tickets:
        conn.execute(
            'INSERT INTO tickets (id, description, feature, created, resolved) VALUES (?, ?, ?, ?, ?)',
            (t['id'], t['description'], t['feature'], t['created'], int(t.get('resolved', False)))
        )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/db/load-tickets', methods=['GET'])
def load_tickets():
    conn = get_db()
    rows = conn.execute('SELECT * FROM tickets').fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'],
        'description': r['description'],
        'feature': r['feature'],
        'created': r['created'],
        'resolved': bool(r['resolved'])
    } for r in rows])

def main():
    init_db()
    app.run(host='0.0.0.0', debug=True, port=5000)


if __name__ == '__main__':
    main()
    