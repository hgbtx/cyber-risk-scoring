#=====================
# IMPORTS & CONFIG
#=====================

from flask import Flask, Response, jsonify, render_template, request, session

app = Flask(__name__)

import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import string
import time
from datetime import datetime, timedelta
from functools import wraps

import pyotp
import qrcode
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

from auth_helpers import require_role, ROLE_LEVELS
from db import get_db, init_db

load_dotenv()
app.secret_key = os.getenv('SECRET_KEY', os.urandom(32).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV', '').strip("'\"") != 'development'
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

TS_FMT = '%m/%d/%Y, %I:%M:%S %p'

def parse_app_ts(ts_str):
    """Parse a timestamp string (app format or ISO 8601) to a datetime object."""
    if not ts_str:
        return None
    try:
        return datetime.strptime(ts_str, TS_FMT)
    except (ValueError, TypeError):
        pass
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None

#=====================
# BACKGROUND SCHEDULER
#=====================

scheduler = BackgroundScheduler()

def scheduled_rescan():
    """Background job: re-fetch CVEs for all tracked assets, create tickets for new high-severity findings."""
    with app.app_context():
        conn = get_db()
        policy = conn.execute('SELECT * FROM org_policies WHERE org_id = 1').fetchone()
        if not policy or not policy['rescan_enabled']:
            conn.close()
            return

        threshold = policy['auto_ticket_threshold'] or 7.0
        auto_ticket = policy['auto_ticket_enabled']

        assets = conn.execute('SELECT * FROM assets WHERE org_id = 1').fetchall()
        for asset in assets:
            cpe_name = asset['cpeName']
            started_at = datetime.now().isoformat()
            try:
                old_cve_data = json.loads(asset['cveData']) if asset['cveData'] else {}
                old_cve_ids = {v.get('cve', {}).get('id', '') for v in old_cve_data.get('vulnerabilities', [])}

                new_vulns = fetch_cves_for_cpe(cpe_name)
                kev_list = get_kev_list()
                cve_ids = [v.get('cve', {}).get('id', '') for v in new_vulns if v.get('cve', {}).get('id')]
                epss_scores = fetch_epss_scores(cve_ids)

                new_findings = []
                for vuln in new_vulns:
                    cve_id = vuln.get('cve', {}).get('id', '')
                    score = priority_score(vuln, kev_list, epss_scores)
                    vuln['priorityScore'] = score
                    vuln['hasKev'] = cve_id in kev_list
                    vuln['epssScore'] = epss_scores.get(cve_id, 0)

                    if cve_id and cve_id not in old_cve_ids:
                        normalized = min((score / 1744) * 10, 10)
                        if normalized >= threshold:
                            new_findings.append(vuln)

                conn.execute(
                    'UPDATE assets SET cveData = ?, last_scanned = ? WHERE cpeName = ? AND org_id = 1',
                    (json.dumps({'vulnerabilities': new_vulns, 'count': len(new_vulns), 'title': old_cve_data.get('title', cpe_name)}),
                     datetime.now().isoformat(), cpe_name))

                tickets_created = 0
                if auto_ticket and new_findings:
                    admin = conn.execute("SELECT id FROM users WHERE role = 'admin' AND org_id = 1 LIMIT 1").fetchone()
                    if admin:
                        for vuln in new_findings:
                            cve_id = vuln['cve']['id']
                            existing = conn.execute(
                                'SELECT id FROM tickets WHERE cve_id = ? AND cpe_name = ? AND isResolved = 0',
                                (cve_id, cpe_name)).fetchone()
                            if existing:
                                continue
                            norm_score = min((vuln['priorityScore'] / 1744) * 10, 10)
                            desc = f"[Auto-generated] {cve_id} detected on {cpe_name} with priority score {norm_score:.1f}/10"
                            sla_tier = 'Critical' if norm_score >= threshold else 'Standard'
                            created_ts = datetime.now().isoformat()
                            sla_deadline = calculate_sla_deadline(created_ts, sla_tier, policy)
                            conn.execute(
                                'INSERT INTO tickets (user_id, description, feature, created, isResolved, cve_id, cpe_name, sla_tier, sla_deadline) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)',
                                (admin['id'], desc, 'Auto-Generated', created_ts, cve_id, cpe_name, sla_tier, sla_deadline))
                            tid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                            conn.execute(
                                'INSERT INTO statusTickets (ticket_id, user_id, status, updated) VALUES (?, ?, ?, ?)',
                                (tid, admin['id'], 'Open', datetime.now().isoformat()))
                            conn.execute(
                                'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
                                (tid, admin['id'], 'Auto-created from scheduled scan', datetime.now().isoformat()))
                            tickets_created += 1

                conn.execute(
                    '''INSERT INTO scan_history (org_id, cpe_name, scan_type, new_cve_count, total_cve_count,
                       tickets_created, started_at, completed_at, status)
                       VALUES (1, ?, 'scheduled', ?, ?, ?, ?, ?, 'completed')''',
                    (cpe_name, len(new_findings), len(new_vulns), tickets_created,
                     started_at, datetime.now().isoformat()))

            except Exception as e:
                conn.execute(
                    '''INSERT INTO scan_history (org_id, cpe_name, scan_type, started_at, completed_at, status, error_message)
                       VALUES (1, ?, 'scheduled', ?, ?, 'failed', ?)''',
                    (cpe_name, started_at, datetime.now().isoformat(), str(e)))

        conn.commit()
        conn.close()

def start_scheduler():
    """Initialize and start the background scheduler."""
    conn = get_db()
    policy = conn.execute('SELECT rescan_interval_hours FROM org_policies WHERE org_id = 1').fetchone()
    conn.close()
    interval = policy['rescan_interval_hours'] if policy and policy['rescan_interval_hours'] else 168

    if scheduler.get_job('rescan'):
        scheduler.remove_job('rescan')
    scheduler.add_job(scheduled_rescan, 'interval', hours=interval, id='rescan', replace_existing=True)
    if not scheduler.running:
        scheduler.start()

#=====================
# AUDIT LOGGING
#=====================

def log_audit(action, resource_type=None, resource_id=None, details=None, user_id=None, username=None):
    """Insert a row into audit_log. Safe to call from any route."""
    try:
        uid = user_id or session.get('user_id')
        uname = username or session.get('username')
        ip = request.remote_addr if request else None
        conn = get_db()
        conn.execute(
            '''INSERT INTO audit_log (org_id, user_id, username, action, resource_type, resource_id, details, ip_address)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (1, uid, uname, action, resource_type, resource_id,
             json.dumps(details) if details else None, ip))
        conn.commit()
        conn.close()
    except Exception:
        pass  # audit logging must never break the request

#=====================
# NOTIFICATIONS
#=====================

# Notification types
NOTIFICATION_TYPES = (
    'ticket_assigned', 'ticket_accepted', 'ticket_resolved',
    'ticket_reopened', 'ticket_commented', 'ticket_mentioned',
    'ticket_reassigned', 'ticket_confirmed', 'ticket_status_changed',
    'risk_decision', 'policy_updated', 'threshold_changed',
    'rescan_completed',
)

def create_notification(user_id, notif_type, title, message='', link='',
                        resource_type=None, resource_id=None, conn=None):
    """Create a notification for a user, respecting their preferences."""
    own_conn = conn is None
    try:
        if own_conn:
            conn = get_db()
        pref = conn.execute(
            'SELECT enabled FROM notification_preferences WHERE user_id = ? AND type = ?',
            (user_id, notif_type)
        ).fetchone()
        if pref and not pref['enabled']:
            return
        conn.execute(
            '''INSERT INTO notifications
               (org_id, user_id, type, title, message, link, resource_type, resource_id)
               VALUES (1, ?, ?, ?, ?, ?, ?, ?)''',
            (user_id, notif_type, title, message or '', link or '',
             resource_type, resource_id)
        )
        if own_conn:
            conn.commit()
    except Exception:
        pass  # notification creation must never break the request
    finally:
        if own_conn and conn:
            conn.close()


def notify_ticket_participants(ticket_id, exclude_user_id, notif_type, title,
                               message='', link='', conn=None):
    """Notify ticket creator + acceptor + collaborators, excluding the acting user."""
    own_conn = conn is None
    try:
        if own_conn:
            conn = get_db()
        recipients = set()
        ticket = conn.execute('SELECT user_id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
        if ticket:
            recipients.add(ticket['user_id'])
        accepted = conn.execute(
            'SELECT user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1',
            (ticket_id,)).fetchone()
        if accepted:
            recipients.add(accepted['user_id'])
        collabs = conn.execute(
            'SELECT user_id FROM ticketCollaborators WHERE ticket_id = ?', (ticket_id,)
        ).fetchall()
        for c in collabs:
            recipients.add(c['user_id'])
        recipients.discard(exclude_user_id)
        for uid in recipients:
            create_notification(uid, notif_type, title, message,
                                link=link, resource_type='ticket',
                                resource_id=str(ticket_id), conn=conn)
        if own_conn:
            conn.commit()
    except Exception:
        pass
    finally:
        if own_conn and conn:
            conn.close()

#=====================
# HELPERS
#=====================

def generate_otp(length=12):
    alphabet = string.ascii_uppercase + string.digits
    raw = ''.join(secrets.choice(alphabet) for _ in range(length))
    return '-'.join(raw[i:i+4] for i in range(0, length, 4))

#---PARSE MENTIONS (myTickets)
def parse_mentions(text):
    """Extract @username mentions from comment text."""
    return re.findall(r'@(\w+)', text)

#---PARSE DATE HELPER---
def parse_date(date_str):
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except Exception:
        return datetime(2000, 1, 1)

#---SLA DEADLINE HELPER---
def calculate_sla_deadline(created_str, tier, policy):
    """Return ISO deadline string, or None if SLA disabled or date unparseable."""
    if not policy or not policy['sla_enabled']:
        return None
    days = policy['sla_critical_days'] if tier == 'Critical' else policy['sla_standard_days']
    if not days:
        return None
    created_dt = parse_date(created_str)
    if created_dt.year == 2000:
        # Fallback: try locale string format from browser's new Date().toLocaleString()
        for fmt in ('%m/%d/%Y, %I:%M:%S %p', '%m/%d/%Y %I:%M:%S %p'):
            try:
                created_dt = datetime.strptime(created_str, fmt)
                break
            except ValueError:
                continue
        else:
            created_dt = datetime.now()
    return (created_dt + timedelta(days=days)).isoformat()

#=====================
# SECURITY MIDDLEWARE
#=====================

CSRF_EXEMPT = {'/auth/verify-otp'}

@app.before_request
def csrf_protect():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.modified = True
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        if request.path in CSRF_EXEMPT:
            return
        token_header = request.headers.get('X-CSRF-Token', '')
        token_session = session.get('csrf_token', '')
        if not token_session or not hmac.compare_digest(token_header, token_session):
            return jsonify({'error': 'CSRF validation failed'}), 403

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if response.content_type and 'text/html' in response.content_type:
        csp = "; ".join([
            "default-src 'self'",
            "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com 'unsafe-inline'",
            "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'",
            "font-src 'self' https://cdnjs.cloudflare.com data:",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'"
        ])
        response.headers['Content-Security-Policy'] = csp
    if 'csrf_token' in session:
        response.set_cookie(
            'csrf_token', session['csrf_token'],
            httponly=False, samesite='Lax',
            secure=os.getenv('FLASK_ENV', '').strip("'\"") != 'development',
            path='/'
        )
    return response

#=====================
# AUTHENTICATION
#=====================

#---AUTHENTICATION HELPERS---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        if session.get('mfa_setup_required') and request.path not in (
            '/auth/totp-setup', '/auth/totp-verify-setup', '/auth/me'
        ):
            return jsonify({'error': 'MFA setup required', 'mfa_setup_required': True}), 403
        return f(*args, **kwargs)
    return decorated

def get_current_user_id():
    return session.get('user_id')

def validate_password(password):
    if len(password) < 8:
        return 'Password must be at least 8 characters.'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter.'
    if not re.search(r'[a-z]', password):
        return 'Password must contain at least one lowercase letter.'
    if not re.search(r'\d', password):
        return 'Password must contain at least one digit.'
    if not re.search(r'[^A-Za-z0-9]', password):
        return 'Password must contain at least one special character.'
    return None

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
        log_audit('OTP_FAILED', 'user', None, {'username': username}, user_id=user['id'], username=username)
        return jsonify({'error': 'Invalid username or one-time password.'}), 401
    if user['otp_expires_at']:
        expiry = datetime.fromisoformat(user['otp_expires_at'])
        if datetime.now() > expiry:
            log_audit('OTP_EXPIRED', 'user', None, {'username': username}, user_id=user['id'], username=username)
            return jsonify({'error': 'One-time password has expired. Contact your administrator.'}), 401
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    log_audit('OTP_VERIFIED', 'user', str(user['id']), {'username': username})
    return jsonify({'success': True, 'must_change_password': bool(user['must_change_password'])})

@app.route('/auth/set-password', methods=['POST'])
@login_required
def set_password():
    data = request.json or {}
    password = data.get('password', '')
    error = validate_password(password)
    if error:
        return jsonify({'error': error}), 400
    uid = get_current_user_id()
    pw_hash = generate_password_hash(password)
    conn = get_db()
    conn.execute(
        'UPDATE users SET password_hash = ?, otp_hash = NULL, otp_expires_at = NULL, must_change_password = 0 WHERE id = ?',
        (pw_hash, uid)
    )
    conn.commit()
    conn.close()
    log_audit('PASSWORD_SET', 'user', str(uid))
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
    if not user or not user['password_hash']:
        conn.close()
        log_audit('LOGIN_FAILED', 'user', None, {'username': username})
        return jsonify({'error': 'Invalid username or password.'}), 401

    # Account lockout check
    if user['locked_until']:
        locked = datetime.fromisoformat(user['locked_until'])
        if datetime.now() < locked:
            conn.close()
            log_audit('LOGIN_LOCKED', 'user', str(user['id']), {'username': username})
            return jsonify({'error': 'Account is temporarily locked. Try again later.'}), 429
        # Lockout expired, reset
        conn.execute('UPDATE users SET locked_until = NULL, failed_login_count = 0 WHERE id = ?', (user['id'],))
        conn.commit()

    if not check_password_hash(user['password_hash'], password):
        # Increment failed login count
        fails = (user['failed_login_count'] or 0) + 1
        if fails >= 5:
            lock_until = (datetime.now() + timedelta(minutes=15)).isoformat()
            conn.execute('UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?',
                         (fails, lock_until, user['id']))
        else:
            conn.execute('UPDATE users SET failed_login_count = ? WHERE id = ?', (fails, user['id']))
        conn.commit()
        conn.close()
        log_audit('LOGIN_FAILED', 'user', None, {'username': username, 'attempt': fails})
        return jsonify({'error': 'Invalid username or password.'}), 401

    if user['must_change_password']:
        conn.close()
        return jsonify({'error': 'Please use the New User login to set your password.'}), 403

    # Reset failed login count on successful password
    conn.execute('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?', (user['id'],))
    conn.commit()

    # Check if TOTP is enabled
    if user['totp_enabled']:
        # Generate a temporary MFA session token
        mfa_token = secrets.token_urlsafe(32)
        session['mfa_pending'] = True
        session['mfa_user_id'] = user['id']
        session['mfa_token'] = mfa_token
        conn.close()
        return jsonify({'requires_mfa': True, 'mfa_session_token': mfa_token})

    # Check if org policy requires MFA for this user's role
    policy = conn.execute('SELECT mfa_required_role FROM org_policies WHERE org_id = 1').fetchone()
    if policy and policy['mfa_required_role'] is not None:
        user_role_level = ROLE_LEVELS.get(user['role'], 0)
        if user_role_level >= policy['mfa_required_role']:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['mfa_setup_required'] = True
            session.permanent = True
            conn.close()
            log_audit('LOGIN_SUCCESS', 'user', str(user['id']),
                      {'username': username, 'mfa_setup_required': True})
            return jsonify({
                'success': True, 'mfa_setup_required': True,
                'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}
            })

    conn.close()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session.permanent = True
    log_audit('LOGIN_SUCCESS', 'user', str(user['id']), {'username': username})
    return jsonify({'success': True, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

@app.route('/auth/logout', methods=['POST'])
def logout():
    log_audit('LOGOUT', 'user', str(session.get('user_id')))
    session.clear()
    return jsonify({'success': True})

@app.route('/auth/me', methods=['GET'])
def auth_me():
    uid = get_current_user_id()
    if not uid:
        return jsonify({'authenticated': False}), 401
    conn = get_db()
    user = conn.execute('SELECT id, username, role, totp_enabled FROM users WHERE id = ?', (uid,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'authenticated': False}), 401
    user_dict = dict(user)
    user_dict['totp_enabled'] = bool(user_dict.get('totp_enabled'))
    return jsonify({'authenticated': True, 'user': user_dict})

@app.route('/auth/my-permissions', methods=['GET'])
@login_required
def get_my_permissions():
    role = session.get('role', 'viewer')
    conn = get_db()
    row = conn.execute('SELECT permissions_json FROM org_policies LIMIT 1').fetchone()
    conn.close()
    if row and row['permissions_json']:
        all_perms = json.loads(row['permissions_json'])
    else:
        return jsonify({'permissions': {}})
    # Extract only this role's permissions
    my_perms = {}
    for category, actions in all_perms.items():
        my_perms[category] = {}
        for action, roles in actions.items():
            my_perms[category][action] = roles.get(role, 0)
    return jsonify({'permissions': my_perms})

#=====================
# TOTP / MFA
#=====================

@app.route('/auth/totp-setup', methods=['POST'])
@login_required
def totp_setup():
    uid = get_current_user_id()
    conn = get_db()
    user = conn.execute('SELECT username, totp_enabled FROM users WHERE id = ?', (uid,)).fetchone()
    if user['totp_enabled']:
        conn.close()
        return jsonify({'error': 'TOTP is already enabled.'}), 400

    secret = pyotp.random_base32()
    conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, uid))

    # Generate 8 backup codes
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    hashed_codes = json.dumps([hashlib.sha256(c.encode()).hexdigest() for c in backup_codes])
    conn.execute('UPDATE users SET backup_codes = ? WHERE id = ?', (hashed_codes, uid))
    conn.commit()
    conn.close()

    # Build otpauth URI
    org_name = 'VulnScore'
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user['username'], issuer_name=org_name)

    # Generate QR code as base64
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    log_audit('TOTP_SETUP_STARTED', 'user', str(uid))
    return jsonify({
        'secret': secret,
        'uri': uri,
        'qr_code': f'data:image/png;base64,{qr_b64}',
        'backup_codes': backup_codes
    })

@app.route('/auth/totp-verify-setup', methods=['POST'])
@login_required
def totp_verify_setup():
    uid = get_current_user_id()
    data = request.json or {}
    code = data.get('code', '').strip()
    if not code:
        return jsonify({'error': 'Verification code is required.'}), 400

    conn = get_db()
    user = conn.execute('SELECT totp_secret FROM users WHERE id = ?', (uid,)).fetchone()
    if not user or not user['totp_secret']:
        conn.close()
        return jsonify({'error': 'TOTP setup not initiated.'}), 400

    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(code, valid_window=1):
        conn.close()
        return jsonify({'error': 'Invalid verification code.'}), 401

    conn.execute('UPDATE users SET totp_enabled = 1 WHERE id = ?', (uid,))
    conn.commit()
    conn.close()
    session.pop('mfa_setup_required', None)
    log_audit('TOTP_ENABLED', 'user', str(uid))
    return jsonify({'success': True})

@app.route('/auth/totp-verify', methods=['POST'])
def totp_verify():
    data = request.json or {}
    code = data.get('code', '').strip()
    mfa_token = data.get('mfa_session_token', '')

    if not session.get('mfa_pending') or session.get('mfa_token') != mfa_token:
        return jsonify({'error': 'Invalid MFA session.'}), 401

    user_id = session.get('mfa_user_id')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found.'}), 401

    # Try TOTP code first
    totp = pyotp.TOTP(user['totp_secret'])
    if totp.verify(code, valid_window=1):
        # Clear MFA pending state, set full session
        session.pop('mfa_pending', None)
        session.pop('mfa_user_id', None)
        session.pop('mfa_token', None)
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session.permanent = True
        conn.close()
        log_audit('LOGIN_SUCCESS', 'user', str(user['id']), {'username': user['username'], 'mfa': True})
        return jsonify({'success': True, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

    # Try backup code
    if user['backup_codes']:
        stored_codes = json.loads(user['backup_codes'])
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        if code_hash in stored_codes:
            stored_codes.remove(code_hash)
            conn.execute('UPDATE users SET backup_codes = ? WHERE id = ?',
                         (json.dumps(stored_codes), user['id']))
            conn.commit()
            session.pop('mfa_pending', None)
            session.pop('mfa_user_id', None)
            session.pop('mfa_token', None)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            conn.close()
            log_audit('LOGIN_SUCCESS', 'user', str(user['id']),
                      {'username': user['username'], 'mfa': True, 'backup_code': True})
            return jsonify({'success': True, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

    # Failed
    fails = (user['failed_login_count'] or 0) + 1
    if fails >= 5:
        lock_until = (datetime.now() + timedelta(minutes=15)).isoformat()
        conn.execute('UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?',
                     (fails, lock_until, user['id']))
        conn.commit()
        session.clear()
        conn.close()
        log_audit('TOTP_LOCKED', 'user', str(user['id']), {'username': user['username']})
        return jsonify({'error': 'Too many failed attempts. Account locked for 15 minutes.'}), 429
    else:
        conn.execute('UPDATE users SET failed_login_count = ? WHERE id = ?', (fails, user['id']))
        conn.commit()
        conn.close()
        log_audit('TOTP_FAILED', 'user', str(user['id']), {'username': user['username'], 'attempt': fails})
        return jsonify({'error': 'Invalid verification code.'}), 401

@app.route('/auth/totp-disable', methods=['POST'])
@login_required
def totp_disable():
    uid = get_current_user_id()
    data = request.json or {}
    code = data.get('code', '').strip()

    conn = get_db()
    user = conn.execute('SELECT totp_secret, totp_enabled, role FROM users WHERE id = ?', (uid,)).fetchone()
    if not user or not user['totp_enabled']:
        conn.close()
        return jsonify({'error': 'TOTP is not enabled.'}), 400

    # Check if org policy requires MFA for this user's role
    policy = conn.execute('SELECT mfa_required_role FROM org_policies WHERE org_id = 1').fetchone()
    if policy and policy['mfa_required_role'] is not None:
        user_role_level = ROLE_LEVELS.get(user['role'], 0)
        if user_role_level >= policy['mfa_required_role']:
            conn.close()
            return jsonify({'error': 'MFA is required for your role and cannot be disabled.'}), 403

    # Verify current code before disabling
    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(code, valid_window=1):
        conn.close()
        return jsonify({'error': 'Invalid TOTP code.'}), 401

    conn.execute('UPDATE users SET totp_secret = NULL, totp_enabled = 0, backup_codes = NULL WHERE id = ?', (uid,))
    conn.commit()
    conn.close()
    log_audit('TOTP_DISABLED', 'user', str(uid))
    return jsonify({'success': True})

#=====================
# FRONTEND ENDPOINTS
#=====================

#---FLASK SERVES HTML---
@app.route('/')
def home():
    return render_template('index.html')

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
        response = requests.get(nvd_api_url, params=params, headers=headers, timeout=30)
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
        f'SELECT cpeName, cpeData FROM cpe_cache WHERE cpeName IN ({placeholders})',  # noqa: S608
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

    try:
        org_row = conn.execute('SELECT org_id FROM users WHERE id = ?', (uid,)).fetchone()
        if not org_row:
            return jsonify({'error': 'User not found'}), 403
        org_id = org_row['org_id']

        # Upsert each asset (preserves existing IDs)
        for a in assets:
            conn.execute('''
                INSERT INTO assets (cpeName, org_id, user_id, title, cpeData, cveData, criticality, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cpeName, org_id)
                DO UPDATE SET
                    title   = excluded.title,
                    cpeData = excluded.cpeData,
                    cveData = excluded.cveData,
                    user_id = excluded.user_id,
                    criticality = COALESCE(excluded.criticality, assets.criticality),
                    tags = COALESCE(excluded.tags, assets.tags)
                WHERE assets.org_id = excluded.org_id
            ''', (a['cpeName'], org_id, uid, a.get('title', ''),
                  json.dumps(a.get('cpeData', {})), json.dumps(a.get('cveData', {})),
                  a.get('criticality', 3), json.dumps(a.get('tags', []))))

        conn.commit()
        log_audit('ASSETS_SAVED', 'asset', None, {'count': len(assets)})
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

#---UPDATE ASSET PROPERTIES---
@app.route('/db/update-asset-properties', methods=['POST'])
@login_required
def update_asset_properties():
    uid = get_current_user_id()
    data = request.json or {}
    cpe_name = data.get('cpeName')
    if not cpe_name:
        return jsonify({'error': 'cpeName is required'}), 400

    conn = get_db()
    org_row = conn.execute('SELECT org_id FROM users WHERE id = ?', (uid,)).fetchone()
    if not org_row:
        conn.close()
        return jsonify({'error': 'User not found'}), 403
    org_id = org_row['org_id']

    asset = conn.execute('SELECT cpeName FROM assets WHERE cpeName = ? AND org_id = ?',
                         (cpe_name, org_id)).fetchone()
    if not asset:
        conn.close()
        return jsonify({'error': 'Asset not found'}), 404

    updates = []
    params = []
    if 'criticality' in data:
        crit = int(data['criticality'])
        if crit < 1 or crit > 5:
            conn.close()
            return jsonify({'error': 'Criticality must be 1-5'}), 400
        updates.append('criticality = ?')
        params.append(crit)
    if 'tags' in data:
        updates.append('tags = ?')
        params.append(json.dumps(data['tags']))

    if not updates:
        conn.close()
        return jsonify({'error': 'No properties to update'}), 400

    params.extend([cpe_name, org_id])
    conn.execute(f'UPDATE assets SET {", ".join(updates)} WHERE cpeName = ? AND org_id = ?', params)  # noqa: S608
    conn.commit()
    conn.close()
    log_audit('ASSET_PROPERTIES_UPDATED', 'asset', cpe_name,
              {'criticality': data.get('criticality'), 'tags': data.get('tags')})
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
    org_row = conn.execute('SELECT org_id FROM users WHERE id = ?', (uid,)).fetchone()
    if not org_row:
        conn.close()
        return jsonify({'error': 'User not found'}), 403
    org_id = org_row['org_id']

    asset = conn.execute('SELECT cpeName FROM assets WHERE cpeName = ? AND org_id = ?', (cpe_name, org_id)).fetchone()
    if not asset:
        conn.close()
        return jsonify({'error': 'Asset not found'}), 404

    archived_ts = None
    if is_archived:
        archived_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')

    existing = conn.execute('SELECT id FROM archivedAssets WHERE cpeName = ? AND org_id = ? AND user_id = ?', (cpe_name, org_id, uid)).fetchone()
    if existing:
        conn.execute(
            'UPDATE archivedAssets SET archived = ?, isArchived = ? WHERE cpeName = ? AND org_id = ? AND user_id = ?',
            (archived_ts, int(is_archived), cpe_name, org_id, uid)
        )
    else:
        conn.execute(
            'INSERT INTO archivedAssets (cpeName, org_id, user_id, archived, isArchived) VALUES (?, ?, ?, ?, ?)',
            (cpe_name, org_id, uid, archived_ts, int(is_archived))
        )

    conn.commit()
    conn.close()
    action = 'ASSET_ARCHIVED' if is_archived else 'ASSET_RESTORED'
    log_audit(action, 'asset', cpe_name, {'cpeName': cpe_name})
    return jsonify({'success': True, 'cpeName': cpe_name, 'isArchived': is_archived, 'archived': archived_ts})

#---DELETE ASSETS---
@app.route('/db/deleted-assets', methods=['POST'])
@require_role('admin')
def delete_asset():
    uid = get_current_user_id()
    data = request.json or {}
    cpe_name = data.get('cpeName')

    if not cpe_name:
        return jsonify({'error': 'cpeName is required'}), 400

    conn = get_db()

    # Role check: only admin can delete assets
    user = conn.execute('SELECT role FROM users WHERE id = ?', (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 403

    perms = conn.execute('SELECT permissions_json FROM org_policies LIMIT 1').fetchone()
    if perms and perms['permissions_json']:
        policy = json.loads(perms['permissions_json'])
        allowed = policy.get('Asset Directory', {}).get('delete assets', {}).get(user['role'], 0)
    else:
        # Fall back to defaults if no saved permissions
        allowed = 0

    if not allowed:
        conn.close()
        return jsonify({'error': 'Your role does not have permission to delete assets'}), 403

    org_row = conn.execute('SELECT org_id FROM users WHERE id = ?', (uid,)).fetchone()
    if not org_row:
        conn.close()
        return jsonify({'error': 'User not found'}), 403
    org_id = org_row['org_id']

    asset = conn.execute('SELECT cpeName FROM assets WHERE cpeName = ? AND org_id = ?', (cpe_name, org_id)).fetchone()
    if not asset:
        conn.close()
        return jsonify({'error': 'Asset not found'}), 404

    conn.execute('DELETE FROM archivedAssets WHERE cpeName = ? AND org_id = ?', (cpe_name, org_id))
    conn.execute('DELETE FROM assets WHERE cpeName = ? AND org_id = ?', (cpe_name, org_id))

    conn.commit()
    conn.close()
    log_audit('ASSET_DELETED', 'asset', cpe_name, {'cpeName': cpe_name})
    return jsonify({'success': True, 'cpeName': cpe_name})

#---LOAD ASSETS---
@app.route('/db/load-assets', methods=['GET'])
@login_required
def load_assets():
    uid = get_current_user_id()
    conn = get_db()
    org_row = conn.execute('SELECT org_id FROM users WHERE id = ?', (uid,)).fetchone()
    if not org_row:
        conn.close()
        return jsonify({'error': 'User not found'}), 403
    org_id = org_row['org_id']
    rows = conn.execute('SELECT * FROM assets WHERE org_id = ?', (org_id,)).fetchall()
    conn.close()
    return jsonify([{
        'cpeName': r['cpeName'],
        'title': r['title'],
        'cpeData': json.loads(r['cpeData']),
        'cveData': json.loads(r['cveData']),
        'user_id': r['user_id'],
        'criticality': r['criticality'] if r['criticality'] is not None else 3,
        'tags': json.loads(r['tags']) if r['tags'] else []
    } for r in rows])

#---LOAD ARCHIVED ASSETS---
@app.route('/db/load-archived-assets', methods=['GET'])
@login_required
def load_archived_assets():
    uid = get_current_user_id()
    conn = get_db()
    org_row = conn.execute('SELECT org_id FROM users WHERE id = ?', (uid,)).fetchone()
    if not org_row:
        conn.close()
        return jsonify({'error': 'User not found'}), 403
    org_id = org_row['org_id']
    rows = conn.execute('''
        SELECT assets.cpeName
        FROM archivedAssets
        JOIN assets ON archivedAssets.cpeName = assets.cpeName
        WHERE archivedAssets.isArchived = 1 AND assets.org_id = ?
    ''', (org_id,)).fetchall()
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
    policy = conn.execute('SELECT * FROM org_policies LIMIT 1').fetchone()

    incoming_ids = set()
    for t in tickets:
        tid = t.get('id')
        is_resolved = int(t.get('isResolved') or 0)
        if tid:
            incoming_ids.add(tid)
            sla_deadline = calculate_sla_deadline(t['created'], 'Standard', policy)
            conn.execute('''
                INSERT INTO tickets (id, user_id, description, feature, created, isResolved, cve_id, cpe_name, sla_tier, sla_deadline)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id)
                DO UPDATE SET description=excluded.description, feature=excluded.feature,
                              isResolved=excluded.isResolved, cve_id=excluded.cve_id, cpe_name=excluded.cpe_name,
                              sla_tier=COALESCE(tickets.sla_tier, excluded.sla_tier),
                              sla_deadline=COALESCE(tickets.sla_deadline, excluded.sla_deadline)
            ''', (tid, uid, t['description'], t['feature'], t['created'], is_resolved,
                  t.get('cve_id'), t.get('cpe_name'), 'Standard', sla_deadline))
        else:
            sla_deadline = calculate_sla_deadline(t['created'], 'Standard', policy)
            cursor = conn.execute(
                'INSERT INTO tickets (user_id, description, feature, created, isResolved, cve_id, cpe_name, sla_tier, sla_deadline) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (uid, t['description'], t['feature'], t['created'], is_resolved,
                 t.get('cve_id'), t.get('cpe_name'), 'Standard', sla_deadline)
            )
            incoming_ids.add(cursor.lastrowid)

    id_list = tuple(incoming_ids) or (0,)
    placeholders = ','.join('?' * len(id_list))
    conn.execute(f'DELETE FROM tickets WHERE user_id = ? AND id NOT IN ({placeholders})',  # noqa: S608
                 (uid, *id_list))

    conn.commit()
    conn.close()
    return jsonify({'success': True})

#---TICKET STATUS---
@app.route('/db/ticket-status', methods=['POST'])
@login_required
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
    notify_ticket_participants(
        ticket_id, uid, 'ticket_status_changed',
        f'Ticket #{ticket_id} status: {status}',
        f'Ticket status changed to {status}',
        link=f'#ticket-{ticket_id}')
    conn.close()
    log_audit('TICKET_STATUS_CHANGED', 'ticket', str(ticket_id), {'status': status})
    return jsonify({'success': True, 'ticket_id': ticket_id, 'status': status, 'updated': updated_ts})

#---DELETE TICKET---
@app.route('/db/ticket-delete', methods=['POST'])
@require_role('admin')
def ticket_delete():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400

    conn = get_db()
    ticket = conn.execute('SELECT id, user_id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    # Role check
    user = conn.execute('SELECT role FROM users WHERE id = ?', (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 403

    perms = conn.execute('SELECT permissions_json FROM org_policies LIMIT 1').fetchone()
    if perms and perms['permissions_json']:
        policy = json.loads(perms['permissions_json'])
        allowed = policy.get('myTickets', {}).get('delete tickets', {}).get(user['role'], 0)
    else:
        # Fall back to defaults if no saved permissions
        allowed = 0

    if not allowed:
        conn.close()
        return jsonify({'error': 'Your role does not have permission to delete tickets'}), 403

    deleted_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
    username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

    # Log the deletion as activity before removing
    conn.execute(
        'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
        (ticket_id, uid, 'Deleted', deleted_ts)
    )

    # Delete related records
    conn.execute('DELETE FROM ticketCollaborators WHERE ticket_id = ?', (ticket_id,))
    conn.execute('DELETE FROM commentTickets WHERE ticket_id = ?', (ticket_id,))
    conn.execute('DELETE FROM acceptedTickets WHERE ticket_id = ?', (ticket_id,))
    conn.execute('DELETE FROM resolvedTickets WHERE ticket_id = ?', (ticket_id,))
    conn.execute('DELETE FROM archivedTickets WHERE ticket_id = ?', (ticket_id,))
    conn.execute('DELETE FROM statusTickets WHERE ticket_id = ?', (ticket_id,))
    conn.execute('DELETE FROM tickets WHERE id = ?', (ticket_id,))

    conn.commit()
    conn.close()
    log_audit('TICKET_DELETED', 'ticket', str(ticket_id), {'deleted_by': username})
    return jsonify({'success': True, 'ticket_id': ticket_id, 'deleted_by': username, 'deleted': deleted_ts})

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
    ticket = conn.execute('SELECT id, user_id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    if ticket['user_id'] == uid:
        conn.close()
        return jsonify({'error': 'Ticket owners cannot accept their own tickets'}), 403

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
    ticket_owner = conn.execute('SELECT user_id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if ticket_owner:
        create_notification(
            ticket_owner['user_id'], 'ticket_accepted',
            f'Ticket #{ticket_id} accepted',
            f'{username} accepted your ticket',
            link=f'#ticket-{ticket_id}',
            resource_type='ticket', resource_id=str(ticket_id))
    conn.close()
    log_audit('TICKET_ACCEPTED', 'ticket', str(ticket_id), {'accepted_by': username})
    return jsonify({'success': True, 'ticket_id': ticket_id, 'accepted': accepted_ts, 'accepted_by': username})

#---RESOLVE TICKET---
@app.route('/db/ticket-resolution', methods=['POST'])
@login_required
def ticket_resolution():
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
    if is_resolved:
        notify_ticket_participants(
            ticket_id, get_current_user_id(), 'ticket_resolved',
            f'Ticket #{ticket_id} resolved',
            'A ticket you are involved with has been resolved',
            link=f'#ticket-{ticket_id}')
    else:
        notify_ticket_participants(
            ticket_id, get_current_user_id(), 'ticket_reopened',
            f'Ticket #{ticket_id} reopened',
            'A ticket you are involved with has been reopened',
            link=f'#ticket-{ticket_id}')
    conn.close()
    audit_action = 'TICKET_RESOLVED' if is_resolved else 'TICKET_REOPENED'
    log_audit(audit_action, 'ticket', str(ticket_id))
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

    # Check role permission for reassigning tickets
    user = conn.execute('SELECT role FROM users WHERE id = ?', (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 403

    perms = conn.execute('SELECT permissions_json FROM org_policies LIMIT 1').fetchone()
    if perms and perms['permissions_json']:
        policy = json.loads(perms['permissions_json'])
        allowed = policy.get('myTickets', {}).get('reassign tickets', {}).get(user['role'], 0)
    else:
        allowed = 0

    if not allowed:
        conn.close()
        return jsonify({'error': 'Your role does not have permission to reassign tickets'}), 403

    accepted = conn.execute(
        'SELECT id, user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()
    if not accepted:
        conn.close()
        return jsonify({'error': 'Ticket has not been accepted yet'}), 400

    reassigned_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
    username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

    # Clear the acceptance
    conn.execute(
        'UPDATE acceptedTickets SET isAccepted = 0 WHERE ticket_id = ? AND user_id = ?',
        (ticket_id, accepted['user_id'])
    )

    # Clear any resolution tied to this ticket
    conn.execute(
        'UPDATE resolvedTickets SET isResolved = 0, resolved = NULL WHERE ticket_id = ?',
        (ticket_id,)
    )

    conn.execute(
        'UPDATE confirmedResolutions SET isConfirmed = 0, confirmed = NULL WHERE ticket_id = ?',
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
    create_notification(
        accepted['user_id'], 'ticket_reassigned',
        f'Ticket #{ticket_id} reassigned',
        f'{username} reassigned the ticket',
        link=f'#ticket-{ticket_id}',
        resource_type='ticket', resource_id=str(ticket_id))
    notify_ticket_participants(
        ticket_id, uid, 'ticket_reassigned',
        f'Ticket #{ticket_id} reassigned',
        f'{username} reassigned the ticket',
        link=f'#ticket-{ticket_id}')
    conn.close()
    log_audit('TICKET_REASSIGNED', 'ticket', str(ticket_id), {'reassigned_by': username})
    return jsonify({
        'success': True, 'ticket_id': ticket_id,
        'reassigned': reassigned_ts, 'reassigned_by': username
    })

#---CONFIRM RESOLUTION---
@app.route('/db/ticket-confirm-resolution', methods=['POST'])
@login_required
def ticket_confirm_resolution():
    data = request.json or {}
    ticket_id = data.get('ticket_id')
    is_resolved = data.get('isResolved', 0)

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400

    uid = get_current_user_id()
    conn = get_db()
    try:
        ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({'error': 'Ticket not found'}), 404

        # Ticket must be resolved before it can be confirmed
        resolved = conn.execute(
            'SELECT id FROM resolvedTickets WHERE ticket_id = ? AND isResolved = 1', (ticket_id,)
        ).fetchone()
        if not resolved:
            return jsonify({'error': 'Ticket must be resolved before confirming resolution'}), 400

        # SoD: confirmer must be a different user than the acceptor
        accepted = conn.execute(
            'SELECT user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
        ).fetchone()
        if accepted and accepted['user_id'] == uid:
            return jsonify({'error': 'The accepting user cannot confirm their own resolution'}), 403

        confirmed_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
        username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

        existing = conn.execute('SELECT id FROM confirmedResolutions WHERE ticket_id = ?', (ticket_id,)).fetchone()
        if existing:
            conn.execute(
                'UPDATE confirmedResolutions SET user_id = ?, confirmed = ?, isConfirmed = 1 WHERE ticket_id = ?',
                (uid, confirmed_ts, ticket_id)
            )
        else:
            conn.execute(
                'INSERT INTO confirmedResolutions (ticket_id, user_id, confirmed, isConfirmed) VALUES (?, ?, ?, 1)',
                (ticket_id, uid, confirmed_ts)
            )

        conn.execute(
            'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
            (ticket_id, uid, 'Resolution Confirmed', confirmed_ts)
        )

        conn.commit()
        notify_ticket_participants(
            ticket_id, get_current_user_id(), 'ticket_confirmed',
            f'Ticket #{ticket_id} resolution confirmed',
            f'{username} confirmed the resolution',
            link=f'#ticket-{ticket_id}')
        log_audit('TICKET_CONFIRMED', 'ticket', str(ticket_id), {'confirmed_by': username})
        return jsonify({'success': True, 'ticket_id': ticket_id, 'confirmed': confirmed_ts, 'confirmed_by': username})
    finally:
        conn.close()

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
    commenter_name = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

    accepted_id = accepted['id'] if accepted else None
    cursor = conn.execute(
        'INSERT INTO commentTickets (ticket_id, accepted_id, user_id, commented, comment_description) VALUES (?, ?, ?, ?, ?)',
        (ticket_id, accepted_id, uid, commented_ts, comment_desc)
    )
    comment_id = cursor.lastrowid

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
    notify_ticket_participants(
        ticket_id, uid, 'ticket_commented',
        f'New comment on Ticket #{ticket_id}',
        f'{commenter_name} commented on a ticket you are involved with',
        link=f'#ticket-{ticket_id}')
    # Notify mentioned users specifically
    for mentioned_name in mentions:
        mentioned_user = conn.execute(
            'SELECT id FROM users WHERE username = ?', (mentioned_name,)).fetchone()
        if mentioned_user and mentioned_user['id'] != uid:
            create_notification(
                mentioned_user['id'], 'ticket_mentioned',
                f'You were mentioned in Ticket #{ticket_id}',
                f'{commenter_name} mentioned you in a comment',
                link=f'#ticket-{ticket_id}',
                resource_type='ticket', resource_id=str(ticket_id))
    conn.close()
    log_audit('TICKET_COMMENTED', 'ticket', str(ticket_id), {'comment_id': comment_id})
    return jsonify({
        'success': True, 'ticket_id': ticket_id, 'comment_id': comment_id,
        'commented': commented_ts, 'comment_by': commenter_name,
        'comment_description': comment_desc,
        'new_collaborators': new_collaborators
    })

#---FIX COMMENT---
@app.route('/db/ticket-comment-fix', methods=['POST'])
@login_required
def ticket_comment_fix():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')
    comment_id = data.get('comment_id')

    if not ticket_id or not comment_id:
        return jsonify({'error': 'ticket_id and comment_id are required'}), 400

    conn = get_db()

    # Verify ticket exists and this user is the ticket acceptor OR a collaborator
    ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    accepted = conn.execute(
        'SELECT id, user_id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()
    is_acceptor = accepted is not None and accepted['user_id'] == uid
    is_collaborator = conn.execute(
        'SELECT id FROM ticketCollaborators WHERE ticket_id = ? AND user_id = ?', (ticket_id, uid)
    ).fetchone() is not None

    if not is_acceptor and not is_collaborator:
        conn.close()
        return jsonify({'error': 'Only the ticket acceptor or a collaborator can mark comments as fixed'}), 403

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
    log_audit('COMMENT_FIXED', 'ticket', str(ticket_id), {'comment_id': comment_id})
    return jsonify({
        'success': True, 'ticket_id': ticket_id, 'comment_id': comment_id,
        'fixed': fixed_ts, 'fixed_by': username
    })

#---REOPEN TICKET---
@app.route('/db/ticket-reopen', methods=['POST'])
@login_required
def ticket_reopen():
    uid = get_current_user_id()
    data = request.json or {}
    ticket_id = data.get('ticket_id')

    if not ticket_id:
        return jsonify({'error': 'ticket_id is required'}), 400

    conn = get_db()
    try:
        ticket = conn.execute('SELECT id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({'error': 'Ticket not found'}), 404

        # Role check
        user = conn.execute('SELECT role FROM users WHERE id = ?', (uid,)).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 403

        perms = conn.execute('SELECT permissions_json FROM org_policies LIMIT 1').fetchone()
        if perms and perms['permissions_json']:
            policy = json.loads(perms['permissions_json'])
            allowed = policy.get('myTickets', {}).get('reopen tickets', {}).get(user['role'], 0)
        else:
            allowed = 0

        if not allowed:
            return jsonify({'error': 'Your role does not have permission to reopen tickets'}), 403

        reopened_ts = datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')
        username = conn.execute('SELECT username FROM users WHERE id = ?', (uid,)).fetchone()['username']

        # Clear resolution
        conn.execute(
            'UPDATE resolvedTickets SET isResolved = 0, resolved = NULL WHERE ticket_id = ?',
            (ticket_id,)
        )

        conn.execute(
            'UPDATE confirmedResolutions SET isConfirmed = 0, confirmed = NULL WHERE ticket_id = ?',
            (ticket_id,)
        )

        # Log activity
        conn.execute(
            'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
            (ticket_id, uid, 'Reopened', reopened_ts)
        )

        # Reset status to In Progress
        conn.execute(
            'UPDATE statusTickets SET status = ? WHERE ticket_id = ?',
            ('In Progress', ticket_id)
        )

        conn.commit()
        log_audit('TICKET_REOPENED', 'ticket', str(ticket_id), {'reopened_by': username})
        return jsonify({
            'success': True, 'ticket_id': ticket_id,
            'reopened': reopened_ts, 'reopened_by': username
        })
    finally:
        conn.close()

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

    # Role-based permission check
    user = conn.execute('SELECT role FROM users WHERE id = ?', (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 403

    perm_key = 'archive tickets' if is_archived else 'restore tickets'
    perms = conn.execute('SELECT permissions_json FROM org_policies LIMIT 1').fetchone()
    if perms and perms['permissions_json']:
        policy = json.loads(perms['permissions_json'])
        allowed = policy.get('myTickets', {}).get(perm_key, {}).get(user['role'], 0)
    else:
        allowed = 0

    if not allowed:
        conn.close()
        return jsonify({'error': f'Your role does not have permission to {perm_key}'}), 403

    # Get accepted record for FK (required NOT NULL by schema)
    accepted = conn.execute(
        'SELECT id FROM acceptedTickets WHERE ticket_id = ? AND isAccepted = 1', (ticket_id,)
    ).fetchone()
    if not accepted:
        conn.close()
        return jsonify({'error': 'Ticket must be accepted before archiving'}), 400

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
    audit_action = 'TICKET_ARCHIVED' if is_archived else 'TICKET_RESTORED'
    log_audit(audit_action, 'ticket', str(ticket_id))
    return jsonify({'success': True, 'ticket_id': ticket_id, 'isArchived': is_archived, 'archived': archived_ts})

#---LOAD TICKETS---
@app.route('/db/load-tickets', methods=['GET'])
@login_required
def load_tickets():
    conn = get_db()
    rows = conn.execute('''
        SELECT tickets.*, users.username AS creator_username,
            resolvedTickets.resolved AS rt_resolved,
            resolvedTickets.isResolved AS rt_isResolved,
            acceptedTickets.accepted AS at_accepted,
            acceptedTickets.isAccepted AS at_isAccepted,
            acceptors.username AS accepted_by_username,
            archivedTickets.archived AS at_archived,
            archivedTickets.isArchived AS at_isArchived,
            confirmedResolutions.confirmed AS cr_confirmed,
            confirmedResolutions.isConfirmed AS cr_isConfirmed,
            confirmers.username AS cr_confirmed_by,
            statusTickets.status AS st_status
        FROM tickets
        JOIN users ON tickets.user_id = users.id
        LEFT JOIN resolvedTickets ON resolvedTickets.ticket_id = tickets.id
        LEFT JOIN acceptedTickets ON acceptedTickets.ticket_id = tickets.id AND acceptedTickets.isAccepted = 1
        LEFT JOIN users AS acceptors ON acceptedTickets.user_id = acceptors.id
        LEFT JOIN archivedTickets ON archivedTickets.ticket_id = tickets.id
        LEFT JOIN confirmedResolutions ON confirmedResolutions.ticket_id = tickets.id
        LEFT JOIN users AS confirmers ON confirmedResolutions.user_id = confirmers.id
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
            SELECT ticketCollaborators.ticket_id, users.username AS collaborator_username
            FROM ticketCollaborators
            JOIN users ON ticketCollaborators.user_id = users.id
        ''').fetchall()

        collab_map = {}
        for c in collab_rows:
            tid = c['ticket_id']
            if tid not in collab_map:
                collab_map[tid] = []
            collab_map[tid].append(c['collaborator_username'])

    conn.close()
    return jsonify([{
        'id': r['id'],
        'user_id': r['user_id'],
        'creator_username': r['creator_username'],
        'description': r['description'],
        'feature': r['feature'],
        'created': r['created'],
        'resolved': r['rt_resolved'] if r['rt_isResolved'] else None,
        'isResolved': bool(r['rt_isResolved']) if r['rt_isResolved'] is not None else bool(r['isResolved']),
        'accepted': r['at_accepted'] if r['at_isAccepted'] else None,
        'isAccepted': bool(r['at_isAccepted']) if r['at_isAccepted'] is not None else False,
        'accepted_by': r['accepted_by_username'] if r['at_isAccepted'] else None,
        'resolved_by': r['accepted_by_username'] if r['rt_isResolved'] else None,
        'isArchived': bool(r['at_isArchived']) if r['at_isArchived'] is not None else False,
        'archived': r['at_archived'] if r['at_isArchived'] else None,
        'comments': comments_map.get(r['id'], []),
        'activity': activity_map.get(r['id'], []),
        'status': r['st_status'] or 'Open',
        'collaborators': collab_map.get(r['id'], []),
        'isConfirmed': bool(r['cr_isConfirmed']),
        'confirmed': r['cr_confirmed'],
        'confirmed_by': r['cr_confirmed_by'] if r['cr_isConfirmed'] else None,
        'cve_id': r['cve_id'],
        'cpe_name': r['cpe_name'],
        'sla_tier': r['sla_tier'] or 'Standard',
        'sla_deadline': r['sla_deadline'],
    } for r in rows])

#---TICKETS BY CVE---
@app.route('/db/tickets-by-cve', methods=['GET'])
@login_required
def tickets_by_cve():
    cve_id = request.args.get('cve_id', '')
    cpe_name = request.args.get('cpe_name', '')
    conn = get_db()
    query = '''SELECT t.id, t.description, t.feature, t.created, t.isResolved, t.cve_id, t.cpe_name,
               COALESCE(st.status, 'Open') AS status
               FROM tickets t LEFT JOIN statusTickets st ON st.ticket_id = t.id WHERE 1=1'''
    params = []
    if cve_id:
        query += ' AND t.cve_id = ?'
        params.append(cve_id)
    if cpe_name:
        query += ' AND t.cpe_name = ?'
        params.append(cpe_name)
    query += ' ORDER BY t.id DESC'
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

#---FEATURE CATEGORIES---
@app.route('/db/feature-categories', methods=['GET'])
@login_required
def get_feature_categories():
    conn = get_db()
    rows = conn.execute('SELECT id, name FROM feature_categories ORDER BY name').fetchall()
    conn.close()
    return jsonify({'categories': [{'id': r['id'], 'name': r['name']} for r in rows]})

@app.route('/db/feature-categories', methods=['POST'])
@login_required
@require_role('admin')
def create_feature_category():
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Category name is required'}), 400
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO feature_categories (name, created_by) VALUES (?, ?)',
            (name, session['user_id'])
        )
        conn.commit()
        row = conn.execute('SELECT id, name FROM feature_categories WHERE name = ?', (name,)).fetchone()
        conn.close()
        return jsonify({'id': row['id'], 'name': row['name']})
    except Exception:
        conn.close()
        return jsonify({'error': 'Category already exists'}), 409

#---TICKET STATS---
@app.route('/db/ticket-stats', methods=['GET'])
@login_required
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

    # MTTA: tickets.created -> acceptedTickets.accepted
    mtta_rows = conn.execute('''
        SELECT t.created, at2.accepted
        FROM tickets t
        JOIN acceptedTickets at2 ON at2.ticket_id = t.id
        WHERE at2.isAccepted = 1 AND t.created IS NOT NULL AND at2.accepted IS NOT NULL
    ''').fetchall()

    mtta_deltas = []
    for r in mtta_rows:
        created = parse_app_ts(r['created'])
        accepted = parse_app_ts(r['accepted'])
        if created and accepted and accepted > created:
            mtta_deltas.append((accepted - created).total_seconds() / 3600)

    mtta_hours = round(sum(mtta_deltas) / len(mtta_deltas), 1) if mtta_deltas else None

    # MTTR: tickets.created -> resolvedTickets.resolved
    mttr_rows = conn.execute('''
        SELECT t.created, r.resolved
        FROM tickets t
        JOIN resolvedTickets r ON r.ticket_id = t.id
        WHERE r.isResolved = 1 AND t.created IS NOT NULL AND r.resolved IS NOT NULL
    ''').fetchall()

    mttr_deltas = []
    for row in mttr_rows:
        created = parse_app_ts(row['created'])
        res_ts = parse_app_ts(row['resolved'])
        if created and res_ts and res_ts > created:
            mttr_deltas.append((res_ts - created).total_seconds() / 3600)

    mttr_hours = round(sum(mttr_deltas) / len(mttr_deltas), 1) if mttr_deltas else None

    reopened_count = conn.execute('''
        SELECT COUNT(DISTINCT ticket_id) AS c FROM ticketActivity WHERE action = 'Reopened'
    ''').fetchone()['c']

    total_ever_resolved = conn.execute('''
        SELECT COUNT(DISTINCT ticket_id) AS c FROM resolvedTickets WHERE isResolved = 1
    ''').fetchone()['c']

    reopen_rate = round(reopened_count / total_ever_resolved * 100, 1) if total_ever_resolved > 0 else 0

    now = datetime.now()
    aging_buckets = {'0-7d': 0, '8-30d': 0, '31-90d': 0, '90d+': 0}
    for r in aging:
        created = parse_app_ts(r['created'])
        if not created:
            continue
        days = (now - created).days
        if days <= 7:
            aging_buckets['0-7d'] += 1
        elif days <= 30:
            aging_buckets['8-30d'] += 1
        elif days <= 90:
            aging_buckets['31-90d'] += 1
        else:
            aging_buckets['90d+'] += 1

    now_iso = datetime.now().isoformat()
    sla_breached_count = conn.execute('''
        SELECT COUNT(*) AS c FROM tickets t
        LEFT JOIN archivedTickets a ON a.ticket_id = t.id
        LEFT JOIN resolvedTickets r ON r.ticket_id = t.id
        WHERE t.sla_deadline IS NOT NULL
          AND t.sla_deadline < ?
          AND COALESCE(a.isArchived, 0) = 0
          AND COALESCE(r.isResolved, 0) = 0
    ''', (now_iso,)).fetchone()['c']

    conn.close()

    return jsonify({
        'by_status': by_status,
        'by_feature': {r['feature']: r['count'] for r in by_feature},
        'by_person': {r['username']: r['count'] for r in by_person},
        'resolution': {'resolved': resolved, 'total': total},
        'aging': [{'id': r['id'], 'created': r['created'], 'status': r['status']} for r in aging],
        'sla_breached': sla_breached_count,
        'metrics': {
            'mtta_hours': mtta_hours,
            'mttr_hours': mttr_hours,
            'reopen_rate': reopen_rate,
            'reopened_count': reopened_count,
            'total_resolved_for_reopen': total_ever_resolved,
            'aging_buckets': aging_buckets
        }
    })

#---SLA REPORT---
@app.route('/db/sla-report', methods=['GET'])
@require_role('manager')
def sla_report():
    """SLA compliance metrics for management reporting (ID.RA-06)."""
    conn = get_db()
    now_iso = datetime.now().isoformat()
    now_dt = datetime.now()

    active = conn.execute('''
        SELECT t.id, t.sla_tier, t.sla_deadline, t.created,
               COALESCE(s.status, 'Open') AS status
        FROM tickets t
        LEFT JOIN statusTickets s ON s.ticket_id = t.id
        LEFT JOIN archivedTickets a ON a.ticket_id = t.id
        LEFT JOIN resolvedTickets r ON r.ticket_id = t.id
        WHERE t.sla_deadline IS NOT NULL
          AND COALESCE(a.isArchived, 0) = 0
          AND COALESCE(r.isResolved, 0) = 0
    ''').fetchall()

    resolved = conn.execute('''
        SELECT t.id, t.sla_tier, t.sla_deadline, r.resolved AS resolved_at
        FROM tickets t
        JOIN resolvedTickets r ON r.ticket_id = t.id
        WHERE t.sla_deadline IS NOT NULL AND r.isResolved = 1
    ''').fetchall()
    conn.close()

    breached, approaching, on_track = [], [], []
    for row in active:
        if not row['sla_deadline']:
            continue
        deadline = parse_date(row['sla_deadline'])
        created = parse_date(row['created'])
        total_secs = (deadline - created).total_seconds()
        remaining_secs = (deadline - now_dt).total_seconds()
        pct_remaining = (remaining_secs / total_secs) if total_secs > 0 else 1.0
        entry = {
            'id': row['id'], 'tier': row['sla_tier'],
            'deadline': row['sla_deadline'], 'status': row['status'],
            'days_remaining': round(remaining_secs / 86400, 1),
        }
        if remaining_secs < 0:
            breached.append(entry)
        elif pct_remaining < 0.25:
            approaching.append(entry)
        else:
            on_track.append(entry)

    met, missed = 0, 0
    for row in resolved:
        resolved_dt = parse_date(row['resolved_at'])
        deadline_dt = parse_date(row['sla_deadline'])
        if resolved_dt <= deadline_dt:
            met += 1
        else:
            missed += 1

    total_closed = met + missed
    compliance_rate = round((met / total_closed) * 100, 1) if total_closed else None

    return jsonify({
        'active': {'breached': breached, 'approaching': approaching, 'on_track': on_track},
        'historic': {'met': met, 'missed': missed, 'compliance_rate': compliance_rate},
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
    valid_roles = ('viewer', 'tier 1 analyst', 'tier 2 analyst', 'manager', 'admin')
    if not username:
        return jsonify({'error': 'Username is required.'}), 400
    if role not in valid_roles:
        return jsonify({'error': f'Role must be one of {valid_roles}'}), 400

    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        conn.close()
        log_audit('USER_CREATE_FAILED', 'user', None, {'username': username, 'reason': 'duplicate'})
        return jsonify({'error': 'Username already exists.'}), 409

    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    policy = conn.execute('SELECT otp_expiry_hours FROM org_policies LIMIT 1').fetchone()
    expiry_hours = policy['otp_expiry_hours'] if policy else 72
    expires_at = (datetime.now() + timedelta(hours=expiry_hours)).isoformat()

    conn.execute(
        'INSERT INTO users (username, otp_hash, otp_expires_at, role, must_change_password) VALUES (?, ?, ?, ?, ?)',
        (username, otp_hash, expires_at, role, 1)
    )
    conn.commit()
    conn.close()
    log_audit('USER_CREATED', 'user', None, {'username': username, 'role': role})
    return jsonify({'success': True, 'username': username, 'role': role, 'otp': otp, 'expires_at': expires_at}), 201

@app.route('/admin/users/update-role', methods=['POST'])
@require_role('admin')
def admin_update_role():
    data = request.json or {}
    username = data.get('username', '').strip()
    role = data.get('role', '')
    valid_roles = ('viewer', 'tier 1 analyst', 'tier 2 analyst','manager', 'admin')
    if role not in valid_roles:
        return jsonify({'error': f'Role must be one of {valid_roles}'}), 400
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found.'}), 404
    old_role = conn.execute('SELECT role FROM users WHERE username = ?', (username,)).fetchone()['role']
    conn.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
    conn.commit()
    conn.close()
    log_audit('ROLE_CHANGED', 'user', None, {'username': username, 'old_role': old_role, 'new_role': role})
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
    log_audit('OTP_RESET', 'user', None, {'username': username})
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
    log_audit('USER_DELETED', 'user', None, {'username': username})
    return jsonify({'success': True, 'username': username})

@app.route('/admin/organization', methods=['GET'])
@require_role('admin')
def admin_get_organization():
    conn = get_db()
    org = conn.execute('SELECT name FROM organizations WHERE id = 1').fetchone()
    conn.close()
    return jsonify({'name': org['name'] if org else 'Default'})

@app.route('/admin/organization', methods=['POST'])
@require_role('admin')
def admin_update_organization():
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Organization name is required.'}), 400
    conn = get_db()
    current = conn.execute('SELECT name FROM organizations WHERE id = 1').fetchone()
    if current and current['name'] != 'Default':
        conn.close()
        return jsonify({'error': 'Organization name has already been registered and cannot be changed.'}), 403
    old_name = current['name'] if current else 'Default'
    conn.execute('UPDATE organizations SET name = ? WHERE id = 1', (name,))
    conn.commit()
    conn.close()
    log_audit('ORG_UPDATED', 'organization', '1', {'old_name': old_name, 'new_name': name})
    return jsonify({'success': True, 'name': name})

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
            otp_expiry_hours        = COALESCE(?, otp_expiry_hours),
            rescan_enabled          = COALESCE(?, rescan_enabled),
            rescan_interval_hours   = COALESCE(?, rescan_interval_hours),
            auto_ticket_enabled     = COALESCE(?, auto_ticket_enabled),
            auto_ticket_threshold   = COALESCE(?, auto_ticket_threshold),
            sla_enabled             = COALESCE(?, sla_enabled),
            sla_critical_days       = COALESCE(?, sla_critical_days),
            sla_standard_days       = COALESCE(?, sla_standard_days),
            mfa_required_role = ?,
            updated_at = ?,
            updated_by = ?
        WHERE id = 1
    ''', (
        data.get('otp_expiry_hours'),
        data.get('rescan_enabled'),
        data.get('rescan_interval_hours'),
        data.get('auto_ticket_enabled'),
        data.get('auto_ticket_threshold'),
        data.get('sla_enabled'),
        data.get('sla_critical_days'),
        data.get('sla_standard_days'),
        data.get('mfa_required_role'),
        datetime.now().isoformat(),
        uid
    ))
    conn.commit()
    conn.close()
    # Restart scheduler with new interval if settings changed
    try:
        start_scheduler()
    except Exception:
        pass
    conn2 = get_db()
    admins = conn2.execute(
        "SELECT id FROM users WHERE role = 'admin' AND org_id = 1 AND id != ?", (uid,)
    ).fetchall()
    for a in admins:
        create_notification(
            a['id'], 'policy_updated',
            'Organization policies updated',
            'An administrator updated the organization policies',
            resource_type='policy', resource_id='1', conn=conn2)
    conn2.commit()
    conn2.close()
    log_audit('POLICY_UPDATED', 'policy', '1', {
        'otp_expiry_hours': data.get('otp_expiry_hours'),
        'rescan_enabled': data.get('rescan_enabled'),
        'auto_ticket_enabled': data.get('auto_ticket_enabled'),
        'sla_enabled': data.get('sla_enabled'),
        'sla_critical_days': data.get('sla_critical_days'),
        'sla_standard_days': data.get('sla_standard_days'),
    })
    return jsonify({'success': True})

@app.route('/admin/permissions', methods=['GET'])
@require_role('admin')
def admin_get_permissions():
    conn = get_db()
    row = conn.execute('SELECT permissions_json FROM org_policies LIMIT 1').fetchone()
    conn.close()
    if row and row['permissions_json']:
        return jsonify({'permissions': json.loads(row['permissions_json'])})
    return jsonify({'permissions': None})

@app.route('/admin/permissions', methods=['POST'])
@require_role('admin')
def admin_update_permissions():
    data = request.json or {}
    perms = data.get('permissions')
    if not perms:
        return jsonify({'error': 'No permissions provided.'}), 400
    conn = get_db()
    conn.execute(
        'UPDATE org_policies SET permissions_json = ?, updated_at = ?, updated_by = ? WHERE id = 1',
        (json.dumps(perms), datetime.now().isoformat(), get_current_user_id())
    )
    conn.commit()
    conn.close()
    log_audit('PERMISSIONS_UPDATED', 'policy', '1')
    return jsonify({'success': True})

#=====================
# RISK DECISIONS
#=====================

@app.route('/db/risk-decision', methods=['POST'])
@login_required
def create_risk_decision():
    uid = get_current_user_id()
    data = request.json or {}
    cpe_name = data.get('cpe_name', '').strip()
    cve_id = data.get('cve_id', '').strip()
    decision = data.get('decision', '').strip()
    justification = data.get('justification', '').strip()
    review_date = data.get('review_date', '')
    ticket_id = data.get('ticket_id')

    if not cpe_name or not cve_id or not decision:
        return jsonify({'error': 'cpe_name, cve_id, and decision are required'}), 400

    valid_decisions = ('mitigate', 'accept', 'transfer', 'avoid', 'false_positive')
    if decision not in valid_decisions:
        return jsonify({'error': f'Decision must be one of {valid_decisions}'}), 400

    if decision == 'false_positive' and not justification:
        return jsonify({'error': 'Justification is required for false positive determination'}), 400

    if decision == 'accept' and not justification:
        return jsonify({'error': 'Justification is required for risk acceptance'}), 400

    if decision == 'accept' and not review_date:
        return jsonify({'error': 'Review date is required for risk acceptance'}), 400

    conn = get_db()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 403

    # Supersede any existing active decision for this CVE-asset pair
    conn.execute('''
        UPDATE risk_decisions SET status = 'superseded', updated_at = ?
        WHERE cpe_name = ? AND cve_id = ? AND status = 'active' AND org_id = 1
    ''', (datetime.now().isoformat(), cpe_name, cve_id))

    conn.execute('''
        INSERT INTO risk_decisions (org_id, cpe_name, cve_id, decision, justification, decided_by, review_date, ticket_id)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?)
    ''', (cpe_name, cve_id, decision, justification, uid, review_date or None, ticket_id))

    conn.commit()
    conn.close()
    conn2 = get_db()
    managers = conn2.execute(
        "SELECT id FROM users WHERE role IN ('admin', 'manager') AND org_id = 1 AND id != ?", (uid,)
    ).fetchall()
    for m in managers:
        create_notification(
            m['id'], 'risk_decision',
            f'Risk decision: {decision} for {cve_id}',
            f'{cpe_name} / {cve_id} — decision: {decision}',
            resource_type='cve', resource_id=cve_id, conn=conn2)
    conn2.commit()
    conn2.close()
    log_audit('RISK_DECISION', 'cve', cve_id, {'cpe_name': cpe_name, 'decision': decision})
    return jsonify({'success': True})

@app.route('/db/risk-decisions', methods=['GET'])
@login_required
def get_risk_decisions():
    cpe_name = request.args.get('cpe_name', '')
    cve_id = request.args.get('cve_id', '')
    decision_type = request.args.get('decision', '')
    status_filter = request.args.get('status', 'active')

    conn = get_db()
    query = '''
        SELECT rd.*, u.username AS decided_by_username, a.username AS approved_by_username
        FROM risk_decisions rd
        JOIN users u ON rd.decided_by = u.id
        LEFT JOIN users a ON rd.approved_by = a.id
        WHERE rd.org_id = 1
    '''
    params = []

    if cpe_name:
        query += ' AND rd.cpe_name = ?'
        params.append(cpe_name)
    if cve_id:
        query += ' AND rd.cve_id = ?'
        params.append(cve_id)
    if decision_type:
        query += ' AND rd.decision = ?'
        params.append(decision_type)
    if status_filter:
        query += ' AND rd.status = ?'
        params.append(status_filter)

    query += ' ORDER BY rd.id DESC'
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/db/risk-decisions/expiring', methods=['GET'])
@login_required
def get_expiring_risk_decisions():
    conn = get_db()
    now = datetime.now().isoformat()
    rows = conn.execute('''
        SELECT rd.*, u.username AS decided_by_username
        FROM risk_decisions rd
        JOIN users u ON rd.decided_by = u.id
        WHERE rd.org_id = 1 AND rd.status = 'active' AND rd.review_date IS NOT NULL AND rd.review_date <= ?
        ORDER BY rd.review_date ASC
    ''', (now,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/db/risk-decision/review', methods=['POST'])
@login_required
def review_risk_decision():
    data = request.json or {}
    decision_id = data.get('id')
    new_review_date = data.get('review_date', '')

    if not decision_id:
        return jsonify({'error': 'Decision id is required'}), 400

    conn = get_db()
    decision = conn.execute('SELECT id FROM risk_decisions WHERE id = ? AND org_id = 1', (decision_id,)).fetchone()
    if not decision:
        conn.close()
        return jsonify({'error': 'Decision not found'}), 404

    conn.execute('''
        UPDATE risk_decisions SET review_date = ?, updated_at = ? WHERE id = ?
    ''', (new_review_date or None, datetime.now().isoformat(), decision_id))
    conn.commit()
    conn.close()
    log_audit('RISK_DECISION_REVIEWED', 'risk_decision', str(decision_id))
    return jsonify({'success': True})

#=====================
# FALSE POSITIVE REVIEW
#=====================

@app.route('/admin/false-positives', methods=['GET'])
@login_required
@require_role('admin')
def get_false_positives():
    conn = get_db()
    rows = conn.execute('''
        SELECT rd.*, u.username AS decided_by_username
        FROM risk_decisions rd
        JOIN users u ON rd.decided_by = u.id
        WHERE rd.decision = 'false_positive' AND rd.status = 'active' AND rd.org_id = 1
        ORDER BY rd.created_at DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/admin/reverse-false-positive', methods=['POST'])
@login_required
@require_role('manager')
def reverse_false_positive():
    data = request.json or {}
    decision_id = data.get('decision_id')
    if not decision_id:
        return jsonify({'error': 'decision_id is required'}), 400
    conn = get_db()
    row = conn.execute(
        'SELECT id FROM risk_decisions WHERE id = ? AND decision = ? AND status = ? AND org_id = 1',
        (decision_id, 'false_positive', 'active')).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Active false positive not found'}), 404
    conn.execute(
        'UPDATE risk_decisions SET status = ?, updated_at = ? WHERE id = ?',
        ('reversed', datetime.now().isoformat(), decision_id))
    conn.commit()
    conn.close()
    log_audit('FALSE_POSITIVE_REVERSED', 'risk_decision', str(decision_id))
    return jsonify({'success': True})

#=====================
# NOTIFICATION ROUTES
#=====================

@app.route('/notifications', methods=['GET'])
@login_required
def get_notifications():
    uid = get_current_user_id()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    unread_only = request.args.get('unread_only', '0') == '1'
    conn = get_db()
    where = 'WHERE user_id = ?'
    params = [uid]
    if unread_only:
        where += ' AND is_read = 0'
    total = conn.execute(f'SELECT COUNT(*) AS c FROM notifications {where}', params).fetchone()['c']  # noqa: S608
    rows = conn.execute(
        f'SELECT * FROM notifications {where} ORDER BY created_at DESC LIMIT ? OFFSET ?',  # noqa: S608
        (*params, per_page, (page - 1) * per_page)
    ).fetchall()
    unread_count = conn.execute(
        'SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND is_read = 0', (uid,)
    ).fetchone()['c']
    conn.close()
    return jsonify({
        'notifications': [dict(r) for r in rows],
        'unread_count': unread_count,
        'total': total, 'page': page,
        'pages': (total + per_page - 1) // per_page if total else 0
    })

@app.route('/notifications/unread-count', methods=['GET'])
@login_required
def get_unread_count():
    uid = get_current_user_id()
    conn = get_db()
    count = conn.execute(
        'SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND is_read = 0', (uid,)
    ).fetchone()['c']
    conn.close()
    return jsonify({'unread_count': count})

@app.route('/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    uid = get_current_user_id()
    data = request.json or {}
    notif_ids = data.get('ids', [])
    conn = get_db()
    if notif_ids:
        placeholders = ','.join('?' * len(notif_ids))
        conn.execute(
            f'UPDATE notifications SET is_read = 1 WHERE user_id = ? AND id IN ({placeholders})',  # noqa: S608
            (uid, *notif_ids))
    else:
        conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (uid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/notifications/preferences', methods=['GET'])
@login_required
def get_notification_preferences():
    uid = get_current_user_id()
    conn = get_db()
    rows = conn.execute(
        'SELECT type, enabled FROM notification_preferences WHERE user_id = ?', (uid,)
    ).fetchall()
    conn.close()
    prefs = {r['type']: bool(r['enabled']) for r in rows}
    for t in NOTIFICATION_TYPES:
        if t not in prefs:
            prefs[t] = True
    return jsonify({'preferences': prefs})

@app.route('/notifications/preferences', methods=['POST'])
@login_required
def update_notification_preferences():
    uid = get_current_user_id()
    data = request.json or {}
    prefs = data.get('preferences', {})
    conn = get_db()
    for notif_type, enabled in prefs.items():
        if notif_type not in NOTIFICATION_TYPES:
            continue
        conn.execute(
            '''INSERT INTO notification_preferences (user_id, type, enabled) VALUES (?, ?, ?)
               ON CONFLICT(user_id, type) DO UPDATE SET enabled = ?''',
            (uid, notif_type, int(enabled), int(enabled)))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

#=====================
# RISK TOLERANCE
#=====================

@app.route('/admin/risk-tolerance', methods=['GET'])
@login_required
def get_risk_tolerance():
    conn = get_db()
    policy = conn.execute(
        'SELECT risk_threshold, risk_tolerance_statement, risk_tolerance_updated_at, risk_tolerance_updated_by FROM org_policies WHERE org_id = 1'
    ).fetchone()
    result = {}
    if policy:
        result = {
            'risk_threshold': policy['risk_threshold'] if policy['risk_threshold'] is not None else 7.0,
            'risk_tolerance_statement': policy['risk_tolerance_statement'] or '',
            'updated_at': policy['risk_tolerance_updated_at'] or '',
            'updated_by': None
        }
        if policy['risk_tolerance_updated_by']:
            user = conn.execute('SELECT username FROM users WHERE id = ?',
                                (policy['risk_tolerance_updated_by'],)).fetchone()
            result['updated_by'] = user['username'] if user else None
    conn.close()
    return jsonify(result)

@app.route('/admin/risk-tolerance', methods=['POST'])
@require_role('admin')
def update_risk_tolerance():
    uid = get_current_user_id()
    data = request.json or {}
    new_threshold = data.get('risk_threshold')
    statement = data.get('risk_tolerance_statement')
    reason = data.get('reason', '').strip()
    conn = get_db()
    policy = conn.execute('SELECT risk_threshold, risk_tolerance_statement FROM org_policies WHERE org_id = 1').fetchone()
    old_threshold = policy['risk_threshold'] if policy and policy['risk_threshold'] is not None else 7.0
    updates, params = [], []
    if new_threshold is not None:
        new_threshold = float(new_threshold)
        if new_threshold < 0 or new_threshold > 10:
            conn.close()
            return jsonify({'error': 'Threshold must be between 0 and 10'}), 400
        updates.append('risk_threshold = ?')
        params.append(new_threshold)
        if abs(new_threshold - old_threshold) > 0.001:
            conn.execute(
                '''INSERT INTO risk_threshold_history (org_id, old_value, new_value, changed_by, reason)
                   VALUES (1, ?, ?, ?, ?)''',
                (old_threshold, new_threshold, uid, reason or None))
    if statement is not None:
        updates.append('risk_tolerance_statement = ?')
        params.append(statement.strip())
    if updates:
        updates.extend(['risk_tolerance_updated_at = ?', 'risk_tolerance_updated_by = ?'])
        params.extend([datetime.now().isoformat(), uid])
        conn.execute(f'UPDATE org_policies SET {", ".join(updates)} WHERE org_id = 1', params)  # noqa: S608
        conn.commit()
        # Notify all users about threshold change
        if new_threshold is not None and abs(new_threshold - old_threshold) > 0.001:
            username = session.get('username', 'Admin')
            all_users = conn.execute(
                'SELECT id FROM users WHERE org_id = 1 AND id != ?', (uid,)).fetchall()
            for u in all_users:
                create_notification(
                    u['id'], 'threshold_changed',
                    f'Risk threshold changed: {old_threshold} → {new_threshold}',
                    f'{username} updated the org risk threshold. Reason: {reason or "Not specified"}',
                    resource_type='policy', resource_id='1', conn=conn)
            conn.commit()
    conn.close()
    log_audit('RISK_TOLERANCE_UPDATED', 'policy', '1', {
        'old_threshold': old_threshold, 'new_threshold': new_threshold,
        'has_statement': bool(statement), 'reason': reason})
    return jsonify({'success': True})

@app.route('/admin/risk-threshold-history', methods=['GET'])
@login_required
def get_risk_threshold_history():
    conn = get_db()
    rows = conn.execute('''
        SELECT h.*, u.username FROM risk_threshold_history h
        LEFT JOIN users u ON h.changed_by = u.id
        WHERE h.org_id = 1 ORDER BY h.created_at DESC LIMIT 50
    ''').fetchall()
    conn.close()
    return jsonify({'entries': [dict(r) for r in rows]})

#=====================
# AUDIT LOG VIEWER
#=====================

@app.route('/admin/audit-log', methods=['GET'])
@require_role('admin')
def admin_get_audit_log():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    conn = get_db()
    query = 'SELECT * FROM audit_log WHERE 1=1'
    params = []

    if action_filter:
        query += ' AND action = ?'
        params.append(action_filter)
    if user_filter:
        query += ' AND username = ?'
        params.append(user_filter)
    if date_from:
        query += ' AND timestamp >= ?'
        params.append(date_from)
    if date_to:
        query += ' AND timestamp <= ?'
        params.append(date_to)

    count_query = query.replace('SELECT *', 'SELECT COUNT(*) AS c')
    total = conn.execute(count_query, params).fetchone()['c']

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({
        'entries': [dict(r) for r in rows],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/admin/audit-log/export', methods=['GET'])
@require_role('admin')
def admin_export_audit_log():
    conn = get_db()
    rows = conn.execute('SELECT * FROM audit_log ORDER BY id DESC').fetchall()
    conn.close()

    import io
    import csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'User', 'Action', 'Resource Type', 'Resource ID', 'Details', 'IP Address'])
    for r in rows:
        writer.writerow([r['id'], r['timestamp'], r['username'], r['action'],
                         r['resource_type'], r['resource_id'], r['details'], r['ip_address']])

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=audit_log.csv'}
    )

#=====================
# SCAN HISTORY & RESCAN
#=====================

@app.route('/admin/scan-history', methods=['GET'])
@require_role('admin')
def admin_get_scan_history():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) AS c FROM scan_history WHERE org_id = 1').fetchone()['c']
    rows = conn.execute(
        'SELECT * FROM scan_history WHERE org_id = 1 ORDER BY id DESC LIMIT ? OFFSET ?',
        (per_page, (page - 1) * per_page)
    ).fetchall()
    conn.close()
    return jsonify({
        'entries': [dict(r) for r in rows],
        'total': total,
        'page': page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/admin/rescan-now', methods=['POST'])
@require_role('admin')
def admin_rescan_now():
    conn = get_db()
    assets = conn.execute('SELECT cpeName FROM assets WHERE org_id = 1').fetchall()
    if not assets:
        conn.close()
        return jsonify({'error': 'No assets to scan'}), 400

    policy = conn.execute('SELECT * FROM org_policies WHERE org_id = 1').fetchone()
    threshold = (policy['auto_ticket_threshold'] if policy else 7.0) or 7.0
    auto_ticket = policy['auto_ticket_enabled'] if policy else 0
    conn.close()

    total_new = 0
    total_scanned = 0

    for asset in assets:
        cpe_name = asset['cpeName']
        started_at = datetime.now().isoformat()
        conn = get_db()
        try:
            asset_row = conn.execute('SELECT cveData FROM assets WHERE cpeName = ? AND org_id = 1', (cpe_name,)).fetchone()
            old_cve_data = json.loads(asset_row['cveData']) if asset_row and asset_row['cveData'] else {}
            old_cve_ids = {v.get('cve', {}).get('id', '') for v in old_cve_data.get('vulnerabilities', [])}

            new_vulns = fetch_cves_for_cpe(cpe_name)
            kev_list = get_kev_list()
            cve_ids = [v.get('cve', {}).get('id', '') for v in new_vulns if v.get('cve', {}).get('id')]
            epss_scores = fetch_epss_scores(cve_ids)

            new_findings = []
            for vuln in new_vulns:
                cve_id = vuln.get('cve', {}).get('id', '')
                score = priority_score(vuln, kev_list, epss_scores)
                vuln['priorityScore'] = score
                vuln['hasKev'] = cve_id in kev_list
                vuln['epssScore'] = epss_scores.get(cve_id, 0)
                if cve_id and cve_id not in old_cve_ids:
                    normalized = min((score / 1744) * 10, 10)
                    if normalized >= threshold:
                        new_findings.append(vuln)

            conn.execute(
                'UPDATE assets SET cveData = ?, last_scanned = ? WHERE cpeName = ? AND org_id = 1',
                (json.dumps({'vulnerabilities': new_vulns, 'count': len(new_vulns), 'title': old_cve_data.get('title', cpe_name)}),
                 datetime.now().isoformat(), cpe_name))

            tickets_created = 0
            if auto_ticket and new_findings:
                admin = conn.execute("SELECT id FROM users WHERE role = 'admin' AND org_id = 1 LIMIT 1").fetchone()
                if admin:
                    for vuln in new_findings:
                        vid = vuln['cve']['id']
                        existing = conn.execute(
                            'SELECT id FROM tickets WHERE cve_id = ? AND cpe_name = ? AND isResolved = 0',
                            (vid, cpe_name)).fetchone()
                        if existing:
                            continue
                        ns = min((vuln['priorityScore'] / 1744) * 10, 10)
                        desc = f"[Auto-generated] {vid} detected on {cpe_name} with priority score {ns:.1f}/10"
                        sla_tier = 'Critical' if ns >= threshold else 'Standard'
                        created_ts = datetime.now().isoformat()
                        sla_deadline = calculate_sla_deadline(created_ts, sla_tier, policy)
                        conn.execute(
                            'INSERT INTO tickets (user_id, description, feature, created, isResolved, cve_id, cpe_name, sla_tier, sla_deadline) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)',
                            (admin['id'], desc, 'Auto-Generated', created_ts, vid, cpe_name, sla_tier, sla_deadline))
                        tid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                        conn.execute(
                            'INSERT INTO statusTickets (ticket_id, user_id, status, updated) VALUES (?, ?, ?, ?)',
                            (tid, admin['id'], 'Open', datetime.now().isoformat()))
                        conn.execute(
                            'INSERT INTO ticketActivity (ticket_id, user_id, action, timestamp) VALUES (?, ?, ?, ?)',
                            (tid, admin['id'], 'Auto-created from manual scan', datetime.now().isoformat()))
                        tickets_created += 1

            conn.execute(
                '''INSERT INTO scan_history (org_id, cpe_name, scan_type, new_cve_count, total_cve_count,
                   tickets_created, started_at, completed_at, status)
                   VALUES (1, ?, 'manual', ?, ?, ?, ?, ?, 'completed')''',
                (cpe_name, len(new_findings), len(new_vulns), tickets_created,
                 started_at, datetime.now().isoformat()))

            total_new += len(new_findings)
            total_scanned += 1
            conn.commit()
        except Exception as e:
            conn.execute(
                '''INSERT INTO scan_history (org_id, cpe_name, scan_type, started_at, completed_at, status, error_message)
                   VALUES (1, ?, 'manual', ?, ?, 'failed', ?)''',
                (cpe_name, started_at, datetime.now().isoformat(), str(e)))
            conn.commit()
        finally:
            conn.close()

    log_audit('RESCAN_TRIGGERED', 'scan', None, {'assets_scanned': total_scanned, 'new_cves': total_new})
    return jsonify({'success': True, 'assets_scanned': total_scanned, 'new_cves': total_new})

@app.route('/db/save-chart-layout', methods=['POST'])
@login_required
def save_chart_layout():
    data = request.json or {}
    layout = data.get('layout', [])
    uid = get_current_user_id()
    conn = get_db()
    conn.execute(
        'UPDATE users SET chart_layout_json = ? WHERE id = ?',
        (json.dumps(layout), uid)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/db/load-chart-layout', methods=['GET'])
@login_required
def load_chart_layout():
    uid = get_current_user_id()
    conn = get_db()
    row = conn.execute('SELECT chart_layout_json FROM users WHERE id = ?', (uid,)).fetchone()
    conn.close()
    if row and row['chart_layout_json']:
        return jsonify({'layout': json.loads(row['chart_layout_json'])})
    return jsonify({'layout': []})

#===========
# MAIN
#===========

def main():
    init_db()
    start_scheduler()
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(host='0.0.0.0', debug=debug, port=5000, use_reloader=False)  # noqa: S104

if __name__ == '__main__':
    main()
