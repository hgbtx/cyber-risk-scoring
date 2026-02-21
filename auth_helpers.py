from flask import session, jsonify
from functools import wraps
from db import get_db

# Role hierarchy levels (mirrors roles table)
ROLE_LEVELS = {
    'viewer': 1,
    'analyst': 2,
    'manager': 3,
    'admin': 4
}

# SoD conflict rules: action -> list of conflicting prior actions
SOD_CONFLICTS = {
    'Accepted': ['Created'],
    'Archived': ['Resolved'],
}


def get_role_level(role_name):
    return ROLE_LEVELS.get(role_name, 0)


def require_role(min_role):
    """Decorator that checks the user's role level meets the minimum required."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            user_role = session.get('role', 'viewer')
            if get_role_level(user_role) < get_role_level(min_role):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def require_permission(category, permission):
    """Decorator that checks the role_permissions table instead of hardcoded role levels."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            role = session.get('role', 'viewer')
            conn = get_db()
            row = conn.execute(
                'SELECT access_level FROM role_permissions WHERE category = ? AND permission = ? AND role = ?',
                (category, permission, role)
            ).fetchone()
            conn.close()
            access = row['access_level'] if row else 'blocked'
            if access == 'blocked':
                return jsonify({'error': 'Insufficient permissions'}), 403
            if access in ('managerial approval', 'admin approval'):
                return jsonify({
                    'error': 'This action requires approval',
                    'requires_approval': access
                }), 202
            # 'read only' and 'read/write' both pass through —
            # individual routes handle read-only logic if needed
            return f(*args, **kwargs)
        return decorated
    return decorator


def check_permission(category, permission):
    """Non-decorator version — returns the access_level string for inline checks."""
    role = session.get('role', 'viewer')
    conn = get_db()
    row = conn.execute(
        'SELECT access_level FROM role_permissions WHERE category = ? AND permission = ? AND role = ?',
        (category, permission, role)
    ).fetchone()
    conn.close()
    return row['access_level'] if row else 'blocked'

def check_ownership(resource_type, resource_id, user_id):
    """Check if a user owns a resource, and whether org policy grants wider access."""
    conn = get_db()

    # Check direct ownership
    if resource_type == 'asset':
        row = conn.execute('SELECT user_id FROM assets WHERE id = ?', (resource_id,)).fetchone()
    elif resource_type == 'ticket':
        row = conn.execute('SELECT user_id FROM tickets WHERE id = ?', (resource_id,)).fetchone()
    else:
        conn.close()
        return False

    if not row:
        conn.close()
        return False

    is_owner = (row['user_id'] == user_id)

    if is_owner:
        conn.close()
        return True

    # Check org policy for non-owners
    user_role = session.get('role', 'viewer')
    policy = conn.execute('SELECT asset_sharing_mode FROM org_policies LIMIT 1').fetchone()
    conn.close()

    if not policy:
        return False

    sharing_mode = policy['asset_sharing_mode']

    if resource_type == 'asset':
        if sharing_mode == 'private':
            return get_role_level(user_role) >= get_role_level('manager')
        elif sharing_mode == 'visible':
            return get_role_level(user_role) >= get_role_level('viewer')
        elif sharing_mode == 'collaborative':
            return get_role_level(user_role) >= get_role_level('analyst')

    if resource_type == 'ticket':
        return get_role_level(user_role) >= get_role_level('analyst')

    return False


def check_sod(ticket_id, user_id, action):
    """
    Check SoD conflicts for a ticket action.
    Returns dict:
        {'allowed': True} — no conflict
        {'allowed': False, 'reason': '...', 'enforcement': 'hard'|'soft'} — conflict found
    """
    conflicts = SOD_CONFLICTS.get(action)
    if not conflicts:
        return {'allowed': True}

    conn = get_db()

    # Check if this user performed any conflicting prior action
    placeholders = ','.join('?' * len(conflicts))
    conflict = conn.execute(
        f'SELECT action FROM ticketActivity WHERE ticket_id = ? AND user_id = ? AND action IN ({placeholders})',
        (ticket_id, user_id, *conflicts)
    ).fetchone()

    if not conflict:
        conn.close()
        return {'allowed': True}

    # Conflict found — check enforcement mode
    policy = conn.execute('SELECT sod_enforcement FROM org_policies LIMIT 1').fetchone()
    conn.close()

    enforcement = policy['sod_enforcement'] if policy else 'hard'
    reason = f'SoD conflict: user already performed "{conflict["action"]}" on this ticket'

    return {
        'allowed': False,
        'reason': reason,
        'enforcement': enforcement,
        'conflicting_action': conflict['action']
    }


def log_sod_override(ticket_id, user_id, action_blocked, override_by, reason=None):
    """Log a manager override of a soft SoD block."""
    conn = get_db()
    conn.execute(
        'INSERT INTO sod_overrides (ticket_id, user_id, action_blocked, override_by, reason) VALUES (?, ?, ?, ?, ?)',
        (ticket_id, user_id, action_blocked, override_by, reason)
    )
    conn.commit()
    conn.close()