from flask import session, jsonify
from functools import wraps
from db import get_db

# Role hierarchy levels (mirrors roles table)
ROLE_LEVELS = {
    'viewer': 1,
    'tier 1 analyst': 2,
    'tier 2 analyst': 3,
    'manager': 4,
    'admin': 5
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

    return False