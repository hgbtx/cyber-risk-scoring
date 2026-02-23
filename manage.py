import argparse, sys, secrets, string
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from db import get_db, init_db


def generate_otp(length=12):
    alphabet = string.ascii_uppercase + string.digits
    raw = ''.join(secrets.choice(alphabet) for _ in range(length))
    return '-'.join(raw[i:i+4] for i in range(0, length, 4))


def get_otp_expiry_hours():
    conn = get_db()
    row = conn.execute('SELECT otp_expiry_hours FROM org_policies LIMIT 1').fetchone()
    conn.close()
    return row['otp_expiry_hours'] if row else 72


def create_admin(username, password):
    if len(password) < 8:
        print('Error: Password must be at least 8 characters.')
        sys.exit(1)
    init_db()
    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        conn.close()
        print(f'Error: Account "{username}" already exists. Use promote instead.')
        sys.exit(1)
    pw_hash = generate_password_hash(password)
    conn.execute(
        'INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, ?)',
        (username, pw_hash, 'admin', 0)
    )
    conn.commit()
    conn.close()
    print(f'Admin account created: {username}')


def create_user(username, role='viewer'):
    valid_roles = ('viewer', 'tier 1 analyst', 'tier 2 analyst','manager', 'admin')
    if role not in valid_roles:
        print(f'Error: Role must be one of {valid_roles}')
        sys.exit(1)
    init_db()
    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        conn.close()
        print(f'Error: Account "{username}" already exists.')
        sys.exit(1)

    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    expiry_hours = get_otp_expiry_hours()
    expires_at = (datetime.now() + timedelta(hours=expiry_hours)).isoformat()

    conn.execute(
        'INSERT INTO users (username, otp_hash, otp_expires_at, role, must_change_password) VALUES (?, ?, ?, ?, ?)',
        (username, otp_hash, expires_at, role, 1)
    )
    conn.commit()
    conn.close()
    print(f'Account created: {username} (role: {role})')
    print(f'One-time password: {otp}')
    print(f'Expires: {expires_at}')


def promote_user(username, role):
    valid_roles = ('viewer', 'tier 1 analyst', 'tier 2 analyst','manager', 'admin')
    if role not in valid_roles:
        print(f'Error: Role must be one of {valid_roles}')
        sys.exit(1)
    init_db()
    conn = get_db()
    user = conn.execute('SELECT id, role FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        conn.close()
        print(f'Error: No account found for "{username}"')
        sys.exit(1)
    old_role = user['role']
    conn.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
    conn.commit()
    conn.close()
    print(f'{username}: {old_role} -> {role}')


def reset_otp(username):
    init_db()
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        conn.close()
        print(f'Error: No account found for "{username}"')
        sys.exit(1)

    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    expiry_hours = get_otp_expiry_hours()
    expires_at = (datetime.now() + timedelta(hours=expiry_hours)).isoformat()

    conn.execute(
        'UPDATE users SET otp_hash = ?, otp_expires_at = ?, must_change_password = 1, password_hash = NULL WHERE username = ?',
        (otp_hash, expires_at, username)
    )
    conn.commit()
    conn.close()
    print(f'OTP reset for: {username}')
    print(f'New one-time password: {otp}')
    print(f'Expires: {expires_at}')

def delete_user(username):
    init_db()
    conn = get_db()
    user = conn.execute('SELECT id, role FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        conn.close()
        print(f'Error: No account found for "{username}"')
        sys.exit(1)
    if user['role'] == 'admin':
        admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        if admin_count <= 1:
            conn.close()
            print('Error: Cannot delete the only admin account.')
            sys.exit(1)
    conn.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    print(f'Account deleted: {username}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User management CLI')
    sub = parser.add_subparsers(dest='command')

    c1 = sub.add_parser('create-admin', help='Create the initial admin account')
    c1.add_argument('--username', required=True)
    c1.add_argument('--password', required=True)

    c2 = sub.add_parser('create-user', help='Create a new user with OTP')
    c2.add_argument('--username', required=True)
    c2.add_argument('--role', default='viewer')

    c3 = sub.add_parser('promote', help='Change a user role')
    c3.add_argument('--username', required=True)
    c3.add_argument('--role', required=True)

    c4 = sub.add_parser('reset-otp', help='Generate a new OTP for a user')
    c4.add_argument('--username', required=True)

    c5 = sub.add_parser('delete-user', help='Delete a user account')
    c5.add_argument('--username', required=True)

    args = parser.parse_args()
    if args.command == 'create-admin':
        create_admin(args.username, args.password)
    elif args.command == 'create-user':
        create_user(args.username, args.role)
    elif args.command == 'promote':
        promote_user(args.username, args.role)
    elif args.command == 'reset-otp':
        reset_otp(args.username)
    elif args.command == 'delete-user':
        delete_user(args.username)
    else:
        parser.print_help()