import argparse, sys
from werkzeug.security import generate_password_hash
from db import get_db, init_db

def create_admin(email, password):
    if len(password) < 8:
        print('Error: Password must be at least 8 characters.')
        sys.exit(1)
    init_db()
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if existing:
        conn.close()
        print(f'Error: Account {email} already exists. Use --promote instead.')
        sys.exit(1)
    pw_hash = generate_password_hash(password)
    conn.execute(
        'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
        (email, pw_hash, 'admin')
    )
    conn.commit()
    conn.close()
    print(f'Admin account created: {email}')

def promote_user(email, role):
    valid_roles = ('viewer', 'analyst', 'manager', 'admin')
    if role not in valid_roles:
        print(f'Error: Role must be one of {valid_roles}')
        sys.exit(1)
    init_db()
    conn = get_db()
    user = conn.execute('SELECT id, role FROM users WHERE email = ?', (email,)).fetchone()
    if not user:
        conn.close()
        print(f'Error: No account found for {email}')
        sys.exit(1)
    old_role = user['role']
    conn.execute('UPDATE users SET role = ? WHERE email = ?', (role, email))
    conn.commit()
    conn.close()
    print(f'{email}: {old_role} -> {role}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User management CLI')
    sub = parser.add_subparsers(dest='command')

    create = sub.add_parser('create-admin', help='Create a new admin account')
    create.add_argument('--email', required=True)
    create.add_argument('--password', required=True)

    promo = sub.add_parser('promote', help='Change a user role')
    promo.add_argument('--email', required=True)
    promo.add_argument('--role', required=True)

    args = parser.parse_args()
    if args.command == 'create-admin':
        create_admin(args.email, args.password)
    elif args.command == 'promote':
        promote_user(args.email, args.role)
    else:
        parser.print_help()