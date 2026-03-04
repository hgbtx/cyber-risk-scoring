import sqlite3, json, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL DEFAULT 1,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            otp_hash TEXT,
            otp_expires_at TEXT,
            must_change_password INTEGER DEFAULT 1,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        );

        CREATE TABLE IF NOT EXISTS assets (
            cpeName TEXT NOT NULL,
            org_id  INTEGER NOT NULL DEFAULT 1,
            user_id INTEGER NOT NULL,
            title   TEXT,
            cpeData TEXT,
            cveData TEXT,
            PRIMARY KEY (cpeName, org_id),
            FOREIGN KEY (org_id)  REFERENCES organizations(id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS archivedAssets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cpeName TEXT NOT NULL,
            org_id  INTEGER NOT NULL DEFAULT 1,
            user_id INTEGER NOT NULL,
            archived TEXT,
            isArchived INTEGER DEFAULT 0,
            FOREIGN KEY (cpeName, org_id) REFERENCES assets(cpeName, org_id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            description TEXT,
            feature TEXT,
            created TEXT,
            isResolved INTEGER DEFAULT 0,
            resolved TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS resolvedTickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            resolved TEXT,
            isResolved INTEGER DEFAULT 0,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS cpe_cache (
            cpeName TEXT PRIMARY KEY NOT NULL UNIQUE,
            cpeData TEXT,
            fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS acceptedTickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            accepted TEXT,
            isAccepted INTEGER DEFAULT 0,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS archivedTickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            accepted_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            archived TEXT,
            isArchived INTEGER DEFAULT 0,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (accepted_id) REFERENCES acceptedTickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS commentTickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            accepted_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            commented TEXT,
            comment_description TEXT,
            isFixed INTEGER DEFAULT 0,
            fixed TEXT,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (accepted_id) REFERENCES acceptedTickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS reassignedTickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            reassigned TEXT,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS confirmedResolutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            confirmed TEXT,
            isConfirmed INTEGER DEFAULT 0,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS deletedTickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            deleted TEXT,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS feature_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS ticketActivity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS statusTickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            updated TEXT,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS ticketCollaborators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            added_by INTEGER NOT NULL,
            added TEXT,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(ticket_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            level INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS org_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            otp_expiry_hours INTEGER NOT NULL DEFAULT 72,
            permissions_json TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            FOREIGN KEY (org_id) REFERENCES organizations(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL DEFAULT 1,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        );

        CREATE TABLE IF NOT EXISTS risk_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL DEFAULT 1,
            cpe_name TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            justification TEXT,
            decided_by INTEGER NOT NULL,
            approved_by INTEGER,
            review_date TEXT,
            ticket_id INTEGER,
            status TEXT DEFAULT 'active',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES organizations(id),
            FOREIGN KEY (decided_by) REFERENCES users(id),
            FOREIGN KEY (approved_by) REFERENCES users(id),
            FOREIGN KEY (ticket_id) REFERENCES tickets(id)
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL DEFAULT 1,
            cpe_name TEXT NOT NULL,
            scan_type TEXT DEFAULT 'scheduled',
            new_cve_count INTEGER DEFAULT 0,
            total_cve_count INTEGER DEFAULT 0,
            tickets_created INTEGER DEFAULT 0,
            started_at TEXT,
            completed_at TEXT,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL DEFAULT 1,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            link TEXT,
            resource_type TEXT,
            resource_id TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES organizations(id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notification_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            UNIQUE(user_id, type),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS risk_threshold_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL DEFAULT 1,
            old_value REAL NOT NULL,
            new_value REAL NOT NULL,
            changed_by INTEGER NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES organizations(id),
            FOREIGN KEY (changed_by) REFERENCES users(id)
        );

    ''')
    conn.commit()

    # Migration: add isFixed/fixed columns if missing
    try:
        conn.execute('ALTER TABLE commentTickets ADD COLUMN isFixed INTEGER DEFAULT 0')
    except:
        pass
    try:
        conn.execute('ALTER TABLE commentTickets ADD COLUMN fixed TEXT')
    except:
        pass

    # Migration: add org_id to assets if missing (old schema had cpeName as sole PK)
    try:
        conn.execute('ALTER TABLE assets ADD COLUMN org_id INTEGER NOT NULL DEFAULT 1')
    except:
        pass

    # Migration: add org_id to archivedAssets if missing
    try:
        conn.execute('ALTER TABLE archivedAssets ADD COLUMN org_id INTEGER NOT NULL DEFAULT 1')
    except:
        pass

    # Migration: add chart_layout_json to users if missing
    try:
        conn.execute('ALTER TABLE users ADD COLUMN chart_layout_json TEXT')
    except:
        pass

    # Migration: TOTP / MFA columns
    for col, defn in [
        ('totp_secret', 'TEXT'),
        ('totp_enabled', 'INTEGER DEFAULT 0'),
        ('backup_codes', 'TEXT'),
        ('failed_login_count', 'INTEGER DEFAULT 0'),
        ('locked_until', 'TEXT'),
    ]:
        try:
            conn.execute(f'ALTER TABLE users ADD COLUMN {col} {defn}')
        except:
            pass

    # Migration: asset scanning columns
    for col, defn in [
        ('last_scanned', 'TEXT'),
        ('auto_ticket', 'INTEGER DEFAULT 1'),
    ]:
        try:
            conn.execute(f'ALTER TABLE assets ADD COLUMN {col} {defn}')
        except:
            pass

    # Migration: org_policies mfa_required_role column
    try:
        conn.execute('ALTER TABLE org_policies ADD COLUMN mfa_required_role INTEGER')
    except Exception:
        pass

    # Migration: org_policies scanning columns
    for col, defn in [
        ('rescan_enabled', 'INTEGER DEFAULT 0'),
        ('rescan_interval_hours', 'INTEGER DEFAULT 168'),
        ('auto_ticket_enabled', 'INTEGER DEFAULT 0'),
        ('auto_ticket_threshold', 'REAL DEFAULT 7.0'),
        ('auto_ticket_feature', "TEXT DEFAULT 'Auto-Generated'"),
    ]:
        try:
            conn.execute(f'ALTER TABLE org_policies ADD COLUMN {col} {defn}')
        except:
            pass

    # Migration: asset criticality and tags
    for col, defn in [
        ('criticality', 'INTEGER DEFAULT 3'),
        ('tags', "TEXT DEFAULT '[]'"),
    ]:
        try:
            conn.execute(f'ALTER TABLE assets ADD COLUMN {col} {defn}')
        except:
            pass

    # Migration: CVE-ticket linkage columns
    for col, defn in [
        ('cve_id', 'TEXT'),
        ('cpe_name', 'TEXT'),
    ]:
        try:
            conn.execute(f'ALTER TABLE tickets ADD COLUMN {col} {defn}')
        except:
            pass

    # Migration: risk tolerance columns on org_policies
    for col, defn in [
        ('risk_threshold', 'REAL DEFAULT 7.0'),
        ('risk_tolerance_statement', 'TEXT'),
        ('risk_tolerance_updated_at', 'TEXT'),
        ('risk_tolerance_updated_by', 'INTEGER'),
    ]:
        try:
            conn.execute(f'ALTER TABLE org_policies ADD COLUMN {col} {defn}')
        except:
            pass

    # Migration: rebuild notification_preferences if it has the old per-column schema
    np_cols = [row[1] for row in conn.execute('PRAGMA table_info(notification_preferences)').fetchall()]
    if 'type' not in np_cols:
        conn.execute('DROP TABLE IF EXISTS notification_preferences')
        conn.execute('''
            CREATE TABLE notification_preferences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                UNIQUE(user_id, type),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

    # Migration: add resource_type/resource_id to notifications if missing
    n_cols = [row[1] for row in conn.execute('PRAGMA table_info(notifications)').fetchall()]
    if 'resource_type' not in n_cols:
        try:
            conn.execute('ALTER TABLE notifications ADD COLUMN resource_type TEXT')
        except Exception:
            pass
    if 'resource_id' not in n_cols:
        try:
            conn.execute('ALTER TABLE notifications ADD COLUMN resource_id TEXT')
        except Exception:
            pass

    # Migration: SLA policy columns on org_policies (ID.RA-06)
    for col, defn in [
        ('sla_enabled',       'INTEGER DEFAULT 0'),
        ('sla_critical_days', 'INTEGER DEFAULT 7'),
        ('sla_standard_days', 'INTEGER DEFAULT 30'),
    ]:
        try:
            conn.execute(f'ALTER TABLE org_policies ADD COLUMN {col} {defn}')
        except:
            pass

    # Migration: SLA columns on tickets (ID.RA-06)
    for col, defn in [
        ('sla_tier',     "TEXT DEFAULT 'Standard'"),
        ('sla_deadline', 'TEXT'),
    ]:
        try:
            conn.execute(f'ALTER TABLE tickets ADD COLUMN {col} {defn}')
        except:
            pass

    try:
        conn.execute('ALTER TABLE resolvedTickets ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0')
    except:
        pass

    conn.commit()

    # Seed roles if empty
    if conn.execute('SELECT COUNT(*) FROM roles').fetchone()[0] == 0:
        conn.executemany(
            'INSERT INTO roles (name, level) VALUES (?, ?)',
            [('viewer', 1), ('tier 1 analyst', 2), ('tier 2 analyst', 3), ('manager', 4), ('admin', 5)]
        )

    # Seed default organization if empty
    if conn.execute('SELECT COUNT(*) FROM organizations').fetchone()[0] == 0:
        conn.execute("INSERT INTO organizations (name) VALUES (?)", ('Default',))

    # Seed default org_policies if empty
    if conn.execute('SELECT COUNT(*) FROM org_policies').fetchone()[0] == 0:
        conn.execute("INSERT INTO org_policies (org_id, otp_expiry_hours) VALUES (1, 72)")

    # Seed default feature categories if empty
    if conn.execute('SELECT COUNT(*) FROM feature_categories').fetchone()[0] == 0:
        defaults = [
            'Search', 'myCharts', 'Asset Directory',
            'myTickets', 'Left Panel', 'Right Panel', 'Other',
            'Auto-Generated',
        ]
        for name in defaults:
            conn.execute(
                'INSERT INTO feature_categories (name) VALUES (?)',
                (name,),
            )
    else:
        # Ensure 'Auto-Generated' category exists for scheduled scans
        if not conn.execute("SELECT id FROM feature_categories WHERE name = 'Auto-Generated'").fetchone():
            conn.execute("INSERT INTO feature_categories (name) VALUES ('Auto-Generated')")

    conn.commit()

    conn.close()