import sqlite3, json, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cpeName TEXT NOT NULL,
            title TEXT,
            cpeData TEXT,
            cveData TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, cpeName)
        );
        
        CREATE TABLE IF NOT EXISTS archivedAssets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            archived TEXT,
            isArchived INTEGER DEFAULT 0,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
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

        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            level INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS org_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            asset_sharing_mode TEXT NOT NULL DEFAULT 'private',
            sod_enforcement TEXT NOT NULL DEFAULT 'hard',
            otp_expiry_hours INTEGER NOT NULL DEFAULT 72,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            FOREIGN KEY (org_id) REFERENCES organizations(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sod_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            action_blocked TEXT NOT NULL,
            override_by INTEGER NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (override_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            permission TEXT NOT NULL,
            role TEXT NOT NULL,
            access_level TEXT NOT NULL DEFAULT 'blocked',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            UNIQUE(category, permission, role),
            FOREIGN KEY (updated_by) REFERENCES users(id)
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
    conn.commit()

    # Seed default organization if empty
    if conn.execute('SELECT COUNT(*) FROM organizations').fetchone()[0] == 0:
        conn.execute("INSERT INTO organizations (name) VALUES (?)", ('Default',))

    # Seed roles if empty
    if conn.execute('SELECT COUNT(*) FROM roles').fetchone()[0] == 0:
        conn.executemany(
            'INSERT INTO roles (name, level) VALUES (?, ?)',
            [('viewer', 1), ('analyst', 2), ('manager', 3), ('admin', 4)]
        )

    # Seed default org policy if empty
    if conn.execute('SELECT COUNT(*) FROM org_policies').fetchone()[0] == 0:
        org_id = conn.execute('SELECT id FROM organizations LIMIT 1').fetchone()[0]
        conn.execute(
            'INSERT INTO org_policies (org_id, asset_sharing_mode, sod_enforcement) VALUES (?, ?, ?)',
            (org_id, 'private', 'hard')
        )
    conn.commit()

    # Seed default role permissions if empty
    if conn.execute('SELECT COUNT(*) FROM role_permissions').fetchone()[0] == 0:
        default_perms = [
            # Search Permissions
            ('Search', 'Viewable Search tab',           'viewer',  'read only'),
            ('Search', 'Viewable Search tab',           'analyst', 'read only'),
            ('Search', 'Viewable Search tab',           'manager', 'read only'),
            ('Search', 'Viewable Search tab',           'admin',   'read/write'),
            ('Search', 'Perform searches',              'viewer',  'blocked'),
            ('Search', 'Perform searches',              'analyst', 'read/write'),
            ('Search', 'Perform searches',              'manager', 'read/write'),
            ('Search', 'Perform searches',              'admin',   'read/write'),
            ('Search', 'Drag and drop to Assets',       'viewer',  'blocked'),
            ('Search', 'Drag and drop to Assets',       'analyst', 'read/write'),
            ('Search', 'Drag and drop to Assets',       'manager', 'read/write'),
            ('Search', 'Drag and drop to Assets',       'admin',   'read/write'),
            ('Search', 'Add assets to Asset Directory', 'viewer',  'blocked'),
            ('Search', 'Add assets to Asset Directory', 'analyst', 'managerial approval'),
            ('Search', 'Add assets to Asset Directory', 'manager', 'read/write'),
            ('Search', 'Add assets to Asset Directory', 'admin',   'read/write'),
            # myCharts Permissions
            ('myCharts', 'Viewable myCharts tab',             'viewer',  'read only'),
            ('myCharts', 'Viewable myCharts tab',             'analyst', 'read only'),
            ('myCharts', 'Viewable myCharts tab',             'manager', 'read only'),
            ('myCharts', 'Viewable myCharts tab',             'admin',   'read/write'),
            ('myCharts', 'Drag and drop charts to dashboard', 'viewer',  'blocked'),
            ('myCharts', 'Drag and drop charts to dashboard', 'analyst', 'read/write'),
            ('myCharts', 'Drag and drop charts to dashboard', 'manager', 'read/write'),
            ('myCharts', 'Drag and drop charts to dashboard', 'admin',   'read/write'),
            ('myCharts', 'Download PNG',                      'viewer',  'blocked'),
            ('myCharts', 'Download PNG',                      'analyst', 'read/write'),
            ('myCharts', 'Download PNG',                      'manager', 'read/write'),
            ('myCharts', 'Download PNG',                      'admin',   'read/write'),
            ('myCharts', 'Download PDF',                      'viewer',  'blocked'),
            ('myCharts', 'Download PDF',                      'analyst', 'read/write'),
            ('myCharts', 'Download PDF',                      'manager', 'read/write'),
            ('myCharts', 'Download PDF',                      'admin',   'read/write'),
            # Asset Directory Permissions
            ('Asset Directory', 'Viewable Asset Directory tab', 'viewer',  'read only'),
            ('Asset Directory', 'Viewable Asset Directory tab', 'analyst', 'read only'),
            ('Asset Directory', 'Viewable Asset Directory tab', 'manager', 'read only'),
            ('Asset Directory', 'Viewable Asset Directory tab', 'admin',   'read/write'),
            ('Asset Directory', 'Save assets',                  'viewer',  'blocked'),
            ('Asset Directory', 'Save assets',                  'analyst', 'read/write'),
            ('Asset Directory', 'Save assets',                  'manager', 'read/write'),
            ('Asset Directory', 'Save assets',                  'admin',   'read/write'),
            ('Asset Directory', 'Archive assets',               'viewer',  'blocked'),
            ('Asset Directory', 'Archive assets',               'analyst', 'managerial approval'),
            ('Asset Directory', 'Archive assets',               'manager', 'read/write'),
            ('Asset Directory', 'Archive assets',               'admin',   'read/write'),
            ('Asset Directory', 'Delete assets',                'viewer',  'blocked'),
            ('Asset Directory', 'Delete assets',                'analyst', 'blocked'),
            ('Asset Directory', 'Delete assets',                'manager', 'admin approval'),
            ('Asset Directory', 'Delete assets',                'admin',   'read/write'),
            ('Asset Directory', 'Download CSV',                 'viewer',  'blocked'),
            ('Asset Directory', 'Download CSV',                 'analyst', 'read/write'),
            ('Asset Directory', 'Download CSV',                 'manager', 'read/write'),
            ('Asset Directory', 'Download CSV',                 'admin',   'read/write'),
            ('Asset Directory', 'Download JSON',                'viewer',  'blocked'),
            ('Asset Directory', 'Download JSON',                'analyst', 'read/write'),
            ('Asset Directory', 'Download JSON',                'manager', 'read/write'),
            ('Asset Directory', 'Download JSON',                'admin',   'read/write'),
            # myTickets Permissions
            ('myTickets', 'Viewable myTickets tab', 'viewer',  'read only'),
            ('myTickets', 'Viewable myTickets tab', 'analyst', 'read only'),
            ('myTickets', 'Viewable myTickets tab', 'manager', 'read only'),
            ('myTickets', 'Viewable myTickets tab', 'admin',   'read/write'),
            ('myTickets', 'Create tickets',         'viewer',  'read/write'),
            ('myTickets', 'Create tickets',         'analyst', 'read/write'),
            ('myTickets', 'Create tickets',         'manager', 'read/write'),
            ('myTickets', 'Create tickets',         'admin',   'read/write'),
            ('myTickets', 'Delete tickets',         'viewer',  'blocked'),
            ('myTickets', 'Delete tickets',         'analyst', 'blocked'),
            ('myTickets', 'Delete tickets',         'manager', 'read/write'),
            ('myTickets', 'Delete tickets',         'admin',   'read/write'),
            ('myTickets', 'Resolve tickets',        'viewer',  'blocked'),
            ('myTickets', 'Resolve tickets',        'analyst', 'managerial approval'),
            ('myTickets', 'Resolve tickets',        'manager', 'read/write'),
            ('myTickets', 'Resolve tickets',        'admin',   'read/write'),
            ('myTickets', 'Reassign tickets',       'viewer',  'blocked'),
            ('myTickets', 'Reassign tickets',       'analyst', 'blocked'),
            ('myTickets', 'Reassign tickets',       'manager', 'read/write'),
            ('myTickets', 'Reassign tickets',       'admin',   'read/write'),
            ('myTickets', 'Reopen tickets',         'viewer',  'blocked'),
            ('myTickets', 'Reopen tickets',         'analyst', 'managerial approval'),
            ('myTickets', 'Reopen tickets',         'manager', 'read/write'),
            ('myTickets', 'Reopen tickets',         'admin',   'read/write'),
            ('myTickets', 'Accept tickets',         'viewer',  'blocked'),
            ('myTickets', 'Accept tickets',         'analyst', 'read/write'),
            ('myTickets', 'Accept tickets',         'manager', 'read/write'),
            ('myTickets', 'Accept tickets',         'admin',   'read/write'),
            ('myTickets', 'Update ticket status',   'viewer',  'blocked'),
            ('myTickets', 'Update ticket status',   'analyst', 'read/write'),
            ('myTickets', 'Update ticket status',   'manager', 'read/write'),
            ('myTickets', 'Update ticket status',   'admin',   'read/write'),
            ('myTickets', 'Comment tickets',        'viewer',  'read only'),
            ('myTickets', 'Comment tickets',        'analyst', 'read/write'),
            ('myTickets', 'Comment tickets',        'manager', 'read/write'),
            ('myTickets', 'Comment tickets',        'admin',   'read/write'),
            ('myTickets', 'Fix comment tickets',    'viewer',  'blocked'),
            ('myTickets', 'Fix comment tickets',    'analyst', 'blocked'),
            ('myTickets', 'Fix comment tickets',    'manager', 'read/write'),
            ('myTickets', 'Fix comment tickets',    'admin',   'read/write'),
            ('myTickets', 'Download ticket log',    'viewer',  'blocked'),
            ('myTickets', 'Download ticket log',    'analyst', 'managerial approval'),
            ('myTickets', 'Download ticket log',    'manager', 'read/write'),
            ('myTickets', 'Download ticket log',    'admin',   'read/write'),
        ]
        conn.executemany(
            'INSERT INTO role_permissions (category, permission, role, access_level) VALUES (?, ?, ?, ?)',
            default_perms
        )
    conn.commit()

    conn.close()