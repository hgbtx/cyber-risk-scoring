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
            cpeName TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT,
            cpeData TEXT,
            cveData TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS archivedAssets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cpeName TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            archived TEXT,
            isArchived INTEGER DEFAULT 0,
            FOREIGN KEY (cpeName) REFERENCES assets(cpeName) ON DELETE CASCADE,
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
    
    conn.commit()

    conn.close()