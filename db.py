import sqlite3, json, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS assets (
            cpeName TEXT PRIMARY KEY,
            title TEXT,
            cpeData TEXT,
            cveData TEXT
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY,
            description TEXT,
            feature TEXT,
            created TEXT,
            resolved INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY,
            description TEXT,
            feature TEXT,
            created TEXT,
            resolved INTEGER DEFAULT 0,
            resolved_at TEXT DEFAULT ''
        );
    ''')
    conn.commit()
    conn.close()