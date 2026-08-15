# db.py
import sqlite3
import os

# Database file name (will be created in the current working directory)
DB_PATH = 'waf_logs.db'


def _get_connection():
    """Create and return a new SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # allow dict-like access
    return conn


def init_db():
    """
    Create the logs table if it doesn't exist.
    Call once at application startup.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            action TEXT NOT NULL CHECK (action IN ('ALLOWED', 'BLOCKED')),
            attack_type TEXT,
            matched_pattern TEXT
        )
    ''')
    conn.commit()
    conn.close()


def log_request(timestamp, client_ip, method, path, action,
                attack_type=None, matched_pattern=None):
    """
    Insert a log entry into the logs table.

    All values are passed as parameters to avoid SQL injection.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, client_ip, method, path, action,
                          attack_type, matched_pattern)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, client_ip, method, path, action, attack_type, matched_pattern))
    conn.commit()
    conn.close()


def get_recent_logs(limit=50):
    """
    Return the most recent log entries as a list of dictionaries,
    newest first.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, client_ip, method, path, action,
               attack_type, matched_pattern
        FROM logs
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_stats():
    """
    Return aggregated statistics about logged requests.

    Returns:
        dict with keys:
            total: total number of requests
            allowed: number of ALLOWED requests
            blocked: number of BLOCKED requests
            sqli: number of SQL injection attacks blocked
            xss: number of XSS attacks blocked
            traversal: number of directory traversal attacks blocked
            command_injection: number of command injection attacks blocked
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM logs')
    total = cursor.fetchone()[0]

    cursor.execute('''
        SELECT
            COUNT(CASE WHEN action = 'ALLOWED' THEN 1 END) AS allowed,
            COUNT(CASE WHEN action = 'BLOCKED' THEN 1 END) AS blocked,
            COUNT(CASE WHEN attack_type = 'sql_injection' THEN 1 END) AS sqli,
            COUNT(CASE WHEN attack_type = 'xss' THEN 1 END) AS xss,
            COUNT(CASE WHEN attack_type = 'directory_traversal' THEN 1 END) AS traversal,
            COUNT(CASE WHEN attack_type = 'command_injection' THEN 1 END) AS command_injection
        FROM logs
    ''')
    row = cursor.fetchone()
    conn.close()

    return {
        "total": total,
        "allowed": row[0],
        "blocked": row[1],
        "sqli": row[2],
        "xss": row[3],
        "traversal": row[4],
        "command_injection": row[5]
    }