
import sqlite3
from pathlib import Path

DATABASE_NAME = str(Path(__file__).resolve().parent / "trustvault.db")

def get_db_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    connection = get_db_connection()

    try:
        # 1. Users table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('admin', 'owner', 'viewer'))
            )
        """)

        # 2. Documents table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL UNIQUE,
                owner_id INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%d %H:%M:%S', 'now')),
                FOREIGN KEY (owner_id)
                    REFERENCES users(id)
            )
        """)

        # 3. Document permissions table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS document_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                granted_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%d %H:%M:%S', 'now')),
                UNIQUE(document_id, user_id),
                FOREIGN KEY (document_id)
                    REFERENCES documents(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (granted_by)
                    REFERENCES users(id)
            )
        """)

        # 4. Audit logs table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                document_id INTEGER,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%d %H:%M:%S', 'now')),
                FOREIGN KEY (user_id)
                    REFERENCES users(id),
                FOREIGN KEY (document_id)
                    REFERENCES documents(id)
                    ON DELETE SET NULL
            )
        """)

        connection.commit()
        print("TrustVault database initialized successfully!")

    except sqlite3.Error as error:
        connection.rollback()
        print("Database error:", error)
        raise

    finally:
        connection.close()


def add_audit_log(user_id, action, document_id=None):
    connection = get_db_connection()

    try:
        connection.execute("""
            INSERT INTO audit_logs (user_id, document_id, action)
            VALUES (?, ?, ?)
        """, (user_id, document_id, action))
        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_audit_logs():
    connection = get_db_connection()

    try:
        return connection.execute("""
            SELECT audit_logs.id,
                   users.username,
                   audit_logs.document_id,
                   audit_logs.action,
                   audit_logs.timestamp
            FROM audit_logs
            JOIN users ON users.id = audit_logs.user_id
            ORDER BY audit_logs.id DESC
        """).fetchall()

    finally:
        connection.close()


if __name__ == "__main__":
    init_db()

