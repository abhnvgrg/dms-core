import sqlite3
import os
from contextlib import contextmanager

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "storage", "evidence.db")


def init_db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    with open_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                extracted_text TEXT,
                redacted_text TEXT,
                ocr_status TEXT DEFAULT 'pending'
            )
            """
        )
        conn.commit()


@contextmanager
def open_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
