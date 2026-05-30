"""
RPM Encrypter - Activity Logging Module
=======================================

Handles append-only logging of user actions (encryption, decryption, etc.)
using a lightweight local SQLite database.

Security Constraints:
- No passwords, keys, or recovery phrases are ever logged.
- File contents are never logged.
- Only non-sensitive metadata (action type, filename, success/fail status) is stored.
"""

import sqlite3
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

DB_PATH = Path.home() / ".rpm_encrypter_activity.db"

class ActivityLogger:
    """
    Thread-safe SQLite wrapper for the activity feed.
    """

    def __init__(self, enabled: bool = True):
        # F4 FIX: When logging is disabled, the logger still initializes (so the
        # schema exists if logging is re-enabled at runtime) but log_event writes
        # nothing to disk. Defaults to True to preserve existing behavior.
        self.enabled = enabled
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Create the database and tables if they don't exist."""
        try:
            with self._lock:
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS activity (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            action TEXT NOT NULL,
                            filename TEXT NOT NULL,
                            status TEXT NOT NULL,
                            details TEXT
                        )
                    """)
                    conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to initialize activity DB: %s", e)

    def log_event(self, action: str, filename: str, status: str, details: str = "") -> None:
        """
        Log a new event to the activity feed.

        Args:
            action: E.g., 'Encrypt', 'Decrypt', 'Re-Key', 'Inspect'.
            filename: The target filename (not the full path if possible, or sanitized).
            status: 'Success', 'Failed', 'Warning'.
            details: Optional extra information (e.g., error messages). Do NOT include sensitive data.
        """
        # F4 FIX: Respect the disabled state — write nothing when logging is off.
        if not self.enabled:
            return
        timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
        try:
            with self._lock:
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO activity (timestamp, action, filename, status, details) VALUES (?, ?, ?, ?, ?)",
                        (timestamp, action, filename, status, details)
                    )
                    conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to log activity event: %s", e)

    def get_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve recent activity logs, ordered by newest first.
        """
        try:
            with self._lock:
                with sqlite3.connect(DB_PATH) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT timestamp, action, filename, status, details FROM activity ORDER BY id DESC LIMIT ?",
                        (limit,)
                    )
                    rows = cursor.fetchall()
                    return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Failed to retrieve activity logs: %s", e)
            return []

    def clear_logs(self) -> None:
        """Clear all activity logs."""
        try:
            with self._lock:
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM activity")
                    conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to clear activity logs: %s", e)
