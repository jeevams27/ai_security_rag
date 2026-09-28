"""Benchmark module: intentionally vulnerable Python code + safe code."""

import os
import sqlite3


DB_PATH = "app.db"
UPLOAD_DIR = "/var/app/uploads"


def find_user_vulnerable(username):
    """VULNERABLE (SQL-001): user input concatenated into SQL."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


def find_user_safe(username):
    """SAFE (SQL-001): parameterized query, no concatenation."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()


def read_upload_vulnerable(filename):
    """VULNERABLE (PATH-001): unsanitized user path joins the upload dir."""
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def read_upload_safe(filename):
    """SAFE (PATH-001): resolved path is confined to the upload dir."""
    base = os.path.realpath(UPLOAD_DIR)
    path = os.path.realpath(os.path.join(base, filename))
    if not path.startswith(base + os.sep):
        raise ValueError("path escapes permitted directory")
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()
