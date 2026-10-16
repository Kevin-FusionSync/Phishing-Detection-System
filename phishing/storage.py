import json
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    input_type TEXT NOT NULL,
    sender TEXT,
    subject TEXT,
    url TEXT,
    preview TEXT,
    ml_probability REAL,
    rule_score REAL,
    risk_score REAL,
    risk_level TEXT,
    indicators TEXT
)
"""


def _connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA)
    return conn


def save_result(result, input_type, sender="", subject="", url="", text="", path=DB_PATH):
    preview = " ".join((text or "").split())[:200]
    row = (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        input_type,
        sender,
        subject,
        url,
        preview,
        result.ml_probability,
        result.rule_score,
        result.risk_score,
        result.risk_level,
        json.dumps([f.name for f in result.indicators]),
    )
    conn = _connect(path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO analyses (created_at, input_type, sender, subject, url, preview, "
                "ml_probability, rule_score, risk_score, risk_level, indicators) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
    finally:
        conn.close()


def load_history(path=DB_PATH):
    conn = _connect(path)
    try:
        df = pd.read_sql_query("SELECT * FROM analyses ORDER BY id DESC", conn)
    finally:
        conn.close()
    if not df.empty:
        df["indicators"] = df["indicators"].map(lambda s: ", ".join(json.loads(s or "[]")))
    return df


def clear_history(path=DB_PATH):
    conn = _connect(path)
    try:
        with conn:
            conn.execute("DELETE FROM analyses")
    finally:
        conn.close()
