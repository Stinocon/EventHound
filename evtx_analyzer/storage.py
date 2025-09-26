import os
import json
import sqlite3
from typing import Dict, Iterable

DB_PATH = os.path.join(os.getcwd(), 'outputs', 'events.db')


def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db() -> None:
    conn = get_conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                channel TEXT,
                event_id TEXT,
                computer TEXT,
                provider TEXT,
                record_id TEXT,
                user_sid TEXT,
                data_json TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_events(events: Iterable[Dict]) -> int:
    conn = get_conn()
    try:
        cur = conn.cursor()
        rows = [(
            e.get('timestamp'),
            e.get('channel'),
            str(e.get('event_id')) if e.get('event_id') is not None else None,
            e.get('computer'),
            e.get('provider'),
            str(e.get('record_id')) if e.get('record_id') is not None else None,
            e.get('user_sid'),
            json.dumps(e.get('data')) if e.get('data') is not None else None,
        ) for e in events]
        cur.executemany(
            """
            INSERT INTO events (timestamp, channel, event_id, computer, provider, record_id, user_sid, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows
        )
        conn.commit()
        return cur.rowcount or 0
    finally:
        conn.close()
