"""Migrate SQLite `scans` and `stats` into Postgres using `DATABASE_URL` env var.

Usage:
  Set `DATABASE_URL` in the environment (e.g. export DATABASE_URL=postgres://user:pw@host:5432/db)
  Then run: python migrate_sqlite_to_postgres.py
"""
import os
import sqlite3
from urllib.parse import urlparse

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise SystemExit('Please set DATABASE_URL environment variable pointing to Postgres')

SQLITE_DB = os.environ.get('SQLITE_DB', 'backend/cybersentinel.db')
if not os.path.exists(SQLITE_DB):
    raise SystemExit(f'SQLite DB not found at {SQLITE_DB}')

print('Reading from', SQLITE_DB)
conn = sqlite3.connect(SQLITE_DB)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

scans = cur.execute('SELECT * FROM scans ORDER BY id').fetchall()
stats = cur.execute('SELECT key, value FROM stats').fetchall()
conn.close()

print(f'Found {len(scans)} scans and {len(stats)} stats rows')

from sqlalchemy import create_engine, text

engine = create_engine(DATABASE_URL, future=True)
raw = engine.raw_connection()
pcur = raw.cursor()

try:
    # Ensure tables exist (simple schema compatible with backend)
    pcursor = pcur
    pcursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        url_hash TEXT NOT NULL,
        verdict TEXT NOT NULL,
        risk_score REAL NOT NULL,
        ml_score REAL,
        lr_score REAL,
        features TEXT,
        ai_analysis TEXT,
        ip_address TEXT,
        created_at TIMESTAMP WITH TIME ZONE
    )
    ''')
    pcursor.execute('''
    CREATE TABLE IF NOT EXISTS stats (
        key TEXT PRIMARY KEY,
        value BIGINT DEFAULT 0
    )
    ''')

    # Insert stats
    for r in stats:
        pcursor.execute("INSERT INTO stats (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (r['key'], int(r['value'])))

    # Insert scans
    for s in scans:
        pcursor.execute(
            "INSERT INTO scans (url, url_hash, verdict, risk_score, ml_score, lr_score, features, ai_analysis, ip_address, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (s['url'], s['url_hash'], s['verdict'], s['risk_score'], s['ml_score'], s['lr_score'], s['features'], s['ai_analysis'], s['ip_address'], s['created_at'])
        )

    raw.commit()
    print('Migration complete.')
finally:
    pcur.close()
    raw.close()
