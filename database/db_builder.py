"""
Database Builder Module — CleanDrop
-------------------------------------
Populates the Supabase malware hash table
using a SHA256 hash list (e.g., from MalwareBazaar).

Run once to seed the database:
    python database/db_builder.py

Requires SUPABASE_URL and SUPABASE_KEY in .env
"""

import os
from dotenv import load_dotenv

load_dotenv()


# ── COMMENTED OUT: old SQLite builder ────────────────────────────────────────
# import sqlite3
#
# def build_database_sqlite(hashes_file_path):
#     os.makedirs('database', exist_ok=True)
#     conn = sqlite3.connect('database/malware_hashes.db')
#     cursor = conn.cursor()
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS hashes (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             hash TEXT NOT NULL UNIQUE
#         )
#     ''')
#     added = 0
#     try:
#         with open(hashes_file_path, 'r') as f:
#             for line in f:
#                 h = line.strip()
#                 if len(h) == 64 and not h.startswith('#'):
#                     cursor.execute(
#                         'INSERT OR IGNORE INTO hashes (hash) VALUES (?)', (h,)
#                     )
#                     added += 1
#     except FileNotFoundError:
#         print(f'File not found: {hashes_file_path}')
#         conn.close()
#         return
#     conn.commit()
#     conn.close()
#     print(f'Database ready — {added} malware hashes stored')
#
# if __name__ == '__main__':
#     build_database_sqlite('database/full_sha256.txt')
# ─────────────────────────────────────────────────────────────────────────────


def build_database(hashes_file_path, batch_size=500):
    """
    Read a SHA256 hash list and upsert all hashes into the Supabase 'hashes' table.

    The Supabase table must exist with the following schema:
        CREATE TABLE hashes (
            id   BIGSERIAL PRIMARY KEY,
            hash TEXT NOT NULL UNIQUE
        );

    Args:
        hashes_file_path : path to a text file with one SHA256 hash per line
        batch_size       : number of rows to upsert per API call (default 500)
    """
    from supabase import create_client

    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_SERVICE_KEY") or os.environ.get("SUPABASE_KEY", "")
    if not url or not key:
        print("Error: SUPABASE_URL and SUPABASE_KEY must be set in .env")
        return

    client = create_client(url, key)

    added = 0
    batch = []

    try:
        with open(hashes_file_path, 'r') as f:
            for line in f:
                h = line.strip()
                if len(h) == 64 and not h.startswith('#'):
                    batch.append({"hash": h})
                    added += 1

                    if len(batch) >= batch_size:
                        client.table("hashes").upsert(batch, on_conflict="hash").execute()
                        batch = []

        # flush remaining
        if batch:
            client.table("hashes").upsert(batch, on_conflict="hash").execute()

    except FileNotFoundError:
        print(f'File not found: {hashes_file_path}')
        return

    print(f'Done — {added} malware hashes pushed to Supabase')


if __name__ == '__main__':
    build_database('database/full_sha256.txt')
