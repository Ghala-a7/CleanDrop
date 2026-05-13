"""
Hash Engine Module — CleanDrop
===============================
WHAT THIS MODULE DOES:
    This is Layer 1 of CleanDrop's detection system.
    It generates a SHA256 fingerprint (hash) of the uploaded file,
    then checks if that fingerprint exists in the Supabase malware database.

    Think of it like a criminal fingerprint database:
    - Every known malware file has a unique fingerprint stored in the DB.
    - If the uploaded file's fingerprint matches → MALWARE.
    - If it doesn't match → SAFE (not in database).

RETURNS:
    status : 'MALWARE' | 'SAFE' | 'ERROR'
    source : 'Supabase Database'
    score  : 100 (malware) | 0 (safe/error)
"""

import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

# ── Supabase client (lazy-initialised to avoid import cost on every scan) ──
_supabase_client = None

def _get_client():
    global _supabase_client
    if _supabase_client is None:
        from supabase import create_client
        url = os.environ.get("SUPABASE_URL", "")
        key = os.environ.get("SUPABASE_KEY", "")
        if not url or not key:
            raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
        _supabase_client = create_client(url, key)
    return _supabase_client


# ── COMMENTED OUT: old SQLite connection ─────────────────────────────────────
# import sqlite3
#
# def check_hash_in_database_sqlite(file_hash):
#     if not file_hash:
#         return {'status': 'ERROR', 'source': 'Local Database', 'score': 0}
#     try:
#         conn = sqlite3.connect('database/malware_hashes.db')
#         cursor = conn.cursor()
#         cursor.execute('SELECT hash FROM hashes WHERE hash = ?', (file_hash,))
#         result = cursor.fetchone()
#         conn.close()
#         if result:
#             return {'status': 'MALWARE', 'source': 'Local Database', 'score': 100}
#         else:
#             return {'status': 'SAFE', 'source': 'Local Database', 'score': 0}
#     except Exception:
#         return {'status': 'SAFE', 'source': 'Local Database', 'score': 0}
# ─────────────────────────────────────────────────────────────────────────────


def get_file_hash(file_path):
    """
    Generate the SHA256 hash of a file.
    Reads in 4KB chunks to handle large files without loading them fully into memory.
    Returns the hash as a 64-character hex string, or None if the file doesn't exist.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None


def check_hash_in_database(file_hash):
    """
    Check if a given SHA256 hash exists in the Supabase malware database.

    Table: hashes — columns: id (int), hash (text, unique)

    Returns a dict with:
        status : 'MALWARE' if found, 'SAFE' if not found, 'ERROR' if invalid input
        source : always 'Supabase Database'
        score  : 100 if malware, 0 otherwise
    """
    if not file_hash:
        return {'status': 'ERROR', 'source': 'Supabase Database', 'score': 0}

    try:
        client = _get_client()
        response = (
            client.table("hashes")
            .select("hash")
            .eq("hash", file_hash)
            .execute()
        )
        if response.data:
            return {'status': 'MALWARE', 'source': 'Supabase Database', 'score': 100}
        return {'status': 'SAFE', 'source': 'Supabase Database', 'score': 0}

    except Exception as e:
        print(f"[HashEngine] Supabase error: {e}")
        return {'status': 'SAFE', 'source': 'Supabase Database', 'score': 0}


if __name__ == '__main__':
    test_hash = get_file_hash('test.txt')
    print("Hash:", test_hash)
    db_result = check_hash_in_database(test_hash)
    print("Database Check:", db_result)
