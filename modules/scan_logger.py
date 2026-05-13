"""
Scan Logger Module — CleanDrop
================================
Logs every file and URL scan to the Supabase scan_logs table.
Failures are silently caught — logging never interrupts a scan.
"""

import os
from dotenv import load_dotenv

load_dotenv()

_client = None


def _get_client():
    global _client
    if _client is None:
        from supabase import create_client
        url = os.environ.get("SUPABASE_URL", "")
        key = os.environ.get("SUPABASE_KEY", "")
        if url and key:
            _client = create_client(url, key)
    return _client


def log_file_scan(filename, score, risk_level, hash_result, vt_result,
                  entropy_result, heuristic_result, dlp_result, sig_result):
    try:
        client = _get_client()
        if not client:
            return

        client.table("scan_logs").insert({
            "scan_type": "file",
            "target":    filename,
            "risk_level": risk_level,
            "score":     score,
            "details": {
                "hash":       hash_result.get("status"),
                "virustotal": vt_result.get("status"),
                "vt_rate":    vt_result.get("detection_rate"),
                "entropy":    entropy_result.get("risk"),
                "heuristics": heuristic_result.get("risk"),
                "indicators": heuristic_result.get("total_indicators", 0),
                "dlp":        "Detected" if dlp_result.get("pii_found") else "Clean",
                "pii_types":  list(dlp_result.get("findings", {}).keys()),
                "signature":  "Spoofed" if sig_result.get("is_spoofed") else "Clean",
            },
        }).execute()

    except Exception as e:
        print(f"[ScanLogger] file log error: {e}")


def log_url_scan(url, status, score, source, threats=None):
    try:
        client = _get_client()
        if not client:
            return

        client.table("scan_logs").insert({
            "scan_type":  "url",
            "target":     url,
            "risk_level": status,
            "score":      score,
            "details": {
                "source":  source,
                "threats": threats or [],
            },
        }).execute()

    except Exception as e:
        print(f"[ScanLogger] url log error: {e}")
