"""
VirusTotal Module — CleanDrop
==============================
WHAT THIS MODULE DOES:
    This is Layer 2 of CleanDrop's detection system.
    It sends the file's SHA256 hash to the VirusTotal API,
    which checks it against 70+ antivirus engines simultaneously.

    Think of it as asking 70 antivirus experts at once:
    "Have you seen this file before? Is it dangerous?"

    The more engines that flag it → the higher the risk.

RETURNS:
    status         : 'MALWARE' | 'SAFE' | 'CRITICAL' | 'ERROR'
    malicious_count: number of engines that flagged it
    total_engines  : total number of engines checked
    detection_rate : percentage of engines that flagged it
    score          : 0–100
    source         : 'VirusTotal'
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def check_virustotal(file_hash):
    """
    Query the VirusTotal API with a file hash.

    Detection thresholds:
        0 engines    → SAFE   (score: 0)
        1–5%         → LOW    (score: 15)
        6–10%        → MEDIUM (score: 30)
        11–20%       → MEDIUM (score: 50)
        21–50%       → HIGH   (score: 70)
        51–70%       → HIGH   (score: 82)
        >70%         → CRITICAL (score: 92)

    Non-detection statuses (not in DB, rate limited, etc.) → SAFE score: 0
    """
    if not file_hash:
        return {
            'status': 'ERROR',
            'malicious_count': 0,
            'total_engines': 0,
            'detection_rate': 'N/A',
            'score': 0,
            'source': 'VirusTotal'
        }

    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            rate = (malicious / total * 100) if total > 0 else 0

            # Determine status and score based on detection rate
            if malicious == 0:
                status, score = 'SAFE', 0
            elif rate <= 5:
                status, score = 'LOW', 15
            elif rate <= 10:
                status, score = 'MEDIUM', 30
            elif rate <= 20:
                status, score = 'MEDIUM', 50
            elif rate <= 50:
                status, score = 'HIGH', 70
            elif rate <= 70:
                status, score = 'HIGH', 82
            else:
                status, score = 'CRITICAL', 92

            return {
                'status': status,
                'malicious_count': malicious,
                'total_engines': total,
                'detection_rate': f"{malicious}/{total} engines ({round(rate, 1)}%)",
                'score': score,
                'source': 'VirusTotal'
            }

        elif response.status_code == 404:
            # Hash not found in VirusTotal database — not necessarily dangerous
            return {
                'status': 'SAFE',
                'malicious_count': 0,
                'total_engines': 0,
                'detection_rate': 'Not in VirusTotal DB',
                'score': 0,
                'source': 'VirusTotal'
            }

        elif response.status_code == 429:
            return {
                'status': 'SAFE',
                'malicious_count': 0,
                'total_engines': 0,
                'detection_rate': 'Rate limit reached',
                'score': 0,
                'source': 'VirusTotal'
            }

        else:
            return {
                'status': 'SAFE',
                'malicious_count': 0,
                'total_engines': 0,
                'detection_rate': 'N/A',
                'score': 0,
                'source': 'VirusTotal'
            }

    except requests.exceptions.RequestException:
        return {
            'status': 'SAFE',
            'malicious_count': 0,
            'total_engines': 0,
            'detection_rate': 'Connection error',
            'score': 0,
            'source': 'VirusTotal'
        }


if __name__ == '__main__':
    print(check_virustotal('PUT_REAL_HASH_HERE'))