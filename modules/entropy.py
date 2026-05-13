"""
Entropy Analysis Module — CleanDrop
=====================================
WHAT THIS MODULE DOES:
    This is Layer 3 of CleanDrop's detection system.
    It measures how random the bytes inside a file are (Shannon Entropy).

    Why does randomness matter?
    - Normal files (text, code) have LOW entropy — they have patterns.
    - Encrypted or packed malware has HIGH entropy — it looks like random noise.
    - Attackers encrypt malware to hide it from antivirus scanners.
    - High entropy = possible encryption = possible hidden malware.

    Exception: Images, videos, and compressed files (.jpg, .zip, etc.)
    naturally have high entropy — so we score them as SAFE regardless.

ENTROPY SCALE:
    < 5.0   → SAFE     (score: 0)   — plain text, structured data
    5.0–5.9 → LOW      (score: 10)  — slightly above normal
    6.0–6.9 → LOW      (score: 30)  — compressed or mixed content
    7.0–7.1 → MEDIUM   (score: 50)  — suspicious
    7.2–7.4 → HIGH     (score: 65)  — likely obfuscated
    7.5–7.6 → HIGH     (score: 75)  — likely packed/encrypted
    7.7–7.8 → CRITICAL (score: 85)  — strongly encrypted
    >= 7.9  → CRITICAL (score: 95)  — maximum randomness

RETURNS:
    entropy : float (the calculated entropy value)
    risk    : 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    score   : 0–95
    source  : 'Entropy Analysis'
    note    : (only for compressed files) explanation string
"""

import math
import os
from collections import Counter

COMPRESSED_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff',
    '.zip', '.gz', '.rar', '.7z', '.tar',
    '.mp3', '.mp4', '.avi', '.mov',
}


def calculate_entropy(file_path):
    """
    Calculate Shannon Entropy of a file's byte content.
    Returns a dict with entropy value, risk level, score, and source.
    """
    ext = os.path.splitext(file_path)[1].lower()

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if not data:
            return {'entropy': 0.0, 'risk': 'SAFE', 'score': 0, 'source': 'Entropy Analysis'}

        counter = Counter(data)
        total = len(data)
        entropy = -sum(
            (count / total) * math.log2(count / total)
            for count in counter.values()
        )
        entropy = round(entropy, 4)

        # Compressed/image formats — high entropy is normal, always SAFE
        if ext in COMPRESSED_EXTENSIONS:
            return {
                'entropy': entropy,
                'risk': 'SAFE',
                'score': 0,
                'source': 'Entropy Analysis',
                'note': 'Compressed format — high entropy is expected'
            }

        # Standard entropy scoring
        if entropy < 5.0:
            risk, score = 'SAFE',     0
        elif entropy < 6.0:
            risk, score = 'LOW',      10
        elif entropy < 7.0:
            risk, score = 'LOW',      30
        elif entropy < 7.2:
            risk, score = 'MEDIUM',   50
        elif entropy < 7.5:
            risk, score = 'HIGH',     65
        elif entropy < 7.7:
            risk, score = 'HIGH',     75
        elif entropy < 7.9:
            risk, score = 'CRITICAL', 85
        else:
            risk, score = 'CRITICAL', 95

        return {
            'entropy': entropy,
            'risk': risk,
            'score': score,
            'source': 'Entropy Analysis'
        }

    except FileNotFoundError:
        return {'entropy': 0.0, 'risk': 'SAFE', 'score': 0, 'source': 'Entropy Analysis'}


if __name__ == '__main__':
    test_file = 'ENTER_FILENAME_HERE.txt'
    if os.path.exists(test_file):
        print(calculate_entropy(test_file))
    else:
        print("Entropy module ready. No test file specified.")