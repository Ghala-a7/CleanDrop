"""
Heuristic Detection Module — CleanDrop
========================================
...
"""

import os

def heuristic_scan(file_path):

    SUSPICIOUS_INDICATORS = {
        'System Commands': [
            b'cmd.exe', b'powershell', b'WScript.Shell',
            b'regsvr32', b'mshta.exe', b'wmic'
        ],
        'Code Injection': [
            b'CreateRemoteThread', b'VirtualAlloc',
            b'WriteProcessMemory', b'NtCreateThreadEx'
        ],
        'Network Activity': [
            b'socket', b'WSAStartup', b'InternetOpen',
            b'URLDownloadToFile', b'WinHttpOpen'
        ],
        'Obfuscation': [
            b'base64_decode', b'eval(', b'exec(',
            b'fromCharCode', b'unescape('
        ],
        'Registry Modification': [
            b'RegCreateKey', b'RegSetValue', b'CurrentVersion\\Run'
        ]
    }

    HIGH_SEVERITY   = {'Code Injection', 'Registry Modification'}
    MEDIUM_SEVERITY = {'System Commands', 'Network Activity'}

    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        findings    = {}
        total_found = 0

        for category, indicators in SUSPICIOUS_INDICATORS.items():
            found_here = []
            for indicator in indicators:
                if indicator in content:
                    found_here.append(indicator.decode('utf-8', errors='ignore'))
                    total_found += 1
            if found_here:
                findings[category] = found_here

        # ── Base score by indicator count ──
        if total_found == 0:
            risk, score = 'SAFE',     0
        elif total_found == 1:
            risk, score = 'LOW',      20
        elif total_found == 2:
            risk, score = 'MEDIUM',   45
        elif total_found <= 4:
            risk, score = 'HIGH',     65
        else:
            risk, score = 'CRITICAL', 88

        # ── Severity boost ──
        if total_found > 0:
            triggered = set(findings.keys())
            if triggered & HIGH_SEVERITY:
                score = min(score + 15, 100)
            if triggered & MEDIUM_SEVERITY:
                score = min(score + 8, 100)

        # ── Re-derive risk label from FINAL boosted score ──
        # This ensures the table label always matches the number
        if score == 0:
            risk = 'SAFE'
        elif score <= 20:
            risk = 'LOW'
        elif score <= 50:
            risk = 'MEDIUM'
        elif score <= 80:
            risk = 'HIGH'
        else:
            risk = 'CRITICAL'

        return {
            'findings':          findings,
            'total_indicators':  total_found,
            'risk':              risk,
            'score':             score,
            'source':            'Heuristic Detection'
        }

    except FileNotFoundError:
        return {
            'findings':          {},
            'total_indicators':  0,
            'risk':              'SAFE',
            'score':             0,
            'source':            'Heuristic Detection'
        }


if __name__ == '__main__':
    test_file = 'ENTER_FILENAME_HERE.txt'
    if os.path.exists(test_file):
        result = heuristic_scan(test_file)
        print(f"Risk: {result['risk']} | Score: {result['score']} | Indicators: {result['total_indicators']}")
        print(f"Findings: {result['findings']}")
    else:
        print("Heuristic module ready. No test file specified.")