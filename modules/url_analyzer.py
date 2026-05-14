import os
import requests
import re
import base64
import time
from dotenv import load_dotenv

load_dotenv()

DEBUG_CLOUDFLARE = False


def _keys():
    """Read API keys at call time so Streamlit Cloud secrets are always picked up."""
    return {
        "google":       os.environ.get("GOOGLE_API_KEY", ""),
        "virustotal":   os.environ.get("VIRUSTOTAL_API_KEY", ""),
        "cf_token":     os.environ.get("CLOUDFLARE_TOKEN", ""),
        "cf_account":   os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""),
    }


# =============================================================================
# STEP 1 — Input Normalization
# =============================================================================
def normalize_url(raw_input):
    raw = raw_input.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if "." in raw and " " not in raw:
        return "https://" + raw
    return raw


def is_valid_url(url):
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))


def extract_domain(url):
    domain = re.sub(r'^https?://', '', url)
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


# =============================================================================
# STEP 2 — Google Safe Browsing
# =============================================================================
def check_google_safe_browsing(url):
    api_url = (
        f'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        f'?key={_keys()["google"]}'
    )
    payload = {
        'client': {'clientId': 'cleandrop', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes':      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            'platformTypes':    ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries':    [{'url': url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if not data:
                return {'status': 'NOT_FOUND', 'confirmed': False, 'source': 'Google Safe Browsing'}
            threats = [m['threatType'] for m in data.get('matches', [])]
            return {'status': 'MALICIOUS', 'confirmed': False, 'threats': threats, 'source': 'Google Safe Browsing'}
        return {'status': 'ERROR', 'confirmed': False, 'source': 'Google Safe Browsing'}
    except requests.exceptions.RequestException:
        return {'status': 'CONNECTION_ERROR', 'confirmed': False, 'source': 'Google Safe Browsing'}


# =============================================================================
# STEP 3 — VirusTotal URL Check
# =============================================================================
def check_virustotal_url(url):
    try:
        url_id   = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url   = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers  = {"x-apikey": _keys()["virustotal"]}
        response = requests.get(vt_url, headers=headers, timeout=15)
 
        if response.status_code == 200:
            data       = response.json()
            attrs      = data["data"]["attributes"]
            stats      = attrs["last_analysis_stats"]
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            total      = sum(stats.values())
            flagged    = malicious + suspicious
 
            # ── NEW: Extract actual threat category names from engine results ──
            # Each engine returns its own verdict — we collect the category names
            threat_categories = set()
            analysis_results  = attrs.get("last_analysis_results", {})
 
            for engine_name, engine_result in analysis_results.items():
                if engine_result.get("category") in ("malicious", "phishing", "suspicious"):
                    # Engine gave a specific category label — collect it
                    result_label = engine_result.get("result", "")
                    if result_label and result_label.lower() not in (
                        "malicious", "suspicious", "clean", "unrated", "none", ""
                    ):
                        threat_categories.add(result_label)
 
            # ── Normalize threat category names ──
            # Different engines use different names for the same threat
            # We map them to clean readable labels
            normalized_threats = set()
            for label in threat_categories:
                lower = label.lower()
                if any(w in lower for w in ["phish", "phishing"]):
                    normalized_threats.add("Phishing")
                elif any(w in lower for w in ["malware", "malicious"]):
                    normalized_threats.add("Malware")
                elif any(w in lower for w in ["spam", "scam"]):
                    normalized_threats.add("Spam/Scam")
                elif any(w in lower for w in ["trojan"]):
                    normalized_threats.add("Trojan")
                elif any(w in lower for w in ["ransomware"]):
                    normalized_threats.add("Ransomware")
                elif any(w in lower for w in ["botnet", "bot"]):
                    normalized_threats.add("Botnet")
                elif any(w in lower for w in ["cryptomin"]):
                    normalized_threats.add("Cryptomining")
                else:
                    if len(label) < 40:   # avoid long engine-specific strings
                        normalized_threats.add(label)
 
            # Use normalized threats if found, otherwise generic label
            threat_list = list(normalized_threats) if normalized_threats else []
 
            if malicious >= 3:
                return {
                    'status':         'MALICIOUS',
                    'confirmed':      False,
                    'malicious':      malicious,
                    'suspicious':     suspicious,
                    'total_engines':  total,
                    'detection_rate': f"{flagged}/{total}",
                    'score':          min(70 + (malicious * 3), 100),
                    'threats':        threat_list,      # ← actual threat types now
                    'source':         'VirusTotal'
                }
            elif malicious >= 2:
                return {
                    'status':         'SUSPICIOUS',
                    'confirmed':      False,
                    'malicious':      malicious,
                    'suspicious':     suspicious,
                    'total_engines':  total,
                    'detection_rate': f"{flagged}/{total}",
                    'score':          50,
                    'threats':        threat_list,
                    'source':         'VirusTotal'
                }
            elif harmless >= 50:
                return {
                    'status':    'KNOWN_SAFE',
                    'confirmed': True,
                    'harmless':  harmless,
                    'total':     total,
                    'score':     0,
                    'source':    'VirusTotal'
                }
            return {'status': 'NOT_FOUND', 'confirmed': False, 'score': 0, 'source': 'VirusTotal'}
 
        elif response.status_code == 404:
            return _submit_and_retry(url)
        elif response.status_code == 429:
            return {'status': 'RATE_LIMITED', 'confirmed': False, 'score': 0, 'source': 'VirusTotal'}
        return {'status': 'ERROR', 'confirmed': False, 'score': 0, 'source': 'VirusTotal'}
 
    except requests.exceptions.RequestException:
        return {'status': 'CONNECTION_ERROR', 'confirmed': False, 'score': 0, 'source': 'VirusTotal'}

def _submit_and_retry(url):
    # When a URL is not in VirusTotal, we submit it for scanning
    # but we do NOT wait and retry — this causes false SAFE results
    # Instead we just return NOT_FOUND so other layers decide
    try:
        headers  = {"x-apikey": _keys()["virustotal"]}
        requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}, timeout=15
        )
        # Submitted for future scanning — but we treat as NOT_FOUND now
        return {'status': 'NOT_FOUND', 'confirmed': False, 'score': 0, 'source': 'VirusTotal'}
    except requests.exceptions.RequestException:
        return {'status': 'CONNECTION_ERROR', 'confirmed': False, 'score': 0, 'source': 'VirusTotal'}
        
# =============================================================================
# STEP 4 — Cloudflare (two endpoints combined)
# =============================================================================
def check_cloudflare_radar(url):
    k       = _keys()
    domain  = extract_domain(url)
    headers = {
        "Authorization": f"Bearer {k['cf_token']}",
        "Content-Type":  "application/json"
    }

    DANGEROUS_KEYWORDS = [
        "spyware", "malware", "phish", "botnet", "ransomware",
        "cryptomin", "command and control", "social engineering",
        "unauthorized proxy", "anonymous proxy", "proxy avoidance",
        "trojan", "adware", "keylogger", "rootkit", "worm",
        "security threat", "threat",
    ]
    SUSPICIOUS_KEYWORDS = [
        "newly observed", "newly registered", "dynamic dns", "parked",
    ]
    SAFE_CATEGORY_KEYWORDS = [
    "search engine", "social network", "business", "educational",
    "government", "health", "news", "shopping", "technology",
    "financial", "email", "entertainment", "travel", "sports",
    "reference", "computer", "web hosting", "instant messenger",
    "content server", "video", "streaming", "media", "music",
    "social media", "online communities", "fashion", "food",
    "games", "real estate", "dating", "auctions", "job search",
    ]

    all_labels = set()

    # ── Endpoint A: Radar Ranking ──
    radar_url = f"https://api.cloudflare.com/client/v4/radar/ranking/domain/{domain}"
    try:
        resp_a = requests.get(radar_url, headers=headers, timeout=10)
        if DEBUG_CLOUDFLARE:
            print(f"\n[DEBUG] Endpoint A status: {resp_a.status_code}")
        if resp_a.status_code == 200:
            _extract_labels(resp_a.json().get("result", {}), all_labels)
    except requests.exceptions.RequestException:
        pass

    # ── Endpoint B: Intel Domain ──
    if k['cf_account'] and k['cf_account'] != 'YOUR_ACCOUNT_ID':
        intel_url = (
            f"https://api.cloudflare.com/client/v4/accounts/"
            f"{k['cf_account']}/intel/domain?domain={domain}"
        )
        try:
            resp_b = requests.get(intel_url, headers=headers, timeout=10)
            if DEBUG_CLOUDFLARE:
                print(f"[DEBUG] Endpoint B status: {resp_b.status_code}")
            if resp_b.status_code == 200:
                _extract_labels(resp_b.json().get("result", {}), all_labels)
        except requests.exceptions.RequestException:
            pass

    if DEBUG_CLOUDFLARE:
        print(f"[DEBUG] All extracted labels: {all_labels}")

    if not all_labels:
        return {'status': 'NOT_FOUND', 'confirmed': False, 'score': 0, 'source': 'Cloudflare Radar'}

    # ── Check dangerous (case-insensitive keyword match) ──
    threats_found = {
        label for label in all_labels
        if any(kw in label.lower() for kw in DANGEROUS_KEYWORDS)
    }
    if threats_found:
        return {
            'status':     'MALICIOUS',
            'confirmed':  False,
            'threats':    list(threats_found),
            'categories': list(all_labels),
            'score':      90,
            'source':     'Cloudflare Radar'
        }

    # ── Check suspicious ──
    suspicious_found = {
        label for label in all_labels
        if any(kw in label.lower() for kw in SUSPICIOUS_KEYWORDS)
    }
    if suspicious_found:
        return {
            'status':     'SUSPICIOUS',
            'confirmed':  False,
            'threats':    list(suspicious_found),
            'categories': list(all_labels),
            'score':      40,
            'source':     'Cloudflare Radar'
        }

    # ── Check confirmed safe ──
    safe_found = {
        label for label in all_labels
        if any(kw in label.lower() for kw in SAFE_CATEGORY_KEYWORDS)
    }
    if safe_found:
        return {
            'status':     'KNOWN_SAFE',
            'confirmed':  True,
            'categories': list(all_labels),
            'score':      0,
            'source':     'Cloudflare Radar'
        }

    return {
        'status':     'NOT_FOUND',
        'confirmed':  False,
        'categories': list(all_labels),
        'score':      0,
        'source':     'Cloudflare Radar'
    }


def _extract_labels(data_dict, label_set):
    """
    THE FIX: now checks BOTH 'risk_type' (singular) AND 'risk_types' (plural)
    because Cloudflare Intel API uses 'risk_type' not 'risk_types'
    """
    if not isinstance(data_dict, dict):
        return

    # ── FIXED: added 'risk_type' singular to the list ──
    for field in (
        "content_categories",
        "risk_types",
        "risk_type",          # ← THIS was the missing field causing the bug
        "categories",
        "inherited_content_categories",
        "inherited_risk_types",
        "security_categories",
        "threat_types",
    ):
        items = data_dict.get(field, [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    for key in ("name", "superCategoryName", "displayName", "description"):
                        val = item.get(key)
                        if val and isinstance(val, str) and not val.isdigit():
                            label_set.add(val)
                elif isinstance(item, str):
                    label_set.add(item)
        elif isinstance(items, str):
            label_set.add(items)

    # Recurse into nested dicts
    for key, val in data_dict.items():
        if isinstance(val, dict):
            _extract_labels(val, label_set)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _extract_labels(item, label_set)


# =============================================================================
# STEP 5 — MAIN FUNCTION
# =============================================================================
def check_url(raw_input):
    """
    FIXED: Checks ALL THREE databases always.
    Even if Google finds a match, we still check VT and Cloudflare.
    Final result combines findings from all sources that detected a threat.
    """
    url = normalize_url(raw_input)
 
    if not is_valid_url(url):
        return {
            'status':  'INVALID_URL',
            'score':   0,
            'message': 'Please enter a valid URL like "https://example.com" or just "example.com"'
        }
 
    sources_checked  = []
    suspicious_info  = None
    confirmed_safe   = False
 
    # ── Store results from all three layers ──
    all_threats      = []    # collect threats from ALL databases
    all_sources      = []    # collect sources that found threats
    malicious_layers = []    # layers that confirmed MALICIOUS
 
    # ════════════════════════════════════════
    # Layer 1: Google Safe Browsing
    # ════════════════════════════════════════
    google = check_google_safe_browsing(url)
    sources_checked.append('Google Safe Browsing')
 
    if google['status'] == 'MALICIOUS':
        g_threats = google.get('threats', [])
        # Google returns codes like SOCIAL_ENGINEERING → map to readable names
        readable_google = []
        for t in g_threats:
            if t == 'SOCIAL_ENGINEERING':
                readable_google.append('Phishing')
            elif t == 'MALWARE':
                readable_google.append('Malware')
            elif t == 'UNWANTED_SOFTWARE':
                readable_google.append('Unwanted Software')
            else:
                readable_google.append(t)
        all_threats.extend(readable_google)
        all_sources.append('Google Safe Browsing')
        malicious_layers.append('Google Safe Browsing')
        # ← NO early return — continue checking other layers
 
    # ════════════════════════════════════════
    # Layer 2: VirusTotal
    # ════════════════════════════════════════
    vt = check_virustotal_url(url)
    sources_checked.append('VirusTotal')
 
    if vt['status'] == 'MALICIOUS':
        vt_threats = vt.get('threats', [])
        if not vt_threats:
            vt_threats = [f"Detected by {vt.get('malicious', 0)} engines"]
        all_threats.extend(vt_threats)
        all_sources.append(
            f"VirusTotal ({vt.get('malicious', 0)}/{vt.get('total_engines', 0)} engines)"
        )
        malicious_layers.append('VirusTotal')
 
    elif vt['status'] == 'SUSPICIOUS':
        suspicious_info = vt
 
    if vt.get('confirmed') is True:
        confirmed_safe = True
 
    # ════════════════════════════════════════
    # Layer 3: Cloudflare Radar
    # ════════════════════════════════════════
    cf = check_cloudflare_radar(url)
    sources_checked.append('Cloudflare Radar')
 
    if cf['status'] == 'MALICIOUS':
        cf_threats = cf.get('threats', [])
        all_threats.extend(cf_threats)
        all_sources.append('Cloudflare Radar')
        malicious_layers.append('Cloudflare Radar')
 
    elif cf['status'] == 'SUSPICIOUS' and not suspicious_info:
        suspicious_info = cf
 
    if cf.get('confirmed') is True:
        confirmed_safe = True
 
    # ════════════════════════════════════════
    # FINAL DECISION — based on ALL layers
    # ════════════════════════════════════════
 
    # If ANY layer confirmed MALICIOUS → return combined result
    if malicious_layers:
        # Remove duplicate threat names
        unique_threats = list(dict.fromkeys(all_threats))
 
        # Build detection summary showing ALL databases that found it
        if len(malicious_layers) > 1:
            source_summary = ' + '.join(malicious_layers)
            message = (
                f"Confirmed malicious by {len(malicious_layers)} databases: "
                f"{source_summary}"
            )
        else:
            source_summary = malicious_layers[0]
            message = f"Flagged by {source_summary}"

        return {
            'status':          'MALICIOUS',
            'score':           100 if len(malicious_layers) > 1 else cf.get('score', vt.get('score', 90)),
            'threats':         unique_threats,
            'detection_rate':  vt.get('detection_rate', 'N/A') if vt['status'] == 'MALICIOUS' else 'N/A',
            'source':          source_summary,
            'all_sources':     all_sources,
            'databases_count': len(malicious_layers),
            'message':         message
        }
 
    # Return SUSPICIOUS
    if suspicious_info:
        return {
            'status':         'SUSPICIOUS',
            'score':          50,
            'detection_rate': suspicious_info.get('detection_rate', 'N/A'),
            'threats':        suspicious_info.get('threats', []),
            'source':         suspicious_info.get('source', ''),
            'message':        'Flagged as suspicious by one or more security databases'
        }
 
    # SAFE — confirmed by Cloudflare category
    if cf_confirmed := cf.get('confirmed') is True:
        return {
            'status':  'SAFE',
            'score':   0,
            'source':  ' + '.join(sources_checked),
            'message': 'No threats detected — URL confirmed as legitimate by Cloudflare'
        }
 
    # SAFE — confirmed by VirusTotal AND Cloudflare knows the domain
    if vt.get('confirmed') is True and cf['status'] != 'NOT_FOUND':
        return {
            'status':  'SAFE',
            'score':   0,
            'source':  ' + '.join(sources_checked),
            'message': 'No threats detected — URL confirmed as legitimate'
        }
 
    # UNKNOWN — no database could confirm safety
    return {
        'status':  'UNKNOWN',
        'score':   0,
        'source':  ' + '.join(sources_checked),
        'message': (
            'This URL was not found in any threat database '
            '(Google Safe Browsing + VirusTotal + Cloudflare Radar). '
            'This does NOT mean it is safe — it means it is unknown. '
            'Proceed with caution and avoid entering personal information.'
        )
    }


# =============================================================================
# Quick test
# =============================================================================
if __name__ == '__main__':
    import sys
    if '--debug' in sys.argv:
        DEBUG_CLOUDFLARE = True

    test_urls = [
        'https://www.google.com',
        'telega.me',
        'totally-unknown-xyz999abc.com',
        'not-a-url',
    ]
    for url in test_urls:
        print(f"\nInput     : {url}")
        print(f"Normalized: {normalize_url(url)}")
        result = check_url(url)
        print(f"Status    : {result['status']}")
        print(f"Score     : {result.get('score', 0)}")
        print(f"Source    : {result.get('source', 'N/A')}")
        print(f"Message   : {result.get('message', 'N/A')}")