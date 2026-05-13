"""
Risk Score Module — CleanDrop
==============================
WHAT THIS MODULE DOES:
    This is the brain of CleanDrop. It takes the results from ALL 5 modules
    and combines them into one final risk score (0–100) and risk level.

    It uses AHP (Analytic Hierarchy Process) — a weighted scoring method
    that gives different importance to each module:

    MODULE WEIGHTS (must sum to 1.0):
        Hash Engine   → 30%  (most reliable — binary match)
        VirusTotal    → 25%  (consensus of 70+ engines)
        Heuristics    → 15%  (behavioral indicators)
        Entropy       → 10%  (randomness/encryption detection)
        DLP           → 10%  (privacy/PII risk)
        Signature      → 5%   (file type consistency)
        URL Analyzer  →  5%  (link reputation)

    ARCHITECTURE (4 layers):
        Layer 1 — AHP Weighted Baseline (combines all module scores)
        Layer 2 — Tier 1 Override: confirmed malware → CRITICAL (≥90)
        Layer 3 — Tier 2 Floor: behavioral suspicion → proportional HIGH
        Layer 4 — Tier 3 Floor: privacy risk → proportional MEDIUM/HIGH
        Final   = max(all layers), capped at 100

RISK LEVELS:
    0          → SAFE
    1–20       → LOW
    21–50      → MEDIUM
    51–80      → HIGH
    81–100     → CRITICAL

IMPORTANT — SOURCE OF TRUTH:
    This module trusts the score from each module directly.
    It does NOT recalculate scores independently.
    Each module is responsible for its own score.
"""

AHP_WEIGHTS = {
    "hash":       0.30,
    "virustotal": 0.25,
    "heuristics": 0.15,
    "entropy":    0.10,
    "dlp":        0.10,
    "signature":  0.05,
    "url":        0.05,
}


def calculate_risk_score(hash_result, vt_result, entropy_result,
                         heuristic_result, pii_result, sig_result=None, url_result=None):
    """
    Combine all module results into a single risk score.

    Each module must return a dict with at least:
        status : str
        score  : float (0–100)

    Returns:
        score            : float (0–100)
        level            : 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
        message          : human-readable explanation
        findings_summary : list of reason strings
        breakdown        : per-module weighted contributions
    """

    # ── 0. Extract values from each module ──────────────────────
    hash_status    = hash_result.get("status", "SAFE")
    hash_score     = 100.0 if hash_status == "MALWARE" else 0.0

    vt_status      = vt_result.get("status", "SAFE")
    vt_score       = float(vt_result.get("score", 0))
    vt_malicious   = int(vt_result.get("malicious_count", 0))
    vt_total       = int(vt_result.get("total_engines", 0))

    # Trust entropy.py's score directly — no recalculation
    entropy_value  = float(entropy_result.get("entropy", 0.0))
    entropy_note   = entropy_result.get("note", "")
    entropy_risk   = entropy_result.get("risk", "SAFE")
    if "Compressed format" in entropy_note:
        entropy_score = 0.0
    else:
        entropy_score = float(entropy_result.get("score", 0))

    # Trust heuristics.py's score directly
    heuristic_risk    = heuristic_result.get("risk", "SAFE")
    heuristic_count   = int(heuristic_result.get("total_indicators", 0))
    heuristic_findings = heuristic_result.get("findings", {})
    heuristic_score   = float(heuristic_result.get("score", 0))

    # Trust dlp.py's score directly
    pii_found    = bool(pii_result.get("pii_found", False))
    pii_findings = pii_result.get("findings", {})
    pii_score    = float(pii_result.get("score", 0))

    # URL module — optional
    if url_result is None:
        url_score  = 0.0
        url_status = "SAFE"
    else:
        url_score  = float(url_result.get("score", 0))
        url_status = url_result.get("status", "SAFE")
    
    # Signature module — optional
    if sig_result is None:
        sig_score  = 0.0
        sig_risk   = "SAFE"
        sig_spoofed = False
    else:
        sig_score   = float(sig_result.get("score", 0))
        sig_risk    = sig_result.get("risk", "SAFE")
        sig_spoofed = bool(sig_result.get("is_spoofed", False))

    # ── 1. AHP Weighted Baseline ─────────────────────────────────
    ahp_score = (
        hash_score      * AHP_WEIGHTS["hash"]       +
        vt_score        * AHP_WEIGHTS["virustotal"] +
        heuristic_score * AHP_WEIGHTS["heuristics"] +
        entropy_score   * AHP_WEIGHTS["entropy"]    +
        pii_score       * AHP_WEIGHTS["dlp"]        +
        sig_score       * AHP_WEIGHTS["signature"]  +
        url_score       * AHP_WEIGHTS["url"]
    )

    # ── 2. Tier 1 — Definitive Threat Override (CRITICAL ≥ 90) ───
    tier1_score   = 0.0
    tier1_reasons = []

    if hash_status == "MALWARE":
        tier1_score = 90.0
        tier1_reasons.append("Confirmed Malware — Local Hash Database match")

    if vt_score >= 82:
        tier1_score = max(tier1_score, 90.0)
        tier1_reasons.append(
            f"VirusTotal High Detection ({vt_malicious}/{vt_total} engines)"
        )
    if sig_spoofed and sig_risk == "HIGH":
        tier1_score = max(tier1_score, 85.0)
        tier1_reasons.append("File signature spoofing detected — executable disguised as document")

    # ── 3. Tier 2 — Behavioral Suspicion Floor ───────────────────
    tier2_score   = 0.0
    tier2_reasons = []

    if entropy_score >= 50:
        tier2_score = max(tier2_score, entropy_score)
        tier2_reasons.append(
            f"High Entropy ({entropy_value:.4f} bits) — "
            f"{'Possible packed/encrypted malware' if entropy_value >= 7.5 else 'Suspicious obfuscation'}"
        )

    if heuristic_count >= 1:
        tier2_score = max(tier2_score, heuristic_score)
        tier2_reasons.append(
            f"Heuristic Indicators: {heuristic_count} flag(s) — "
            f"Categories: {', '.join(heuristic_findings.keys())}"
        )

    # ── 4. Tier 3 — Privacy & Data Leakage Floor ─────────────────
    tier3_score   = 0.0
    tier3_reasons = []

    if pii_found:
        tier3_score = max(tier3_score, pii_score)
        pii_types = list(pii_findings.keys())
        tier3_reasons.append(
            f"Saudi PII Detected ({len(pii_types)} type(s)): {', '.join(pii_types)}"
        )

    if url_status in ("MALICIOUS", "CRITICAL"):
        tier3_score = max(tier3_score, 80.0)
        tier3_reasons.append("Malicious URL detected")

    # ── 5. Final Score ────────────────────────────────────────────
    final_score = max(ahp_score, tier1_score, tier2_score, tier3_score)
    final_score = min(round(final_score, 1), 100.0)

    # ── 6. Risk Level ─────────────────────────────────────────────
    if final_score == 0.0:
        risk_level = "SAFE"
    elif final_score <= 20:
        risk_level = "LOW"
    elif final_score <= 50:
        risk_level = "MEDIUM"
    elif final_score <= 80:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # ── 7. Findings Summary ───────────────────────────────────────
    findings = []
    findings.extend(tier1_reasons)
    findings.extend(tier2_reasons)
    findings.extend(tier3_reasons)

    if not findings:
        if vt_score > 0:
            findings.append(f"VirusTotal: {vt_malicious}/{vt_total} engines flagged")
        if entropy_score > 0:
            findings.append(f"Entropy: {entropy_value:.4f} bits — {entropy_risk}")
        if heuristic_count > 0:
            findings.append(f"Heuristics: {heuristic_count} indicator(s) found")

    if not findings:
        findings.append("No threats detected — file appears clean ✅")

    # ── 8. Score Breakdown ────────────────────────────────────────
    breakdown = {
        "ahp_baseline":   round(ahp_score, 1),
        "tier1_override": round(tier1_score, 1),
        "tier2_floor":    round(tier2_score, 1),
        "tier3_floor":    round(tier3_score, 1),
        "hash":           round(hash_score      * AHP_WEIGHTS["hash"],       1),
        "virustotal":     round(vt_score        * AHP_WEIGHTS["virustotal"], 1),
        "heuristics":     round(heuristic_score * AHP_WEIGHTS["heuristics"], 1),
        "entropy":        round(entropy_score   * AHP_WEIGHTS["entropy"],    1),
        "dlp":            round(pii_score       * AHP_WEIGHTS["dlp"],        1),
        "signature":      round(sig_score       * AHP_WEIGHTS["signature"],  1),
        "url":            round(url_score       * AHP_WEIGHTS["url"],        1),
    }

    return {
        "final_score":      final_score,
        "score":            final_score,
        "risk_level":       risk_level,
        "level":            risk_level,
        "message":          _risk_message(risk_level),
        "findings_summary": findings,
        "breakdown":        breakdown,
    }


def _risk_message(level):
    messages = {
        "SAFE":     "File is clean. No threats detected. ✅",
        "LOW":      "Minor indicators found. Generally safe but stay cautious.",
        "MEDIUM":   "Some indicators found. Review carefully before sharing.",
        "HIGH":     "High risk detected. Do not open this file without investigation.",
        "CRITICAL": "Critical threat confirmed. Delete this file immediately. 🚨",
    }
    return messages.get(level, "Unknown risk level.")