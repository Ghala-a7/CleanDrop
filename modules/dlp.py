"""
DLP (Data Loss Prevention) Module — CleanDrop
===============================================
WHAT THIS MODULE DOES:
    This is Layer 5 of CleanDrop's detection system.
    It scans the file's text content for Saudi PII (Personally Identifiable Information)
    using regex patterns — without sending any data to external services.

    Why does this matter?
    Someone might accidentally upload a file containing sensitive personal data
    (ID numbers, bank accounts, phone numbers, emails).
    CleanDrop detects this and warns the user before they share the file.

PII TYPES DETECTED:
    Saudi National ID  — starts with 1, exactly 10 digits
    Saudi IBAN         — starts with SA, followed by 22 digits
    Mobile Number      — starts with 05, exactly 10 digits
    Email Address      — standard email format (user@domain.ext)

SUPPORTED FILE FORMATS:
    .txt, .pdf, .docx, .doc, .xlsx, .xls, .csv

SCORING:
    Each PII type found adds 25 points (max 100).
    Combination bonuses are applied in risk_score.py.

RETURNS:
    pii_found   : bool
    findings    : { type: { count, samples } }
    types_count : int
    score       : 0–100
    source      : 'DLP Scanner'
"""

import re
import subprocess
import os

import PyPDF2
from docx import Document as DocxDoc
import pandas as pd


PII_PATTERNS = {
    "Saudi National ID": r"\b1[0-9]{9}\b",
    "Mobile Number":     r"\b(?:05)[0-9]{8}\b",
    "Email Address":     r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "Saudi IBAN":        r"\bSA[0-9]{22}\b",
}


# ── Text Extractors ─────────────────────────────────────────

def _extract_txt(file_path):
    with open(file_path, "rb") as f:
        bom = f.read(2)

    if bom in (b'\xff\xfe', b'\xfe\xff'):
        with open(file_path, "r", encoding="utf-16", errors="ignore") as f:
            return f.read()
    else:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
        

def _extract_pdf(file_path):
    text = ""
    try:
        reader = PyPDF2.PdfReader(file_path)
        for page in reader.pages:
            text += page.extract_text() or ""
    except Exception as e:
        print(f"[DLP] PDF read error: {e}")
    return text


def _extract_docx(file_path):
    text = ""
    try:
        doc = DocxDoc(file_path)
        for para in doc.paragraphs:
            text += para.text + " "
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    text += cell.text + " "
    except Exception as e:
        print(f"[DLP] DOCX read error: {e}")
    return text


def _extract_doc(file_path):
    text = ""
    try:
        result = subprocess.run(
            ["antiword", file_path],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            text = result.stdout
        else:
            text = _extract_doc_fallback(file_path)
    except FileNotFoundError:
        text = _extract_doc_fallback(file_path)
    except Exception as e:
        print(f"[DLP] .doc extraction error: {e}")
    return text


def _extract_doc_fallback(file_path):
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        readable = re.findall(rb"[ -~]{4,}", raw)
        return " ".join(chunk.decode("ascii", errors="ignore") for chunk in readable)
    except Exception:
        return ""


def _extract_xlsx(file_path):
    try:
        df = pd.read_excel(file_path, dtype=str)
        return df.to_string()
    except Exception as e:
        print(f"[DLP] XLSX read error: {e}")
        return ""


def _extract_xls(file_path):
    try:
        df = pd.read_excel(file_path, dtype=str, engine='xlrd')
        return df.to_string()
    except Exception as e:
        print(f"[DLP] XLS read error: {e}")
        return ""


def _extract_csv(file_path):
    try:
        df = pd.read_csv(file_path, dtype=str)
        return df.to_string()
    except Exception as e:
        print(f"[DLP] CSV read error: {e}")
        return ""


def extract_text(file_path):
    """Route to the correct extractor based on file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    extractors = {
        ".txt":  _extract_txt,
        ".pdf":  _extract_pdf,
        ".docx": _extract_docx,
        ".doc":  _extract_doc,
        ".xlsx": _extract_xlsx,
        ".xls":  _extract_xls,
        ".csv":  _extract_csv,
    }
    extractor = extractors.get(ext)
    if extractor:
        return extractor(file_path)
    print(f"[DLP] Unsupported file type: {ext}")
    return ""


# ── Masking Helper ──────────────────────────────────────────

def _mask(value, pii_type):
    """Mask sensitive data before displaying samples."""
    if pii_type == "Email Address":
        parts = value.split("@")
        return parts[0][0] + "***@" + parts[1]
    elif pii_type == "Saudi IBAN":
        return value[:4] + "****" + value[-4:]
    else:
        # National ID and Mobile Number
        return value[:3] + "****" + value[-2:]


# ── Main Scanner ────────────────────────────────────────────

def scan_for_pii(file_path):
    """
    Scan a file for Saudi PII patterns.
    Returns findings grouped by type with masked samples.
    """
    text = extract_text(file_path)
    findings = {}
    risk_points = 0

    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            findings[pii_type] = {
                "count":   len(matches),
                "samples": [_mask(m, pii_type) for m in matches[:3]],
            }
            risk_points += 25

    return {
        "pii_found":   len(findings) > 0,
        "findings":    findings,
        "types_count": len(findings),
        "score":       min(risk_points, 100),
        "source":      "DLP Scanner",
    }


if __name__ == "__main__":
    import sys
    test_file = sys.argv[1] if len(sys.argv) > 1 else "ENTER_FILENAME_HERE.txt"
    if os.path.exists(test_file):
        result = scan_for_pii(test_file)
        print(f"PII Found   : {result['pii_found']}")
        print(f"Types Found : {result['types_count']}")
        print(f"Score       : {result['score']}/100")
        print(f"Findings    : {result['findings']}")
    else:
        print("DLP module ready. Pass a filename as argument to test.")
