from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER
from datetime import datetime
import re

# ──────────────────────────────────────────────
# BRAND COLOURS  (matches app.py exactly)
# ──────────────────────────────────────────────
PRIMARY     = colors.HexColor("#00FFA3")
PURPLE_DARK = colors.HexColor("#4A235A")
PURPLE_MID  = colors.HexColor("#6C3483")

# Risk colours — copied from app.py RISK_COLORS
C_SAFE     = colors.HexColor("#3B82F6")
C_LOW      = colors.HexColor("#22C55E")
C_MEDIUM   = colors.HexColor("#FFD700")
C_HIGH     = colors.HexColor("#FF7A00")
C_CRITICAL = colors.HexColor("#FF2D2D")
C_INFO     = colors.HexColor("#6B7280")

BG_SAFE     = colors.HexColor("#EFF6FF")
BG_LOW      = colors.HexColor("#F0FFF4")
BG_MEDIUM   = colors.HexColor("#FFFDE7")
BG_HIGH     = colors.HexColor("#FFF4EC")
BG_CRITICAL = colors.HexColor("#FFF0F0")
BG_INFO     = colors.HexColor("#F9FAFB")

# ──────────────────────────────────────────────
# RISK LEVEL HELPERS
# Source of truth: risk_score.py levels
#   0       → SAFE
#   1–20    → LOW
#   21–50   → MEDIUM
#   51–80   → HIGH
#   81–100  → CRITICAL
# ──────────────────────────────────────────────
def _risk_from_score(score):
    if score > 80:   return "CRITICAL", C_CRITICAL, BG_CRITICAL
    if score > 50:   return "HIGH",     C_HIGH,     BG_HIGH
    if score > 20:   return "MEDIUM",   C_MEDIUM,   BG_MEDIUM
    if score > 0:    return "LOW",      C_LOW,      BG_LOW
    return "SAFE", C_SAFE, BG_SAFE


# ──────────────────────────────────────────────
# STATUS → COLOR
# Mirrors status_cell() in app.py exactly
# ──────────────────────────────────────────────
def _status_style(status_str):
    """
    Input: the raw status string that app.py puts in report_details.
    Returns: (label, text_color, bg_color)

    app.py sends these exact values:
      Hash Status      → "SAFE" | "MALWARE" | "ERROR"
      VirusTotal       → "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
      Entropy Risk     → "SAFE (value: X)" | "LOW (...)" | "MEDIUM (...)" | "HIGH (...)" | "CRITICAL (...)"
      Heuristic Risk   → "SAFE (0 indicators)" | "LOW (...)" | "MEDIUM (...)" | "HIGH (...)" | "CRITICAL (...)"
      DLP Status       → "PII Detected" | "Clean"
      File Signature   → "SAFE" | "SPOOFED" (optional)
      Final Risk Level → "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    """
    t = str(status_str).strip().upper()

    # ── 1. Exact / leading keyword (covers all module outputs) ──
    leading = re.match(r'^(CRITICAL|HIGH|MEDIUM|LOW|SAFE|CLEAN)', t)
    if leading:
        w = leading.group(1)
        if w == "CRITICAL":           return "CRITICAL", C_CRITICAL, BG_CRITICAL
        if w == "HIGH":               return "HIGH",     C_HIGH,     BG_HIGH
        if w == "MEDIUM":             return "MEDIUM",   C_MEDIUM,   BG_MEDIUM
        if w == "LOW":                return "LOW",      C_LOW,      BG_LOW
        if w in ("SAFE", "CLEAN"):    return "SAFE",     C_SAFE,     BG_SAFE

    # ── 2. Special values ──
    if "MALWARE"    in t: return "CRITICAL", C_CRITICAL, BG_CRITICAL
    if "SPOOFED"    in t: return "CRITICAL", C_CRITICAL, BG_CRITICAL
    if "PII"        in t: return "HIGH",     C_HIGH,     BG_HIGH
    if "DETECTED"   in t: return "HIGH",     C_HIGH,     BG_HIGH
    if "SUSPICIOUS" in t: return "MEDIUM",   C_MEDIUM,   BG_MEDIUM
    if "ERROR"      in t: return "INFO",     C_INFO,     BG_INFO

    return "SAFE", C_SAFE, BG_SAFE


def S(base, name="_s", **kw):
    return ParagraphStyle(name, parent=base, **kw)


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def generate_report(filename, score, details, output_path="report.pdf"):
    """
    details keys (exactly as app.py sends them):
      "Hash Status"           → hash_result["status"]
      "VirusTotal Status"     → vt_result["status"]
      "Entropy Risk"          → f"{entropy_result['risk']} (value: {entropy_result['entropy']})"
      "Heuristic Risk"        → f"{heuristic_result['risk']} ({heuristic_result['total_indicators']} indicators)"
      "DLP Status"            → "PII Detected" | "Clean"
      "PII Types Found"       → comma-separated types | "None"
      "Final Risk Level"      → risk["level"]
      "File Signature Status" → (optional)
    """
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
    )

    base      = getSampleStyleSheet()["Normal"]
    risk_lbl, risk_clr, risk_bg = _risk_from_score(score)

    # styles
    title_s    = S(base,"T",  fontSize=26, textColor=PRIMARY, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, spaceAfter=20)
    sub_s      = S(base,"SU", fontSize=10, textColor=colors.HexColor("#9CA3AF"),
                   alignment=TA_CENTER, spaceAfter=14)
    section_s  = S(base,"SE", fontSize=13, textColor=PURPLE_MID,
                   fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=8)
    normal_s   = S(base,"N",  fontSize=10, textColor=colors.HexColor("#1F2937"), leading=14)
    footer_s   = S(base,"F",  fontSize=8,  textColor=colors.HexColor("#9CA3AF"), alignment=TA_CENTER)
    score_s    = S(base,"SC", fontSize=14, fontName="Helvetica-Bold", alignment=TA_CENTER)
    level_s    = S(base,"LV", fontSize=12, fontName="Helvetica-Bold", alignment=TA_CENTER)

    el = []

    # ════════ HEADER ════════
    el.append(Paragraph("CleanDrop Security Report", title_s))
    el.append(Paragraph("Threat Detection  |  PII Analysis  |  Risk Intelligence", sub_s))
    el.append(HRFlowable(width="100%", thickness=1.5, color=PRIMARY, spaceAfter=10))
    el.append(Paragraph(f"<b>File:</b>  {filename}", normal_s))
    el.append(Paragraph(f"<b>Date:</b>  {datetime.now().strftime('%Y-%m-%d  %H:%M')}", normal_s))
    el.append(Spacer(1, 14))

    # ════════ SCORE BLOCK ════════
    hx = risk_clr.hexval()
    score_tbl = Table([[
        Paragraph(f'<font color="{hx}"><b>{int(score)}/100</b></font>', score_s),
        Paragraph(f'<font color="{hx}"><b>{risk_lbl}</b></font>', level_s),
    ]], colWidths=[8*cm, 8*cm])
    score_tbl.setStyle(TableStyle([
        ("ALIGN",         (0,0),(-1,-1),"CENTER"),
        ("VALIGN",        (0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",    (0,0),(-1,-1),10),
        ("BOTTOMPADDING", (0,0),(-1,-1),10),
        ("BACKGROUND",    (0,0),(-1,-1),colors.HexColor("#FAFAFA")),
        ("BOX",           (0,0),(-1,-1),1, colors.HexColor("#E5E7EB")),
        ("LINEBEFORE",    (0,0),(0,-1), 4, risk_clr),
    ]))
    el.append(score_tbl)
    el.append(Spacer(1,10))
    el.append(HRFlowable(width="100%", thickness=0.5,
                         color=colors.HexColor("#E5E7EB"), spaceAfter=10))

    # ════════ SCAN RESULTS SUMMARY ════════
    # Rows mirror app.py table_rows order exactly
    el.append(Paragraph("Scan Results Summary", section_s))

    # (display_label, details_key, details_value_override)
    summary = [
        ("Hash Engine",           "Hash Status",           None),
        ("VirusTotal",            "VirusTotal Status",     None),
        ("Entropy Analysis",       "Entropy Risk",          None),
        ("Heuristic Detection",    "Heuristic Risk",        None),
        ("DLP (Saudi PII Scanner)","DLP Status",            None),
        ("File Signature Check",   "File Signature Status", None),
        ("Final Risk Level",       "Final Risk Level",      None),
    ]

    lbl_s = S(base,"sl", fontSize=9)
    val_s = S(base,"sv", fontSize=9)
    hdr_s = S(base,"sh", fontSize=10, textColor=colors.white, fontName="Helvetica-Bold")

    rows = [[
        Paragraph("Module / Check", hdr_s),
        Paragraph("Result", hdr_s),
        Paragraph("Status", hdr_s),
    ]]

    for disp_label, key, _ in summary:
        val = details.get(key)
        if val is None:
            continue
        status_lbl, txt_c, bg_c = _status_style(val)
        rows.append([
            Paragraph(disp_label, lbl_s),
            Paragraph(str(val), val_s),
            Paragraph(f"<b>{status_lbl}</b>",
                      S(base,"st", fontSize=9, fontName="Helvetica-Bold",
                        textColor=txt_c)),
        ])

    tbl = Table(rows, colWidths=[5.5*cm, 8.5*cm, 3*cm], repeatRows=1)
    cmds = [
        ("BACKGROUND",    (0,0),(-1,0),  PURPLE_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0),  colors.white),
        ("TOPPADDING",    (0,0),(-1,0),  9),
        ("BOTTOMPADDING", (0,0),(-1,0),  9),
        ("FONTNAME",      (0,1),(-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,1),(-1,-1), 9),
        ("TOPPADDING",    (0,1),(-1,-1), 7),
        ("BOTTOMPADDING", (0,1),(-1,-1), 7),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
        ("RIGHTPADDING",  (0,0),(-1,-1), 10),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("GRID",          (0,0),(-1,-1), 0.4, colors.HexColor("#D1D5DB")),
        ("BOX",           (0,0),(-1,-1), 1,   colors.HexColor("#C4B5FD")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#FAF5FF")]),
    ]
    # Color the Status column cells
    for i, row in enumerate(rows[1:], start=1):
        raw_val = details.get(
            [k for _, k, _ in summary if _ is None][i-1]
            if i-1 < len(summary) else "", "")
        _, txt_c, bg_c = _status_style(raw_val)
        cmds += [
            ("BACKGROUND", (2,i),(2,i), bg_c),
            ("TEXTCOLOR",  (2,i),(2,i), txt_c),
        ]
    tbl.setStyle(TableStyle(cmds))
    el.append(tbl)
    el.append(Spacer(1,16))

    # ════════ SMART RECOMMENDATIONS ════════
    # Logic mirrors app.py active_recs block exactly
    el.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))
    el.append(Paragraph("Smart Security Recommendations", section_s))

    hash_s    = str(details.get("Hash Status",           "")).upper()
    vt_s      = str(details.get("VirusTotal Status",     "")).upper()
    entropy_s = str(details.get("Entropy Risk",          "")).upper()
    heur_s    = str(details.get("Heuristic Risk",        "")).upper()
    dlp_s     = str(details.get("DLP Status",            "")).upper()
    sig_s     = str(details.get("File Signature Status", "")).upper()

    recs = []

    # Mirror: if hash_result["status"] == "MALWARE" or vt_result["status"] in ("MALWARE","HIGH","CRITICAL")
    if "MALWARE" in hash_s or any(x in vt_s for x in ("MALWARE","HIGH","CRITICAL")):
        recs.append((
            "Hash / VirusTotal — Malware Detected",
            "This file is known to be malicious. Delete it immediately and "
            "do not share it with anyone.",
            C_CRITICAL, BG_CRITICAL))

    # Mirror: if dlp_result["pii_found"]
    if dlp_s not in ("CLEAN", "SAFE", ""):
        recs.append((
            "DLP (PII) — Privacy Alert",
            "The file contains sensitive information (National ID / IBAN / Mobile Number / Email). "
            "Make sure to encrypt it before sending.",
            C_HIGH, BG_HIGH))

    # Mirror: if entropy_result["risk"] in ("HIGH","CRITICAL")
    if any(x in entropy_s for x in ("HIGH","CRITICAL")):
        recs.append((
            "Entropy — High Entropy Detected",
            "The file appears to be encrypted or obfuscated. This is a common technique "
            "used to hide malware. Do not run it unless you fully trust the source.",
            C_HIGH, BG_HIGH))

    # Mirror: if heuristic_result["risk"] in ("HIGH","MEDIUM","CRITICAL")
    if any(x in heur_s for x in ("HIGH","MEDIUM","CRITICAL")):
        recs.append((
            "Heuristics — Suspicious Behavior Detected",
            "The file contains suspicious structural indicators commonly found in malware. "
            "Do not run it unless you fully trust the source.",
            C_HIGH, BG_HIGH))

    # Mirror: if sig_result["is_spoofed"]
    if "SPOOFED" in sig_s:
        recs.append((
            "File Signature — Extension Spoofing Detected",
            "This file claims to be a document but is actually an executable. "
            "Delete it immediately — this is a classic malware delivery technique.",
            C_CRITICAL, BG_CRITICAL))

    # ── Validation guard: top rec must match score level ──
    ORDER = {"SAFE":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    def _rec_level(title):
        t = title.upper()
        for lvl in ("CRITICAL","HIGH","MEDIUM","LOW","SAFE"):
            if lvl in t: return ORDER[lvl]
        return 0

    score_idx = ORDER.get(risk_lbl, 0)
    if recs and max(_rec_level(r[0]) for r in recs) < score_idx:
        recs.insert(0,(
            f"{risk_lbl} — Risk Level Elevated",
            f"The composite risk score is {int(score)}/100 ({risk_lbl}). "
            "Multiple scan signals combined indicate an elevated threat level. "
            "Exercise caution with this file.",
            risk_clr, risk_bg))

    if not recs:
        recs.append((
            "No Threats Detected",
            "This file appears to be safe across all scan modules. "
            "Always exercise caution when sharing files externally.",
            C_SAFE, BG_SAFE))

    for rec_title, rec_msg, txt_c, bg_c in recs:
        rt_s = S(base,"_rt", textColor=txt_c, fontSize=10, fontName="Helvetica-Bold")
        rm_s = S(base,"_rm", textColor=colors.HexColor("#1F2937"), fontSize=9, leading=13)
        rec_tbl = Table([[
            Paragraph(f"<b>{rec_title}</b>", rt_s),
            Paragraph(rec_msg, rm_s),
        ]], colWidths=[5*cm, 11.5*cm])
        rec_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), bg_c),
            ("LEFTPADDING",   (0,0),(-1,-1), 10),
            ("RIGHTPADDING",  (0,0),(-1,-1), 10),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ("BOX",           (0,0),(-1,-1), 1,  txt_c),
            ("LINEBEFORE",    (0,0),(0,-1),  4,  txt_c),
        ]))
        el.append(rec_tbl)
        el.append(Spacer(1,8))

    # ════════ FOOTER ════════
    el.append(Spacer(1,10))
    el.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))
    el.append(Spacer(1,6))
    el.append(Paragraph(
        "Generated by CleanDrop  |  Cyber Security System  |  University of Bisha  |  v1.0",
        footer_s))
    el.append(Paragraph(
        "This report is auto-generated for informational purposes only.", footer_s))

    doc.build(el)


# ──────────────────────────────────────────────
# TEST — simulates exactly what app.py sends
# ──────────────────────────────────────────────
if __name__ == "__main__":
    # Test 1: PII MEDIUM
    generate_report("salary_list.xlsx", 45, {
        "Hash Status":           "SAFE",
        "VirusTotal Status":     "SAFE",
        "Entropy Risk":          "LOW (value: 4.12)",
        "Heuristic Risk":        "SAFE (0 indicators)",
        "DLP Status":            "PII Detected",
        "PII Types Found":       "Saudi National ID, Mobile Number",
        "File Signature Status": "SAFE",
        "Final Risk Level":      "MEDIUM",
    }, "t1_pii_medium.pdf")

    # Test 2: HIGH entropy + heuristic
    generate_report("suspicious.exe", 68, {
        "Hash Status":           "SAFE",
        "VirusTotal Status":     "HIGH",
        "Entropy Risk":          "HIGH (value: 7.35)",
        "Heuristic Risk":        "HIGH (4 indicators)",
        "DLP Status":            "Clean",
        "PII Types Found":       "None",
        "File Signature Status": "SPOOFED",
        "Final Risk Level":      "HIGH",
    }, "t2_high.pdf")

    # Test 3: SAFE
    generate_report("clean_doc.pdf", 0, {
        "Hash Status":           "SAFE",
        "VirusTotal Status":     "SAFE",
        "Entropy Risk":          "SAFE (value: 3.20)",
        "Heuristic Risk":        "SAFE (0 indicators)",
        "DLP Status":            "Clean",
        "PII Types Found":       "None",
        "File Signature Status": "SAFE",
        "Final Risk Level":      "SAFE",
    }, "t3_safe.pdf")

    print("All 3 test reports generated.")