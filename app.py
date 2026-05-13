import streamlit as st
import os

# Bridge st.secrets → os.environ so all modules can use os.environ.get() consistently.
# Works both locally (where .env is loaded via python-dotenv) and on Streamlit Cloud.
for _k, _v in st.secrets.items():
    if isinstance(_v, str):
        os.environ.setdefault(_k, _v)

from modules.dlp import scan_for_pii
from modules.hash_engine import get_file_hash, check_hash_in_database
from modules.virustotal import check_virustotal
from modules.entropy import calculate_entropy
from modules.heuristics import heuristic_scan
from modules.risk_score import calculate_risk_score
from modules.url_analyzer import check_url
from modules.scan_logger import log_file_scan, log_url_scan
import tempfile
import os
import pandas as pd


# ──────────────────────────────────────────────
# PAGE CONFIG  (must be the very first st call)
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="CleanDrop",
    page_icon="🛡️",
    layout="wide",
)

# ──────────────────────────────────────────────
# RISK LEVEL COLOR SYSTEM
# Matches exactly with risk_score.py levels:
#   SAFE     → #00C896  green
#   LOW      → #A8D400  yellow-green
#   MEDIUM   → #FFD700  yellow
#   HIGH     → #FF7A00  orange
#   CRITICAL → #FF2D2D  red
# ──────────────────────────────────────────────
RISK_COLORS = {
    "SAFE":     "#3B82F6",   # أزرق (آمن)
    "LOW":      "#22C55E",   # أخضر
    "MEDIUM":   "#FFD700",   # أصفر
    "HIGH":     "#FF7A00",   # برتقالي
    "CRITICAL": "#FF2D2D",   # أحمر
}

RISK_BG = {
    "SAFE":     "rgba(0,200,150,0.10)",
    "LOW":      "rgba(168,212,0,0.10)",
    "MEDIUM":   "rgba(255,215,0,0.10)",
    "HIGH":     "rgba(255,122,0,0.10)",
    "CRITICAL": "rgba(255,45,45,0.10)",
}

RISK_ICONS = {
    "SAFE":     "🔵",
    "LOW":      "🟢",
    "MEDIUM":   "🟡",
    "HIGH":     "🟠",
    "CRITICAL": "🔴"
}

# ──────────────────────────────────────────────
# SIDEBAR — Theme Toggle at the TOP
# ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Display Settings")
    mode = st.radio("Theme", ["🌑 Dark Mode", "☀️ Light Mode"], index=0)
    st.markdown("---")

    # Risk Level Guide
    st.markdown("**Risk Level Guide**")
    for level, color in RISK_COLORS.items():
        st.markdown(
            f'<div style="display:flex; align-items:center; gap:10px; margin:5px 0;">'
            f'<div style="width:13px; height:13px; border-radius:50%; background:{color}; flex-shrink:0;"></div>'
            f'<span style="font-size:13px; font-weight:500;">{level}</span>'
            f'</div>',
            unsafe_allow_html=True
        )

    st.markdown("---")
    st.markdown("*CleanDrop* v1.0")
    st.markdown("University of Bisha — Cyber Security Dept.")

IS_DARK = mode.startswith("🌑")

# ──────────────────────────────────────────────
# VISUAL IDENTITY — Official CleanDrop Colours
# ──────────────────────────────────────────────
if IS_DARK:
    BG_COLOR   = "#0E1117"
    TEXT_COLOR = "#FFFFFF"
    CARD_BG    = "rgba(255,255,255,0.06)"
    INPUT_BG   = "rgba(255,255,255,0.04)"
else:
    BG_COLOR   = "#F0F2F6"
    TEXT_COLOR = "#1A1A1A"
    CARD_BG    = "rgba(0,0,0,0.04)"
    INPUT_BG   = "rgba(0,0,0,0.03)"

PRIMARY = "#00FFA3"

st.markdown(f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700&family=Roboto:wght@400;500;700&display=swap');

  html, body, [data-testid="stAppViewContainer"], .stApp {{
      background-color: {BG_COLOR} !important;
      color: {TEXT_COLOR} !important;
      font-family: 'Roboto', sans-serif;
  }}
  [data-testid="stSidebar"] {{
      background-color: {"#161B22" if IS_DARK else "#E4E8EF"} !important;
  }}
  [data-testid="stSidebar"] * {{ color: {TEXT_COLOR} !important; }}

  .stButton > button {{
      background-color: {PRIMARY} !important;
      color: #0E1117 !important;
      font-weight: 700;
      border: none;
      border-radius: 8px;
      padding: 0.55rem 1.5rem;
      font-family: 'Roboto', sans-serif;
      transition: opacity 0.2s;
  }}
  .stButton > button:hover {{ opacity: 0.85; }}
  a {{ color: {PRIMARY} !important; }}

  [data-testid="stFileUploader"] {{
      background: {INPUT_BG};
      border: 2px dashed {PRIMARY};
      border-radius: 12px;
      padding: 10px;
  }}
  [data-testid="stDataFrame"] {{
      border: 1px solid {PRIMARY}33;
      border-radius: 10px;
  }}
  .cd-card {{
      background: {CARD_BG};
      border: 1px solid {PRIMARY}33;
      border-radius: 14px;
      padding: 22px 26px;
      margin-top: 18px;
  }}
  .cd-logo-title {{
      font-family: 'Orbitron', sans-serif;
      font-size: 2.4rem;
      font-weight: 700;
      color: {PRIMARY};
      letter-spacing: 2px;
      text-align: center;
  }}
  .cd-subtitle {{
      text-align: center;
      font-size: 1rem;
      color: {TEXT_COLOR};
      opacity: 0.7;
      margin-bottom: 28px;
  }}
  .cd-section {{
      font-size: 1.1rem;
      font-weight: 700;
      color: {PRIMARY};
      border-left: 4px solid {PRIMARY};
      padding-left: 10px;
      margin: 24px 0 10px;
  }}
  hr {{ border-color: {PRIMARY}33; }}
  .url-result-safe {{
      background: {RISK_BG["SAFE"]};
      border: 1px solid {RISK_COLORS["SAFE"]};
      border-radius: 12px;
      padding: 18px 22px;
      margin-top: 12px;
  }}
  .url-result-danger {{
      background: {RISK_BG["CRITICAL"]};
      border: 1px solid {RISK_COLORS["CRITICAL"]};
      border-radius: 12px;
      padding: 18px 22px;
      margin-top: 12px;
  }}
  .url-result-warn {{
      background: {RISK_BG["MEDIUM"]};
      border: 1px solid {RISK_COLORS["MEDIUM"]};
      border-radius: 12px;
      padding: 18px 22px;
      margin-top: 12px;
  }}
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────
st.markdown('<div style="text-align:center; padding:10px 0 4px;"><span style="font-size:3.2rem;">🛡️</span></div>', unsafe_allow_html=True)
st.markdown('<div class="cd-logo-title">CleanDrop</div>', unsafe_allow_html=True)
st.markdown('<div class="cd-subtitle">Security Analysis Report &nbsp;|&nbsp; Threat & PII Detection</div>', unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# SMART RECOMMENDATIONS DICTIONARY
# ──────────────────────────────────────────────
RECOMMENDATIONS = {
    "Hash / VirusTotal": {
        "status": "Malware",
        "icon":   "🔴",
        "color":  RISK_COLORS["CRITICAL"],
        "bg":     RISK_BG["CRITICAL"],
        "message": "⚠️ *Warning:* This file is known to be malicious. *Delete it immediately* and do not share it with anyone.",
    },
    "DLP (PII)": {
        "status": "Detected",
        "icon":   "🟠",
        "color":  RISK_COLORS["HIGH"],
        "bg":     RISK_BG["HIGH"],
        "message": "🔒 *Privacy Alert:* The file contains sensitive information (National ID / IBAN / Mobile Number / Email). Make sure to *encrypt it* before sending.",
    },
    "Entropy": {
        "icon":    "🟠",
        "color":   RISK_COLORS["HIGH"],
        "bg":      RISK_BG["HIGH"],
        "message": "🔐 *High Entropy Detected:* The file appears to be encrypted or obfuscated. This is a common technique used to hide malware. Do *not run it* unless you fully trust the source.",
    },
    "Heuristics": {
        "icon":    "🟠",
        "color":   RISK_COLORS["HIGH"],
        "bg":      RISK_BG["HIGH"],
        "message": "🧩 *Suspicious Behavior Detected:* The file contains suspicious structural indicators commonly found in malware. Do *not run it* unless you fully trust the source.",
    },
    "File Signature": {
        "status": "Spoofed",
        "icon":   "🔴",
        "color":  RISK_COLORS["CRITICAL"],
        "bg":     RISK_BG["CRITICAL"],
        "message": "🚨 *Extension Spoofing Detected:* This file claims to be a document but is actually an executable. *Delete it immediately* — this is a classic malware delivery technique.",
    },
    "URL Analyzer": {
        "status": "Malicious",
        "icon":   "🔴",
        "color":  RISK_COLORS["CRITICAL"],
        "bg":     RISK_BG["CRITICAL"],
        "message": "⚠️ *Malicious Link:* This URL appears in threat blacklists. Do *not enter any personal information* on this site.",
    },
}

# ──────────────────────────────────────────────
# TAB LAYOUT — File Scanner | URL Scanner
# ──────────────────────────────────────────────
tab_file, tab_url = st.tabs(["📂  File Scanner", "🔗  URL Scanner"])

# ══════════════════════════════════════════════
# TAB 1 — FILE SCANNER
# ══════════════════════════════════════════════
with tab_file:

    st.markdown('<div class="cd-section">📂 Upload File for Scanning</div>', unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        "Supported formats: TXT, PDF, DOC, DOCX, XLS, XLSX, CSV,  JPG, JPEG, PNG, WEBP, BMP, TIFF",
        type=["txt", "pdf", "doc", "docx", "xls", "xlsx", "csv", "jpg", "jpeg", "png", "bmp", "tiff", "webp"],
        label_visibility="visible",
    )

    if uploaded_file:

        os.makedirs("temp", exist_ok=True)
        file_ext = os.path.splitext(uploaded_file.name)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext, dir="temp") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        # ── Safe default before spinner ──
        sig_result = {
            'real_type': 'Unknown', 'is_spoofed': False,
            'risk': 'LOW', 'score': 0,
            'note': 'Not checked yet', 'magic_bytes': ''
        }

        with st.spinner("🔍 Scanning file…"):
            from modules.file_signature import check_file_signature
            sig_result       = check_file_signature(tmp_path)
            dlp_result       = scan_for_pii(tmp_path)
            file_hash        = get_file_hash(tmp_path)
            hash_result      = check_hash_in_database(file_hash)
            vt_result        = check_virustotal(file_hash)
            entropy_result   = calculate_entropy(tmp_path)
            heuristic_result = heuristic_scan(tmp_path)

            risk = calculate_risk_score(
                hash_result,
                vt_result,
                entropy_result,
                heuristic_result,
                dlp_result,
                url_result=None,
                sig_result=sig_result,
            )

        score = risk["score"]
        level = risk["level"]

        log_file_scan(
            uploaded_file.name, score, level,
            hash_result, vt_result, entropy_result,
            heuristic_result, dlp_result, sig_result,
        )

        # Gauge color comes directly from RISK_COLORS to match risk_score.py
        gauge_clr = RISK_COLORS.get(level, PRIMARY)

        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown('<div class="cd-section">📊 CleanDrop Security Analysis Report</div>', unsafe_allow_html=True)

        col_gauge, col_details = st.columns([1, 2], gap="large")

        with col_gauge:
            try:
                import plotly.graph_objects as go

                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    title={"text": f"<b>{level}</b>", "font": {"size": 16, "color": gauge_clr}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": TEXT_COLOR, "tickvals": [0, 20, 40, 60, 80, 100], "ticktext": ["0", "20", "40", "60", "80", "100"]},
                        "bar":  {"color": gauge_clr},
                        "bgcolor": "rgba(0,0,0,0)",
                        "steps": [
                            {"range": [0,  20],  "color": "rgba(0, 200, 150, 0.08)"},
                            {"range": [20, 50],  "color": "rgba(255, 215, 0, 0.08)"},
                            {"range": [50, 80],  "color": "rgba(255, 122, 0, 0.08)"},
                            {"range": [80, 100], "color": "rgba(255, 45, 45, 0.08)"},
                        ],
                        "threshold": {
                            "line": {"color": gauge_clr, "width": 4},
                            "thickness": 0.8,
                            "value": score,
                        },
                    },
                    number={"suffix": "/100", "font": {"color": gauge_clr, "size": 40}},
                ))
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color=TEXT_COLOR,
                    margin=dict(t=30, b=10, l=30, r=30),
                    height=260,
                )
                st.plotly_chart(fig, use_container_width=True)

            except ImportError:
                st.markdown(
                    f"""<div style="width:160px;height:160px;border-radius:50%;
                    background:{gauge_clr};display:flex;align-items:center;
                    justify-content:center;font-size:2.2rem;font-weight:700;
                    color:#0E1117;margin:auto;">{score}</div>
                    <p style="text-align:center;margin-top:10px;font-weight:700;
                    color:{gauge_clr};">{level}</p>""",
                    unsafe_allow_html=True,
                )

            # Risk level badge below gauge
            st.markdown(
                f'<div style="text-align:center; margin-top:8px;">'
                f'<span style="background:{RISK_BG.get(level, RISK_BG["SAFE"])}; '
                f'color:{gauge_clr}; border:1px solid {gauge_clr}55; '
                f'padding:6px 20px; border-radius:20px; font-weight:700; '
                f'font-size:14px; letter-spacing:1px;">'
                f'{RISK_ICONS.get(level, "🛡️")} {level}'
                f'</span></div>',
                unsafe_allow_html=True
            )

        with col_details:
            st.markdown(f"**File:** {uploaded_file.name}")
            st.markdown(f"**Risk Level:** {level}")
            st.markdown(f"**AHP Score:** {score}/100")

            # ── Status badge helper — corrected color mapping ──
            def status_cell(status):
                s = str(status).upper()

                if s in ("MALWARE", "MALICIOUS", "CRITICAL", "SPOOFED"):
                    c, bg, icon = RISK_COLORS["CRITICAL"], RISK_BG["CRITICAL"], "🔴"
                elif s == "HIGH":
                    c, bg, icon = RISK_COLORS["HIGH"], RISK_BG["HIGH"], "🟠"
                elif s in ("MEDIUM", "DETECTED"):
                    c, bg, icon = RISK_COLORS["MEDIUM"], RISK_BG["MEDIUM"], "🟡"
                elif s == "LOW":
                    c, bg, icon = RISK_COLORS["LOW"], RISK_BG["LOW"], "🟢"
                else:
                    c, bg, icon = RISK_COLORS["SAFE"], RISK_BG["SAFE"], "🔵"
                    s = "SAFE"

                return (
                    f'<span style="background:{bg};color:{c};padding:2px 10px;'
                    f'border-radius:12px;font-size:12px;font-weight:700;">{icon} {s}</span>'
                )
            
            # Normalize hash status for display
            hash_display = hash_result["status"]
            if hash_display in ("DB_NOT_FOUND", "CLEAN", "ERROR"):
                hash_display = "SAFE"
 
            # Normalize VT status for display
            vt_display = vt_result["status"]
            if vt_display in ("NOT_FOUND", "CLEAN", "RATE_LIMIT", "CONNECTION_ERROR", "ERROR"):
                vt_display = "SAFE"
 
            # Normalize heuristic status — 0 indicators = SAFE not LOW
            heuristic_display = "SAFE" if heuristic_result["total_indicators"] == 0 else heuristic_result["risk"]
 
            # Normalize entropy status
            entropy_display = entropy_result["risk"]
 
            # Normalize DLP status
            dlp_display = "SAFE" if not dlp_result["pii_found"] else level

            
            table_rows = [
                {
                    "Module":  "Hash Engine",
                    "Status":  hash_display,
                    "Details": f"SHA256: {file_hash[:25]}..." if file_hash else "Hash error",
                    "Source":  "Local Malware Database",
                },
                {
                    "Module":  "VirusTotal",
                    "Status":  vt_display,
                    "Details": vt_result.get("detection_rate", "N/A"),
                    "Source":  "VirusTotal (70+ engines)",
                },
                {
                    "Module":  "Entropy Analysis",
                    "Status":  entropy_display,
                    "Details": f"Entropy value: {entropy_result.get('entropy', 'N/A')}",
                    "Source":  "Shannon Entropy",
                },
                {
                    "Module":  "Heuristic Detection",
                    "Status":  heuristic_display,
                    "Details": f"{heuristic_result.get('total_indicators', 0)} suspicious indicators found",
                    "Source":  "Static Behavioral Analysis",
                },
                {
                    "Module":  "DLP (Saudi PII Scanner)",
                    "Status":  dlp_display,
                    "Details": ", ".join(dlp_result["findings"].keys()) if dlp_result["findings"] else "No PII found",
                    "Source":  "Regex Pattern Matching",
                },
                {
                    "Module":  "File Signature Check",
                    "Status":  "SPOOFED" if sig_result["is_spoofed"] else "SAFE",
                    "Details": sig_result["note"] if sig_result["is_spoofed"] else "File type verified — no changes detected",
                    "Source":  "Magic Bytes Analysis",
                },
            ]

            st.markdown('<div class="cd-section" style="margin-top:8px;">🔬 Scan Results</div>', unsafe_allow_html=True)

            rows_html = "".join([
                f'<tr style="border-bottom:1px solid {PRIMARY}22;">'
                f'<td style="padding:10px 12px;font-size:13px;color:{TEXT_COLOR};">{r["Module"]}</td>'
                f'<td style="padding:10px 12px;">{status_cell(r["Status"])}</td>'
                f'<td style="padding:10px 12px;font-size:12px;color:{TEXT_COLOR};opacity:0.7;">{r["Details"]}</td>'
                f'<td style="padding:10px 12px;font-size:11px;color:{TEXT_COLOR};opacity:0.45;font-style:italic;">{r["Source"]}</td>'
                f'</tr>'
                for r in table_rows
            ])

            st.markdown(f"""
            <div style="border:1px solid {PRIMARY}33; border-radius:12px; overflow:hidden;">
              <table style="width:100%; border-collapse:collapse;">
                <thead>
                  <tr style="background:{CARD_BG};">
                    <th style="padding:10px 12px;text-align:left;font-size:12px;color:{PRIMARY};letter-spacing:1px;text-transform:uppercase;">Module</th>
                    <th style="padding:10px 12px;text-align:left;font-size:12px;color:{PRIMARY};letter-spacing:1px;text-transform:uppercase;">Status</th>
                    <th style="padding:10px 12px;text-align:left;font-size:12px;color:{PRIMARY};letter-spacing:1px;text-transform:uppercase;">Details</th>
                    <th style="padding:10px 12px;text-align:left;font-size:12px;color:{PRIMARY};letter-spacing:1px;text-transform:uppercase;">Source</th>
                  </tr>
                </thead>
                <tbody>{rows_html}</tbody>
              </table>
            </div>
            """, unsafe_allow_html=True)

        # ── Detected PII Detail Table ──
        if dlp_result["findings"]:
            st.markdown('<div class="cd-section">🔎 Detected Sensitive Data (Masked)</div>', unsafe_allow_html=True)
            pii_rows = []
            for pii_type, info in dlp_result["findings"].items():
                pii_rows.append({
                    "Data Type":        pii_type,
                    "Occurrences":      info["count"],
                    "Masked Sample(s)": ", ".join(info["samples"]),
                })
            st.dataframe(pd.DataFrame(pii_rows), use_container_width=True, hide_index=True)

        # ── Heuristic Findings Detail ──
        if heuristic_result.get("findings"):
            st.markdown('<div class="cd-section">🧩 Heuristic Findings</div>', unsafe_allow_html=True)
            h_rows = []
            for category, indicators in heuristic_result["findings"].items():
                h_rows.append({"Category": category, "Indicators": ", ".join(indicators)})
            st.dataframe(pd.DataFrame(h_rows), use_container_width=True, hide_index=True)

        # ── Smart Security Recommendations ──
        st.markdown('<div class="cd-section">🛡️ Smart Security Recommendations</div>', unsafe_allow_html=True)

        active_recs = []
        if hash_result["status"] == "MALWARE" or vt_result["status"] in ("MALWARE", "HIGH", "CRITICAL"):
            active_recs.append("Hash / VirusTotal")
        if dlp_result["pii_found"]:
            active_recs.append("DLP (PII)")
        if entropy_result["risk"] in ("HIGH", "CRITICAL"):
            active_recs.append("Entropy")
        if heuristic_result["risk"] in ("HIGH", "MEDIUM", "CRITICAL"):
            active_recs.append("Heuristics")
        if sig_result["is_spoofed"]:
            active_recs.append("File Signature")
        if active_recs:
            for key in active_recs:
                rec = RECOMMENDATIONS[key]
                st.markdown(
                    f'<div style="background:{rec["bg"]}; border:1px solid {rec["color"]}55; '
                    f'border-left:4px solid {rec["color"]}; border-radius:12px; '
                    f'padding:16px 20px; margin-bottom:12px;">'
                    f'<strong style="color:{rec["color"]};">{rec["icon"]} {key}</strong>'
                    f'<br><br>'
                    f'<span style="font-size:13px; color:{TEXT_COLOR}; opacity:0.85;">{rec["message"]}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                f'<div style="background:{RISK_BG["SAFE"]}; border:1px solid {RISK_COLORS["SAFE"]}55; '
                f'border-left:4px solid {RISK_COLORS["SAFE"]}; border-radius:12px; padding:16px 20px;">'
                f'<strong style="color:{RISK_COLORS["SAFE"]};">✅ No Threats Detected</strong><br>'
                f'<span style="font-size:13px; color:{TEXT_COLOR}; opacity:0.8;">This file appears to be safe.</span>'
                f'</div>',
                unsafe_allow_html=True
            )

        # Final alert banner using risk color
        if level == "CRITICAL":
            st.error("🚨 **CRITICAL Risk:** Do not open, share, or execute this file. Notify your IT/security team immediately.")
        elif level == "HIGH":
            st.warning("🔶 **High Risk:** Do not open this file. Investigate further before any action.")
        elif level == "MEDIUM":
            st.warning("🟡 **Medium Risk:** Review the file carefully before sharing. Mask or remove sensitive identifiers.")
        elif level == "LOW":
            st.info("🟢 **Low Risk:** Limited risk detected. Ensure only necessary data is included.")
        else:
            st.success("🔵 **Safe:** No threats detected. This file appears clean.")

        # ── PDF Report ──
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown('<div class="cd-section">📄 Download Report</div>', unsafe_allow_html=True)

        try:
            from modules.report_generator import generate_report

            import re
            os.makedirs("reports", exist_ok=True)
            clean_name = re.sub(r'[^\w\-.]', '_', uploaded_file.name)
            report_path = f"reports/{clean_name}_report.pdf"

            report_details = {
                "Hash Status":       hash_result["status"],
                "VirusTotal Status": vt_result["status"],
                "Entropy Risk":      f"{entropy_result['risk']} (value: {entropy_result.get('entropy', 'N/A')})",
                "Heuristic Risk":    f"{heuristic_result['risk']} ({heuristic_result.get('total_indicators', 0)} indicators)",
                "DLP Status":        level if dlp_result["pii_found"] else "Clean",
                "PII Types Found":   ", ".join(dlp_result["findings"].keys()) if dlp_result["findings"] else "None",
            
            }


            generate_report(uploaded_file.name, score, report_details, output_path=report_path)

            if os.path.exists(report_path):
                with open(report_path, "rb") as f:
                    pdf_bytes = f.read()
                st.download_button(
                    label="⬇️  Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"CleanDrop_Report_{clean_name}.pdf",
                    mime="application/pdf",
                )
        except Exception as e:
            st.info(f"📋 PDF report will be available once report_generator.py is fully integrated. ({e})")

        # Cleanup temp file
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    else:
        st.markdown(
            f"""
            <div class="cd-card" style="text-align:center; padding:40px;">
                <div style="font-size:3rem;">🛡️</div>
                <div style="font-size:1.2rem; font-weight:600; margin-top:12px; color:{PRIMARY};">
                    Ready to Scan
                </div>
                <div style="opacity:0.7; margin-top:8px;">
                    Upload a file above to begin the security analysis.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ══════════════════════════════════════════════
# TAB 2 — URL SCANNER
# ══════════════════════════════════════════════
with tab_url:

    st.markdown('<div class="cd-section">🔗 URL Security Scanner</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div style="color:{TEXT_COLOR}; opacity:0.7; font-size:14px; margin-bottom:16px;">'
        f'Enter any URL to check it.'
        f'</div>',
        unsafe_allow_html=True
    )

    url_input = st.text_input(
    "URL",
    placeholder="https://example.com  or just  example.com",
    label_visibility="collapsed"
    )
    
    check_clicked = st.button("Check URL", key="url_check_btn")

    if url_input and check_clicked:
        st.info("⏳ If this is a new or unknown URL, scanning may take up to 15 seconds — please wait.")
        with st.spinner("🔍 Checking URL against Google Safe Browsing + VirusTotal + Cloudflare Radar.."):            url_result = check_url(url_input)

        status  = url_result.get("status", "ERROR")
        source  = url_result.get("source", "")
        message = url_result.get("message", "")

        log_url_scan(
            url_input, status,
            url_result.get("score", 0),
            source,
            url_result.get("threats", []),
        )

        # ── SAFE ──
        if status == "SAFE":
            st.markdown(
                f'<div class="url-result-safe">'
                f'<strong style="color:{RISK_COLORS["SAFE"]}; font-size:1.1rem;">✅ URL is Safe</strong><br><br>'
                f'No threats detected for: <code>{url_input}</code><br>'
                f'<span style="opacity:0.7; font-size:13px;">Checked by: {source}</span>'
                f'</div>',
                unsafe_allow_html=True
            )

        # ── MALICIOUS ──
        elif status == "MALICIOUS":
            threats      = url_result.get("threats", [])
            det_rate     = url_result.get("detection_rate", "")
            all_sources  = url_result.get("all_sources", [])
            db_count     = url_result.get("databases_count", 1)
            source       = url_result.get("source", "")
            rec          = RECOMMENDATIONS["URL Analyzer"]
 
            # Format threat types — show actual types not just "detected by X engines"
            if threats:
                threat_str = ", ".join(threats)
            else:
                threat_str = "Unknown threat type"
 
            # Format detection sources
            if db_count > 1:
                source_badge = f"🔴 Found in {db_count} databases"
            else:
                source_badge = f"🔴 Found in {source}"
 
            st.markdown(
                f'<div class="url-result-danger">'
                f'<strong style="color:{RISK_COLORS["CRITICAL"]}; font-size:1.1rem;">🚨 Dangerous URL Detected</strong><br><br>'
                f'URL: <code>{url_input}</code><br><br>'
                f'<strong>Threat type(s):</strong> {threat_str}<br>'
                f'<strong>Detected by:</strong> {source_badge}<br>'
                + (f'<strong>VirusTotal detection rate:</strong> {det_rate}<br>' if det_rate and det_rate != "N/A" else "")
                + (f'<strong>All databases:</strong> {" | ".join(all_sources)}<br>' if len(all_sources) > 1 else "")
                + f'<br>{rec["message"]}'
                f'</div>',
                unsafe_allow_html=True
            )
        # ── SUSPICIOUS (new) ──
        elif status == "SUSPICIOUS":
            det_rate = url_result.get("detection_rate", "N/A")
            st.markdown(
                f'<div style="background:{RISK_BG["HIGH"]}; border:1px solid {RISK_COLORS["HIGH"]}; '
                f'border-radius:12px; padding:18px 22px; margin-top:12px;">'
                f'<strong style="color:{RISK_COLORS["HIGH"]}; font-size:1.1rem;">⚠️ Suspicious URL</strong><br><br>'
                f'URL: <code>{url_input}</code><br>'
                f'Detection rate: <strong>{det_rate}</strong><br>'
                f'Source: {source}<br><br>'
                f'<span style="font-size:13px; opacity:0.85;">'
                f'This URL was flagged as suspicious by some security engines. '
                f'It may not be safe — avoid entering personal information on this site.'
                f'</span>'
                f'</div>',
                unsafe_allow_html=True
            )

        # ── UNKNOWN (new) — not in any database ──
        elif status == "UNKNOWN":
            st.markdown(
                f'<div style="background:{RISK_BG["MEDIUM"]}; border:1px solid {RISK_COLORS["MEDIUM"]}; '
                f'border-radius:12px; padding:18px 22px; margin-top:12px;">'
                f'<strong style="color:{RISK_COLORS["MEDIUM"]}; font-size:1.1rem;">❓ Unknown URL</strong><br><br>'
                f'URL: <code>{url_input}</code><br><br>'
                f'<span style="font-size:13px; opacity:0.85;">'
                f'This URL was <strong>not found in any threat database</strong> '
                f'(Google Safe Browsing + VirusTotal). '
                f'This does <strong>not</strong> guarantee it is safe.<br><br>'
                f'⚠️ Proceed with caution — unknown links may still be dangerous.'
                f'</span>'
                f'</div>',
                unsafe_allow_html=True
            )

        # ── INVALID_URL ──
        elif status == "INVALID_URL":
            st.markdown(
                f'<div class="url-result-warn">'
                f'<strong style="color:{RISK_COLORS["MEDIUM"]};">⚠️ Invalid URL Format</strong><br><br>'
                f'The URL must start with <code>http://</code> or <code>https://</code><br>'
                f'Example: <code>https://example.com</code>'
                f'</div>',
                unsafe_allow_html=True
            )

        # ── RATE_LIMITED ──
        elif status == "RATE_LIMITED":
            st.markdown(
                f'<div class="url-result-warn">'
                f'<strong style="color:{RISK_COLORS["MEDIUM"]};">⏳ Too Many Requests</strong><br><br>'
                f'VirusTotal API rate limit reached (4 requests/minute).<br>'
                f'Please wait 60 seconds and try again.'
                f'</div>',
                unsafe_allow_html=True
            )

        # ── CONNECTION_ERROR ──
        elif status == "CONNECTION_ERROR":
            st.markdown(
                f'<div class="url-result-warn">'
                f'<strong style="color:{RISK_COLORS["MEDIUM"]};">⚠️ Connection Error</strong><br><br>'
                f'Could not reach threat databases. Please check your internet connection.'
                f'</div>',
                unsafe_allow_html=True
            )

        # ── Any other error ──
        else:
            st.markdown(
                f'<div class="url-result-warn">'
                f'<strong style="color:{RISK_COLORS["MEDIUM"]};">⚠️ {status}</strong><br><br>'
                f'Could not complete the URL check. Please verify your API keys.'
                f'</div>',
                unsafe_allow_html=True
            )

    elif not url_input:
        st.markdown(
            f"""
            <div class="cd-card" style="text-align:center; padding:40px;">
                <div style="font-size:3rem;">🔗</div>
                <div style="font-size:1.2rem; font-weight:600; margin-top:12px; color:{PRIMARY};">
                    URL Scanner Ready
                </div>
                <div style="opacity:0.7; margin-top:8px; font-size:14px;">
                    Enter a URL above and click Check URL to scan it.
                </div>
                <div style="opacity:0.5; margin-top:16px; font-size:12px;">
                    Powered by Google Safe Browsing API
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ──────────────────────────────────────────────
# FOOTER
# ──────────────────────────────────────────────
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown(
    f'<div style="text-align:center; color:{TEXT_COLOR}; opacity:0.4; font-size:12px; padding-bottom:1rem;">'
    f'CleanDrop &nbsp;·&nbsp; University of Bisha &nbsp;·&nbsp; Cyber Security Department'
    f'</div>',
    unsafe_allow_html=True
)