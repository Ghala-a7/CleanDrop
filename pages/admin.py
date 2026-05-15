import streamlit as st
import os
import io
import requests as req
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timezone, timedelta

# ── Page config must be the very first Streamlit call ─────────────────────────
st.set_page_config(
    page_title="CleanDrop Admin",
    page_icon="🛡️",
    layout="wide",
)

# ── Bridge Streamlit secrets → os.environ ────────────────────────────────────
try:
    for _k, _v in st.secrets.items():
        if isinstance(_v, str):
            os.environ.setdefault(_k, _v)
except Exception:
    pass

from modules.auth import (
    is_authenticated, is_locked_out, login, logout, get_current_user
)

PRIMARY    = "#00FFA3"
BG_COLOR   = "#0E1117"
CARD_BG    = "rgba(255,255,255,0.06)"
TEXT_COLOR = "#FFFFFF"

RISK_COLORS = {
    "SAFE":      "#3B82F6",
    "LOW":       "#22C55E",
    "MEDIUM":    "#FFD700",
    "HIGH":      "#FF7A00",
    "CRITICAL":  "#FF2D2D",
    "MALICIOUS": "#FF2D2D",
    "SUSPICIOUS":"#FF7A00",
    "UNKNOWN":   "#888888",
}

st.markdown(f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700&family=Roboto:wght@400;500;700&display=swap');
  @import url('https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css');

  html, body, [data-testid="stAppViewContainer"], .stApp {{
      background-color: {BG_COLOR} !important;
      color: {TEXT_COLOR} !important;
      font-family: 'Roboto', sans-serif;
  }}
  [data-testid="stSidebar"] {{
      background-color: #161B22 !important;
  }}
  [data-testid="stSidebar"] * {{ color: {TEXT_COLOR} !important; }}

  /* ── Buttons — target via Streamlit's own kind attribute ── */
  button[kind] {{
      background-color: {PRIMARY} !important;
      color: #0E1117 !important;
      font-weight: 700 !important;
      border: none !important;
      border-radius: 8px !important;
      padding: 0.5rem 1.2rem !important;
      font-family: 'Roboto', sans-serif !important;
      transition: opacity 0.2s !important;
  }}
  button[kind] *, button[kind] p, button[kind] span, button[kind] div {{
      color: #0E1117 !important;
  }}
  button[kind]:hover, button[kind]:focus, button[kind]:active {{
      background-color: {PRIMARY} !important;
      color: #0E1117 !important;
      opacity: 0.85 !important;
      border: none !important;
  }}

  .admin-logo {{
      font-family: 'Orbitron', sans-serif;
      font-size: 1.4rem;
      font-weight: 700;
      color: {PRIMARY};
      letter-spacing: 2px;
  }}
  .stat-card {{
      background: {CARD_BG};
      border: 1px solid {PRIMARY}33;
      border-radius: 14px;
      padding: 22px 24px;
      text-align: center;
  }}
  .stat-number {{
      font-size: 2.2rem;
      font-weight: 700;
      color: {PRIMARY};
  }}
  .stat-label {{
      font-size: 12px;
      color: #AAAAAA;
      margin-top: 4px;
      text-transform: uppercase;
      letter-spacing: 1px;
  }}
  .section-title {{
      font-size: 1rem;
      font-weight: 700;
      color: {PRIMARY};
      border-left: 4px solid {PRIMARY};
      padding-left: 10px;
      margin: 24px 0 14px;
  }}
  .alert-row {{
      background: rgba(255,45,45,0.08);
      border: 1px solid #FF2D2D33;
      border-radius: 10px;
      padding: 12px 16px;
      margin-bottom: 8px;
      font-size: 13px;
  }}
  .health-ok  {{ color: #22C55E; font-weight: 700; }}
  .health-err {{ color: #FF2D2D; font-weight: 700; }}
  .admin-card {{
      background: {CARD_BG};
      border: 1px solid {PRIMARY}33;
      border-radius: 16px;
      padding: 36px 40px;
      margin-top: 20px;
  }}
  .admin-subtitle {{ text-align:center; font-size:0.9rem; color:#AAAAAA; margin-bottom:28px; }}
  .attempt-bar {{
      background: rgba(255,122,0,0.12); border:1px solid #FF7A0055;
      border-radius:8px; padding:10px 16px; font-size:13px;
      color:#FF7A00; margin-bottom:12px;
  }}
  .lockout-bar {{
      background: rgba(255,45,45,0.12); border:1px solid #FF2D2D55;
      border-radius:8px; padding:10px 16px; font-size:13px;
      color:#FF2D2D; margin-bottom:12px;
  }}
  hr {{ border-color: {PRIMARY}22; }}
  label, .stTextInput label, .stSelectbox label, .stRadio label {{
      color: {TEXT_COLOR} !important;
  }}
  [data-testid="stSidebarNav"] {{ display: none !important; }}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# DATA HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _supabase():
    from supabase import create_client
    return create_client(
        os.environ.get("SUPABASE_URL", ""),
        os.environ.get("SUPABASE_KEY", ""),
    )


def fetch_logs() -> pd.DataFrame:
    try:
        rows = _supabase().table("scan_logs").select("*").order("created_at", desc=True).execute().data
        if not rows:
            return pd.DataFrame()
        df = pd.DataFrame(rows)
        df["created_at"] = pd.to_datetime(df["created_at"], utc=True)
        return df
    except Exception as e:
        st.error(f"Could not load scan logs: {e}")
        return pd.DataFrame()


def fetch_hash_count() -> int:
    try:
        res = _supabase().table("hashes").select("id", count="exact").execute()
        return res.count or 0
    except Exception:
        return 0


# ══════════════════════════════════════════════════════════════════════════════
# LOGIN VIEW
# ══════════════════════════════════════════════════════════════════════════════

def show_login():
    col = st.columns([1, 2, 1])[1]
    with col:
        st.markdown(
            f'<div class="admin-logo" style="text-align:center;">'
            f'<i class="bi bi-shield-fill-check" style="color:{PRIMARY};"></i> CleanDrop</div>',
            unsafe_allow_html=True
        )
        st.markdown('<div class="admin-subtitle">Admin Access — Authorized Personnel Only</div>', unsafe_allow_html=True)
        st.markdown('<div class="admin-card">', unsafe_allow_html=True)

        locked, remaining = is_locked_out()
        if locked:
            mins, secs = remaining // 60, remaining % 60
            st.markdown(
                f'<div class="lockout-bar">'
                f'<i class="bi bi-lock-fill"></i> Locked — try again in {mins}m {secs}s</div>',
                unsafe_allow_html=True
            )

        attempts = st.session_state.get("login_attempts", 0)
        if attempts > 0 and not locked:
            st.markdown(
                f'<div class="attempt-bar">'
                f'<i class="bi bi-exclamation-triangle-fill"></i> '
                f'{attempts} failed attempt(s) — {5 - attempts} remaining before lockout</div>',
                unsafe_allow_html=True
            )

        with st.form("admin_login_form", clear_on_submit=False):
            st.markdown(f'<p style="font-weight:600;color:{PRIMARY};margin-bottom:4px;">Email</p>', unsafe_allow_html=True)
            email = st.text_input("Email", placeholder="admin@example.com", label_visibility="collapsed")
            st.markdown(f'<p style="font-weight:600;color:{PRIMARY};margin-bottom:4px;margin-top:12px;">Password</p>', unsafe_allow_html=True)
            password = st.text_input("Password", type="password", placeholder="••••••••", label_visibility="collapsed")
            st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
            submitted = st.form_submit_button("Sign In", disabled=locked, use_container_width=True)

        if submitted and not locked:
            with st.spinner("Authenticating…"):
                result = login(email, password)
            if result["success"]:
                st.rerun()
            else:
                st.error(result["error"])

        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown(
            '<p style="text-align:center;font-size:11px;color:#888888;margin-top:24px;">'
            'CleanDrop · University of Bisha · Cyber Security Dept.</p>',
            unsafe_allow_html=True
        )


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD TABS
# ══════════════════════════════════════════════════════════════════════════════

def tab_overview(df: pd.DataFrame):
    if df.empty:
        st.info("No scan data yet.")
        return

    today = datetime.now(timezone.utc).date()
    df_today      = df[df["created_at"].dt.date == today]
    threats       = df[df["risk_level"].isin(["CRITICAL", "HIGH", "MALICIOUS"])]
    threats_today = df_today[df_today["risk_level"].isin(["CRITICAL", "HIGH", "MALICIOUS"])]

    # ── Stats row ────────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4, gap="medium")
    for col, number, label in [
        (c1, len(df),            "Total Scans"),
        (c2, len(df_today),      "Scans Today"),
        (c3, len(threats),       "Threats Detected"),
        (c4, len(threats_today), "Threats Today"),
    ]:
        col.markdown(
            f'<div class="stat-card">'
            f'<div class="stat-number">{number}</div>'
            f'<div class="stat-label">{label}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
    col_chart1, col_chart2 = st.columns(2, gap="medium")

    # ── Risk distribution donut ───────────────────────────────────────────────
    with col_chart1:
        st.markdown('<div class="section-title">Risk Level Distribution</div>', unsafe_allow_html=True)
        risk_counts = df["risk_level"].value_counts().reset_index()
        risk_counts.columns = ["risk_level", "count"]
        colors = [RISK_COLORS.get(r, "#888") for r in risk_counts["risk_level"]]
        fig = go.Figure(go.Pie(
            labels=risk_counts["risk_level"],
            values=risk_counts["count"],
            hole=0.55,
            marker=dict(colors=colors, line=dict(color="#0E1117", width=2)),
            textinfo="label+percent",
            textfont=dict(color=TEXT_COLOR, size=12),
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color=TEXT_COLOR,
            showlegend=False,
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Scans per day bar chart ───────────────────────────────────────────────
    with col_chart2:
        st.markdown('<div class="section-title">Scans — Last 14 Days</div>', unsafe_allow_html=True)
        df["date"] = df["created_at"].dt.date
        cutoff = today - timedelta(days=13)
        daily  = df[df["date"] >= cutoff].groupby("date").size().reset_index(name="count")
        all_dates = pd.date_range(cutoff, today).date
        daily = daily.set_index("date").reindex(all_dates, fill_value=0).reset_index()
        daily.columns = ["date", "count"]

        fig2 = go.Figure(go.Bar(
            x=daily["date"].astype(str),
            y=daily["count"],
            marker_color=PRIMARY,
            marker_line_width=0,
        ))
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color=TEXT_COLOR,
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
            xaxis=dict(showgrid=False, tickangle=-45, tickfont=dict(size=10)),
            yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Recent critical & high alerts ─────────────────────────────────────────
    st.markdown('<div class="section-title">Recent Critical &amp; High Alerts</div>', unsafe_allow_html=True)
    recent_threats = threats.head(10)
    if recent_threats.empty:
        st.success("No critical or high threats detected.")
    else:
        for _, row in recent_threats.iterrows():
            clr  = RISK_COLORS.get(row["risk_level"], "#888")
            icon = (
                '<i class="bi bi-folder2-open"></i>'
                if row["scan_type"] == "file"
                else '<i class="bi bi-link-45deg"></i>'
            )
            ts = row["created_at"].strftime("%Y-%m-%d %H:%M UTC")
            st.markdown(
                f'<div class="alert-row">'
                f'{icon} <strong style="color:{clr};">[{row["risk_level"]}]</strong> '
                f'&nbsp;{row["target"]}&nbsp;'
                f'<span style="color:#AAAAAA;float:right;font-size:12px;">{ts}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )


def tab_scan_logs(df: pd.DataFrame):
    if df.empty:
        st.info("No scan logs yet.")
        return

    st.markdown('<div class="section-title">Filters</div>', unsafe_allow_html=True)
    fc1, fc2, fc3 = st.columns(3, gap="medium")

    with fc1:
        scan_type_filter = st.selectbox("Scan Type", ["All", "file", "url"])
    with fc2:
        risk_options = ["All"] + sorted(df["risk_level"].unique().tolist())
        risk_filter  = st.selectbox("Risk Level", risk_options)
    with fc3:
        date_options = ["All time", "Today", "Last 7 days", "Last 30 days"]
        date_filter  = st.selectbox("Period", date_options)

    filtered = df.copy()
    today = datetime.now(timezone.utc).date()

    if scan_type_filter != "All":
        filtered = filtered[filtered["scan_type"] == scan_type_filter]
    if risk_filter != "All":
        filtered = filtered[filtered["risk_level"] == risk_filter]
    if date_filter == "Today":
        filtered = filtered[filtered["created_at"].dt.date == today]
    elif date_filter == "Last 7 days":
        filtered = filtered[filtered["created_at"].dt.date >= today - timedelta(days=7)]
    elif date_filter == "Last 30 days":
        filtered = filtered[filtered["created_at"].dt.date >= today - timedelta(days=30)]

    st.markdown(f'<div class="section-title">Scan Logs ({len(filtered)} records)</div>', unsafe_allow_html=True)

    if filtered.empty:
        st.info("No records match the selected filters.")
        return

    display = filtered[["scan_type", "target", "risk_level", "score", "created_at"]].copy()
    display.columns = ["Type", "Target", "Risk Level", "Score", "Timestamp"]
    display["Timestamp"] = display["Timestamp"].dt.strftime("%Y-%m-%d %H:%M UTC")
    display["Score"]     = display["Score"].apply(lambda x: f"{x}/100" if x is not None else "—")

    st.dataframe(display, use_container_width=True, hide_index=True)

    st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)
    csv_buf = io.StringIO()
    display.to_csv(csv_buf, index=False)
    st.download_button(
        label="Export as CSV",
        data=csv_buf.getvalue().encode("utf-8"),
        file_name=f"cleandrop_logs_{today}.csv",
        mime="text/csv",
    )


def tab_hash_db():
    count = fetch_hash_count()

    st.markdown(
        f'<div class="stat-card" style="max-width:280px;">'
        f'<div class="stat-number">{count:,}</div>'
        f'<div class="stat-label">Malware Hashes in Database</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    st.markdown("<div style='margin-top:24px;'></div>", unsafe_allow_html=True)
    col_add, col_del = st.columns(2, gap="large")

    # ── Add hash ─────────────────────────────────────────────────────────────
    with col_add:
        st.markdown('<div class="section-title">Add Hash</div>', unsafe_allow_html=True)
        with st.form("add_hash_form"):
            new_hash = st.text_input("SHA256 Hash (64 hex characters)", placeholder="e3b0c44298fc1c14...")
            add_submitted = st.form_submit_button("Add Hash")

        if add_submitted:
            h = new_hash.strip().lower()
            if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
                st.error("Invalid SHA256 hash — must be exactly 64 hexadecimal characters.")
            else:
                try:
                    _supabase().table("hashes").upsert({"hash": h}, on_conflict="hash").execute()
                    st.success("Hash added successfully.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to add hash: {e}")

    # ── Remove hash ───────────────────────────────────────────────────────────
    with col_del:
        st.markdown('<div class="section-title">Remove Hash</div>', unsafe_allow_html=True)
        with st.form("del_hash_form"):
            del_hash = st.text_input("SHA256 Hash to remove", placeholder="e3b0c44298fc1c14...")
            del_submitted = st.form_submit_button("Remove Hash", type="primary")

        if del_submitted:
            h = del_hash.strip().lower()
            if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
                st.error("Invalid SHA256 hash.")
            else:
                try:
                    res = _supabase().table("hashes").delete().eq("hash", h).execute()
                    if res.data:
                        st.success("Hash removed.")
                        st.rerun()
                    else:
                        st.warning("Hash not found in database.")
                except Exception as e:
                    st.error(f"Failed to remove: {e}")


def _supabase_admin():
    """Service-role client — required for Auth admin operations."""
    from supabase import create_client
    url         = os.environ.get("SUPABASE_URL", "")
    service_key = os.environ.get("SUPABASE_SERVICE_KEY", "")
    if not service_key or service_key == "your_service_role_key_here":
        raise ValueError("SUPABASE_SERVICE_KEY is not configured.")
    return create_client(url, service_key)


def _validate_password(password: str) -> list:
    """Return list of unmet password requirements."""
    errors = []
    if len(password) < 8:
        errors.append("At least 8 characters")
    if not any(c.isupper() for c in password):
        errors.append("At least one uppercase letter (A-Z)")
    if not any(c.islower() for c in password):
        errors.append("At least one lowercase letter (a-z)")
    if not any(c.isdigit() for c in password):
        errors.append("At least one number (0-9)")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("At least one special character (!@#$…)")
    return errors


def tab_users():
    try:
        client = _supabase_admin()
    except ValueError as e:
        st.error(str(e))
        st.info("Add SUPABASE_SERVICE_KEY (service_role key) to your .env and Streamlit secrets. "
                "Find it in Supabase → Settings → API → service_role.")
        return

    try:
        users = client.auth.admin.list_users()
    except Exception as e:
        st.error(f"Could not fetch users: {e}")
        return

    current_email = get_current_user()

    st.markdown('<div class="section-title">Admin Users</div>', unsafe_allow_html=True)

    if not users:
        st.info("No users found.")
    else:
        for user in users:
            email   = user.email or "—"
            uid     = user.id
            created = user.created_at
            if hasattr(created, "strftime"):
                created_str = created.strftime("%Y-%m-%d %H:%M UTC")
            else:
                created_str = str(created)[:16]

            is_self = email == current_email

            col_info, col_edit, col_del = st.columns([4, 1, 1], gap="small")

            with col_info:
                badge = (
                    f'<span style="background:rgba(0,255,163,0.15);color:{PRIMARY};'
                    f'padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px;">YOU</span>'
                    if is_self else ""
                )
                st.markdown(
                    f'<div style="background:{CARD_BG};border:1px solid {PRIMARY}22;'
                    f'border-radius:10px;padding:12px 16px;">'
                    f'<strong>{email}</strong>{badge}'
                    f'<div style="font-size:11px;color:#AAAAAA;margin-top:4px;">'
                    f'Created: {created_str} &nbsp;·&nbsp; ID: {uid[:8]}…</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            with col_edit:
                if st.button("Edit", key=f"edit_{uid}"):
                    st.session_state[f"editing_{uid}"] = not st.session_state.get(f"editing_{uid}", False)

            with col_del:
                if not is_self:
                    if st.button("Delete", key=f"del_{uid}"):
                        st.session_state[f"confirm_del_{uid}"] = True

            # ── Confirm delete ────────────────────────────────────────────────
            if st.session_state.get(f"confirm_del_{uid}"):
                st.warning(f"Delete **{email}**? This cannot be undone.")
                c1, c2, _ = st.columns([1, 1, 4])
                with c1:
                    if st.button("Yes, delete", key=f"confirm_yes_{uid}"):
                        try:
                            client.auth.admin.delete_user(uid)
                            st.success(f"{email} deleted.")
                            st.session_state.pop(f"confirm_del_{uid}", None)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Delete failed: {e}")
                with c2:
                    if st.button("Cancel", key=f"confirm_no_{uid}"):
                        st.session_state.pop(f"confirm_del_{uid}", None)
                        st.rerun()

            # ── Inline edit form ──────────────────────────────────────────────
            if st.session_state.get(f"editing_{uid}"):
                with st.form(f"edit_form_{uid}"):
                    st.markdown(f"**Change password for** `{email}`")
                    new_pw  = st.text_input("New Password",     type="password", key=f"np_{uid}")
                    conf_pw = st.text_input("Confirm Password", type="password", key=f"cp_{uid}")
                    save    = st.form_submit_button("Save Changes")

                if save:
                    issues = _validate_password(new_pw)
                    if issues:
                        for issue in issues:
                            st.error(f"• {issue}")
                    elif new_pw != conf_pw:
                        st.error("Passwords do not match.")
                    else:
                        try:
                            client.auth.admin.update_user_by_id(uid, {"password": new_pw})
                            st.success(f"Password updated for {email}.")
                            st.session_state.pop(f"editing_{uid}", None)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Update failed: {e}")

            st.markdown("<div style='margin-bottom:6px;'></div>", unsafe_allow_html=True)

    # ── Add new user ──────────────────────────────────────────────────────────
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">Add New Admin User</div>', unsafe_allow_html=True)

    with st.form("add_user_form"):
        new_email   = st.text_input("Email address")
        new_pw      = st.text_input("Password",         type="password")
        new_pw_conf = st.text_input("Confirm Password", type="password")
        submitted   = st.form_submit_button("Create User")

    if submitted:
        issues = _validate_password(new_pw)
        if not new_email.strip():
            st.error("Email is required.")
        elif "@" not in new_email:
            st.error("Enter a valid email address.")
        elif issues:
            for issue in issues:
                st.error(f"• {issue}")
        elif new_pw != new_pw_conf:
            st.error("Passwords do not match.")
        else:
            try:
                client.auth.admin.create_user({
                    "email":         new_email.strip().lower(),
                    "password":      new_pw,
                    "email_confirm": True,
                })
                st.success(f"User {new_email} created successfully.")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to create user: {e}")


def tab_api_health():
    st.markdown('<div class="section-title">API Status Check</div>', unsafe_allow_html=True)

    if st.button("Run Health Check"):
        results = {}

        with st.spinner("Checking APIs…"):
            # VirusTotal
            try:
                r = req.get(
                    "https://www.virustotal.com/api/v3/",
                    headers={"x-apikey": os.environ.get("VIRUSTOTAL_API_KEY", "")},
                    timeout=6,
                )
                results["VirusTotal"] = (True, f"HTTP {r.status_code}")
            except Exception as e:
                results["VirusTotal"] = (False, str(e))

            # Google Safe Browsing
            try:
                r = req.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                    f"?key={os.environ.get('GOOGLE_API_KEY', '')}",
                    json={
                        "client": {"clientId": "cleandrop", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": [], "platformTypes": [],
                            "threatEntryTypes": [], "threatEntries": [],
                        },
                    },
                    timeout=6,
                )
                results["Google Safe Browsing"] = (True, f"HTTP {r.status_code}")
            except Exception as e:
                results["Google Safe Browsing"] = (False, str(e))

            # Cloudflare Radar
            try:
                r = req.get(
                    "https://api.cloudflare.com/client/v4/radar/ranking/domain/google.com",
                    headers={"Authorization": f"Bearer {os.environ.get('CLOUDFLARE_TOKEN', '')}"},
                    timeout=6,
                )
                results["Cloudflare Radar"] = (True, f"HTTP {r.status_code}")
            except Exception as e:
                results["Cloudflare Radar"] = (False, str(e))

            # Supabase
            try:
                _supabase().table("scan_logs").select("id").limit(1).execute()
                results["Supabase"] = (True, "Connection OK")
            except Exception as e:
                results["Supabase"] = (False, str(e))

        for api, (ok, detail) in results.items():
            clr    = "#22C55E" if ok else "#FF2D2D"
            bg     = "rgba(34,197,94,0.08)" if ok else "rgba(255,45,45,0.08)"
            border = "rgba(34,197,94,0.3)"  if ok else "rgba(255,45,45,0.3)"
            icon   = '<i class="bi bi-check-circle-fill"></i>' if ok else '<i class="bi bi-x-circle-fill"></i>'
            label  = "Online" if ok else "Unreachable"
            st.markdown(
                f'<div style="background:{bg};border:1px solid {border};border-radius:10px;'
                f'padding:14px 18px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;">'
                f'<span style="font-weight:600;">{api}</span>'
                f'<span style="color:{clr};font-weight:700;">{icon} {label}</span>'
                f'<span style="color:#AAAAAA;font-size:12px;">{detail}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div style="color:#AAAAAA;font-size:14px;">Click the button above to check all API connections.</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD SHELL
# ══════════════════════════════════════════════════════════════════════════════

def show_dashboard():
    with st.sidebar:
        st.markdown(
            f'<div style="color:{PRIMARY};font-weight:700;font-size:14px;">'
            f'<i class="bi bi-shield-fill-check"></i> Admin Panel</div>',
            unsafe_allow_html=True
        )
        st.markdown(f'<div style="font-size:12px;color:#AAAAAA;margin-bottom:12px;">{get_current_user()}</div>', unsafe_allow_html=True)
        st.markdown("---")
        if st.button("Sign Out"):
            logout()
            st.rerun()

    st.markdown(
        f'<div class="admin-logo">'
        f'<i class="bi bi-shield-fill-check" style="color:{PRIMARY};"></i> CleanDrop — Admin Dashboard</div>',
        unsafe_allow_html=True
    )
    st.markdown("<hr style='margin:10px 0 20px;'>", unsafe_allow_html=True)

    df = fetch_logs()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "  Overview",
        "  Scan Logs",
        "  Hash Database",
        "  Users",
        "  API Health",
    ])

    with tab1:
        tab_overview(df)
    with tab2:
        tab_scan_logs(df)
    with tab3:
        tab_hash_db()
    with tab4:
        tab_users()
    with tab5:
        tab_api_health()


# ══════════════════════════════════════════════════════════════════════════════
# ROUTER
# ══════════════════════════════════════════════════════════════════════════════
if is_authenticated():
    show_dashboard()
else:
    show_login()
