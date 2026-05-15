"""
Auth Module — CleanDrop Admin
===============================
Handles admin authentication via Supabase Auth.

Security standards applied:
  - Passwords never handled locally — Supabase Auth manages bcrypt hashing
  - Generic error messages — no distinction between wrong email vs wrong password
  - Rate limiting — 5 failed attempts triggers 15-minute lockout
  - Token expiry — session auto-invalidates when Supabase token expires
  - Lockout persists in session_state — survives page reruns
"""

import os
import time
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 15 * 60  # 15 minutes


def _get_client():
    from supabase import create_client
    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_KEY", "")
    if not url or not key:
        raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
    return create_client(url, key)


def _init_session():
    defaults = {
        "admin_authenticated": False,
        "admin_email":         None,
        "admin_token_expiry":  0,
        "login_attempts":      0,
        "lockout_until":       0,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


# ── Public API ────────────────────────────────────────────────────────────────

def is_authenticated() -> bool:
    """True if there is a valid, non-expired admin session."""
    _init_session()
    if not st.session_state.admin_authenticated:
        return False
    if time.time() > st.session_state.admin_token_expiry:
        _clear_session()
        return False
    return True


def is_locked_out() -> tuple:
    """Returns (locked: bool, seconds_remaining: int)."""
    _init_session()
    if st.session_state.lockout_until > time.time():
        remaining = int(st.session_state.lockout_until - time.time())
        return True, remaining
    return False, 0


def login(email: str, password: str) -> dict:
    """
    Authenticate against Supabase Auth.
    Returns {"success": bool, "error": str | None}
    """
    _init_session()

    locked, remaining = is_locked_out()
    if locked:
        mins = remaining // 60
        secs = remaining % 60
        return {
            "success": False,
            "error": f"Too many failed attempts. Try again in {mins}m {secs}s."
        }

    if not email.strip() or not password:
        return {"success": False, "error": "All fields are required."}

    try:
        client   = _get_client()
        response = client.auth.sign_in_with_password({
            "email":    email.strip().lower(),
            "password": password,
        })

        st.session_state.admin_authenticated = True
        st.session_state.admin_email         = response.user.email
        st.session_state.admin_token_expiry  = response.session.expires_at
        st.session_state.login_attempts      = 0
        st.session_state.lockout_until       = 0

        return {"success": True, "error": None}

    except Exception:
        st.session_state.login_attempts += 1

        if st.session_state.login_attempts >= MAX_ATTEMPTS:
            st.session_state.lockout_until = time.time() + LOCKOUT_SECONDS
            return {
                "success": False,
                "error": (
                    f"Account locked for 15 minutes after "
                    f"{MAX_ATTEMPTS} consecutive failed attempts."
                )
            }

        left = MAX_ATTEMPTS - st.session_state.login_attempts
        return {
            "success": False,
            "error": f"Invalid credentials. {left} attempt(s) remaining before lockout."
        }


def logout():
    """Sign out from Supabase and clear all local session state."""
    _init_session()
    try:
        _get_client().auth.sign_out()
    except Exception:
        pass
    _clear_session()


def get_current_user() -> str:
    """Return the email of the logged-in admin, or empty string."""
    _init_session()
    return st.session_state.get("admin_email") or ""


# ── Internal ──────────────────────────────────────────────────────────────────

def _clear_session():
    st.session_state.admin_authenticated = False
    st.session_state.admin_email         = None
    st.session_state.admin_token_expiry  = 0
