"""Authentication endpoints: login form, POST login handler, registration, consent."""

import re
from html import escape
from urllib.parse import quote_plus, urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.auth.service import authenticate_user, register_user_request, accept_user_consent, get_user_by_id
from app.auth.session import create_session, delete_session
from app.db.session import get_db
from app.security.password import hash_password

router = APIRouter(prefix="", tags=["auth"])


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> str:
    """Display the login form.

    Renders a simple HTML form for username/password entry.

    Query params:
        redirect_to: (optional) Where to redirect after successful login.
        error: (optional) Error message to display.

    Returns:
        HTML form page.
    """
    redirect_to = request.query_params.get("redirect_to", "/login")
    error = request.query_params.get("error", "")

    error_html = ""
    if error:
        error_html = f'<div class="error-msg">{error}</div>'

    safe_redirect_to = escape(redirect_to, quote=True)

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RhAISE &ndash; Login</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
            *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

            :root {{
                --rm-white: #FFFFFF;
                --rm-dark-blue: #00406E;
                --rm-light-blue: #007EC1;
                --rm-dark-grey: #3E3D40;
                --rm-light-grey: #ECECEC;
                --rm-medium-grey: #c7c7c7;
                --rm-shadow-grey: rgba(0, 0, 0, 0.12);
                --radius-m: 6px;
                --radius-l: 12px;
                --font-base: "Roboto", sans-serif;
            }}

            html, body {{
                height: 100%;
                font-family: var(--font-base);
                color: var(--rm-dark-grey);
                font-size: 14px;
                line-height: 20px;
                background: var(--rm-light-grey);
            }}

            .page-wrapper {{
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                background: linear-gradient(135deg, var(--rm-dark-blue) 0%, #006aaa 60%, var(--rm-light-blue) 100%);
            }}

            .login-card {{
                background: var(--rm-white);
                border-radius: var(--radius-l);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.18);
                padding: 48px 40px 40px;
                width: 100%;
                max-width: 420px;
            }}

            .logo-area {{
                display: flex;
                justify-content: center;
                margin-bottom: 32px;
            }}

            .logo-area img {{
                height: 48px;
                width: auto;
            }}

            .login-card h2 {{
                font-size: 20px;
                font-weight: 500;
                color: var(--rm-dark-blue);
                margin-bottom: 24px;
                text-align: center;
            }}

            .form-group {{
                margin-bottom: 16px;
            }}

            .form-group label {{
                display: block;
                font-size: 13px;
                font-weight: 500;
                color: var(--rm-dark-grey);
                margin-bottom: 6px;
            }}

            .form-group input {{
                width: 100%;
                padding: 10px 12px;
                border: 1px solid var(--rm-medium-grey);
                border-radius: var(--radius-m);
                font-family: var(--font-base);
                font-size: 14px;
                color: var(--rm-dark-grey);
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
                outline: none;
            }}

            .form-group input:focus {{
                border-color: var(--rm-light-blue);
                box-shadow: 0 0 0 3px rgba(0, 126, 193, 0.15);
            }}

            .form-group input::placeholder {{
                color: #909297;
            }}

            .btn-login {{
                width: 100%;
                padding: 11px 16px;
                margin-top: 8px;
                background-color: var(--rm-light-blue);
                color: var(--rm-white);
                border: none;
                border-radius: var(--radius-m);
                font-family: var(--font-base);
                font-size: 15px;
                font-weight: 500;
                cursor: pointer;
                transition: background-color 0.2s ease, box-shadow 0.2s ease;
            }}

            .btn-login:hover {{
                background-color: var(--rm-dark-blue);
                box-shadow: 0 2px 6px var(--rm-shadow-grey);
            }}

            .error-msg {{
                background: #fff0f0;
                border: 1px solid #f5c6c6;
                border-radius: var(--radius-m);
                color: #c0392b;
                font-size: 13px;
                padding: 10px 12px;
                margin-bottom: 16px;
            }}

            .footer-note {{
                text-align: center;
                margin-top: 24px;
                font-size: 12px;
                color: rgba(255,255,255,0.6);
            }}
        </style>
    </head>
    <body>
        <div class="page-wrapper">
            <div class="login-card">
                <div class="logo-area">
                    <img src="/static/logo.png" alt="RhAISE Logo">
                </div>
                <h2>Sign in to RhAISE</h2>
                {error_html}
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Email</label>
                        <input id="username" type="email" name="username" placeholder="you@example.com" required autocomplete="email">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input id="password" type="password" name="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required autocomplete="current-password">
                    </div>
                    <input type="hidden" name="redirect_to" value="{safe_redirect_to}">
                    <button class="btn-login" type="submit">Sign in</button>
                    <a href="/register" style="display:block;text-align:center;margin-top:16px;font-size:13px;color:var(--rm-light-blue);text-decoration:none;">Request access &rarr;</a>
                </form>
            </div>
            <p class="footer-note">RhAISE &mdash; Rheinmetall AI Engineering Suite</p>
        </div>
    </body>
    </html>
    """
    return html


@router.post("/login")
async def login_handler(
    username: str = Form(...),
    password: str = Form(...),
    redirect_to: str = Form("/login"),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Handle login form submission.

    Authenticates the user and creates a session.

    Args:
        username: Email address from form.
        password: Password from form.
        redirect_to: URL to redirect to after successful login.
        db: Database session.

    Returns:
        Redirect response on success, or back to login with error.
    """
    user = authenticate_user(db, username, password)

    if not user:
        # Authentication failed – return to login with error message
        encoded_redirect = quote_plus(redirect_to)
        return RedirectResponse(
            url=f"/login?error=Invalid+credentials&redirect_to={encoded_redirect}",
            status_code=302,
        )

    # Create session for authenticated user
    session_id = create_session(user.id)

    # Enforce onboarding: users who are not registered or have not accepted the
    # Terms of Use must complete the consent flow (accept ToU, confirm AI
    # training, and reset their password if not yet registered) before they can
    # continue to the requested destination.
    if not user.registered or not user.accepted_tou:
        response = RedirectResponse(
            url=f"/consent?redirect_to={quote_plus(redirect_to)}",
            status_code=302,
        )
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            max_age=3600,  # 1 hour
        )
        return response

    # Keep redirects local and avoid non-existent root path fallback.
    target_redirect = redirect_to if redirect_to.startswith("/") and redirect_to != "/" else "/login"

    # Redirect to the requested URL (or default to home)
    response = RedirectResponse(url=target_redirect, status_code=302)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        max_age=3600,  # 1 hour
    )
    return response


@router.get("/logout")
async def logout_handler(request: Request, redirect_to: str = "/login") -> RedirectResponse:
    """Clear provider session cookie and invalidate DB session row."""
    session_id = request.cookies.get("session_id")
    if session_id:
        delete_session(session_id)

    response = RedirectResponse(url=redirect_to, status_code=302)
    response.delete_cookie("session_id")
    return response


# ---------------------------------------------------------------------------
# Registration: "Request Access" flow
# ---------------------------------------------------------------------------

_SHARED_STYLES = """
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
        --rm-white: #FFFFFF; --rm-dark-blue: #00406E; --rm-light-blue: #007EC1;
        --rm-dark-grey: #3E3D40; --rm-light-grey: #ECECEC; --rm-medium-grey: #c7c7c7;
        --rm-shadow-grey: rgba(0,0,0,0.12); --radius-m: 6px; --radius-l: 12px;
        --font-base: "Roboto", sans-serif;
    }
    html, body { height: 100%; font-family: var(--font-base); color: var(--rm-dark-grey);
        font-size: 14px; line-height: 20px; background: var(--rm-light-grey); }
    .page-wrapper { min-height: 100vh; display: flex; flex-direction: column;
        align-items: center; justify-content: center;
        background: linear-gradient(135deg, var(--rm-dark-blue) 0%, #006aaa 60%, var(--rm-light-blue) 100%); }
    .card { background: var(--rm-white); border-radius: var(--radius-l);
        box-shadow: 0 8px 32px rgba(0,0,0,0.18); padding: 48px 40px 40px;
        width: 100%; max-width: 480px; }
    .logo-area { display: flex; justify-content: center; margin-bottom: 32px; }
    .logo-area img { height: 48px; width: auto; }
    .card h2 { font-size: 20px; font-weight: 500; color: var(--rm-dark-blue);
        margin-bottom: 8px; text-align: center; }
    .card .subtitle { font-size: 13px; color: #666; text-align: center; margin-bottom: 24px; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 13px; font-weight: 500;
        color: var(--rm-dark-grey); margin-bottom: 6px; }
    .form-group input[type=email], .form-group input[type=text], .form-group input[type=password] {
        width: 100%; padding: 10px 12px; border: 1px solid var(--rm-medium-grey);
        border-radius: var(--radius-m); font-family: var(--font-base); font-size: 14px;
        color: var(--rm-dark-grey); outline: none; }
    .form-group input:focus { border-color: var(--rm-light-blue);
        box-shadow: 0 0 0 3px rgba(0,126,193,0.15); }
    .btn-primary { width: 100%; padding: 11px 16px; margin-top: 8px;
        background-color: var(--rm-light-blue); color: var(--rm-white); border: none;
        border-radius: var(--radius-m); font-family: var(--font-base); font-size: 15px;
        font-weight: 500; cursor: pointer; }
    .btn-primary:hover { background-color: var(--rm-dark-blue); }
    .btn-secondary { display: block; text-align: center; margin-top: 12px;
        font-size: 13px; color: var(--rm-light-blue); text-decoration: none; }
    .btn-secondary:hover { text-decoration: underline; }
    .alert { padding: 10px 12px; border-radius: var(--radius-m); font-size: 13px;
        margin-bottom: 16px; }
    .alert-danger { background: #fff0f0; border: 1px solid #f5c6c6; color: #c0392b; }
    .alert-success { background: #f0fff4; border: 1px solid #b7ebc8; color: #1a6b37; }
    .alert-warning { background: #fffbea; border: 1px solid #f0d060; color: #7a4900; }
    .check-group { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 14px; }
    .check-group input[type=checkbox] { margin-top: 3px; flex-shrink: 0; width: 16px; height: 16px; }
    .check-group label { font-size: 13px; line-height: 1.5; cursor: pointer; }
    .footer-note { text-align: center; margin-top: 24px; font-size: 12px;
        color: rgba(255,255,255,0.6); }
"""


def _html_page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} &ndash; RhAISE</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
    <style>{_SHARED_STYLES}</style>
</head>
<body>
    <div class="page-wrapper">
        <div class="card">
            <div class="logo-area"><img src="/static/logo.png" alt="RhAISE Logo"></div>
            {body}
        </div>
        <p class="footer-note">RhAISE &mdash; Rheinmetall AI Engineering Suite</p>
    </div>
</body>
</html>"""


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> str:
    """Display the registration (access request) form."""
    status = request.query_params.get("status", "")
    alert = ""
    if status == "exists":
        alert = '<div class="alert alert-warning">An access request for this e-mail already exists. Contact support if you need help.</div>'
    elif status == "error":
        alert = '<div class="alert alert-danger">An error occurred. Please try again later.</div>'
    elif status == "success":
        alert = '<div class="alert alert-success">Your request has been submitted. The RHAI team will review it and enable your account.</div>'
    elif status == "invalid":
        alert = '<div class="alert alert-danger">Please enter a valid corporate e-mail address.</div>'

    body = f"""
        <h2>Request Access</h2>
        <p class="subtitle">Enter your corporate e-mail to request access to RhAISE.<br>
        The RHAI team will review your request and enable your account.</p>
        {alert}
        <form method="POST">
            <div class="form-group">
                <label for="email">Corporate E-Mail Address</label>
                <input id="email" type="email" name="email" placeholder="you@company.com"
                       required autocomplete="email">
            </div>
            <button class="btn-primary" type="submit">Request Access</button>
        </form>
        <a class="btn-secondary" href="/login">&larr; Back to Login</a>
    """
    return _html_page("Request Access", body)


@router.post("/register")
async def register_handler(
    email: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Handle access request form submission."""
    email_val = email.strip().lower()
    email_pattern = r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
    if not email_val or not re.match(email_pattern, email_val):
        return RedirectResponse(url="/register?status=invalid", status_code=302)

    success, reason = register_user_request(db, email_val)
    if not success and reason == "already_exists":
        return RedirectResponse(url="/register?status=exists", status_code=302)
    if not success:
        return RedirectResponse(url="/register?status=error", status_code=302)

    return RedirectResponse(url="/register?status=success", status_code=302)


# ---------------------------------------------------------------------------
# Consent: Terms of Use + AI training acceptance
# ---------------------------------------------------------------------------

@router.get("/consent", response_class=HTMLResponse)
async def consent_page(request: Request, db: Session = Depends(get_db)):
    """Display the Terms of Use and AI training consent form.

    Requires an active provider session. After consent the user is sent to the
    original target: the `next` query parameter (an /oauth/authorize URL) when
    present, otherwise the internal `redirect_to` path. Users who are not yet
    registered must also set a new password here.
    """
    session_id = request.cookies.get("session_id")
    from app.auth.session import get_session as _get_session
    session = _get_session(session_id) if session_id else None

    next_url = request.query_params.get("next", "")
    # Validate next URL: must be an internal /oauth/authorize path
    if not next_url.startswith("/oauth/authorize"):
        next_url = ""

    redirect_to = request.query_params.get("redirect_to", "")
    # Validate redirect_to: must be an internal path
    if not redirect_to.startswith("/"):
        redirect_to = ""

    if not session:
        if next_url:
            login_url = "/login?" + urlencode({"redirect_to": f"/consent?next={next_url}"})
        elif redirect_to:
            login_url = "/login?" + urlencode({"redirect_to": f"/consent?redirect_to={redirect_to}"})
        else:
            login_url = "/login?redirect_to=/consent"
        return RedirectResponse(url=login_url, status_code=302)

    user = get_user_by_id(db, session["user_id"])
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # Onboarding already complete – nothing to confirm.
    if user.registered and user.accepted_tou:
        return RedirectResponse(url=next_url or redirect_to or "/login", status_code=302)

    error = request.query_params.get("error", "")
    if error == "pw_mismatch":
        error_html = '<div class="alert alert-danger">Passwords do not match.</div>'
    elif error == "pw_required":
        error_html = '<div class="alert alert-danger">Please choose a new password.</div>'
    elif error:
        error_html = '<div class="alert alert-danger">Please accept all items before continuing.</div>'
    else:
        error_html = ""

    safe_next = escape(next_url, quote=True)
    safe_redirect_to = escape(redirect_to, quote=True)

    # Unregistered users must set a new password as part of onboarding.
    password_html = ""
    if not user.registered:
        password_html = """
            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password"
                       required autocomplete="new-password">
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm New Password</label>
                <input type="password" id="confirm_password" name="confirm_password"
                       required autocomplete="new-password">
            </div>
        """

    body = f"""
        <h2>Terms of Use &amp; AI Training</h2>
        <p class="subtitle">Before accessing RhAISE, please confirm the following.</p>
        {error_html}
        <div class="alert alert-warning">
            <strong>Important Information:</strong><br>
            <ul style="margin-top:8px;padding-left:20px;line-height:1.8">
                <li>RH-Public and RH-Internal information may be uploaded.</li>
                <li>RH-Confidential requires written permission from the information owner.</li>
                <li>Do not upload strictly Confidential or classified national-secrecy data.</li>
                <li>Generated AI content may be inaccurate and must be reviewed by a human before use.</li>
                <li>The RhAISE platform is in a prototype stage; errors may occur. Report them via the support button.</li>
            </ul>
        </div>
        <div class="alert alert-warning" style="margin-top:12px">
            <strong>Required Training:</strong><br>
            <p style="margin-top:6px">Before using RhAISE, you must complete:<br>
            <strong>Artificial intelligence: Basic course &mdash; Course ID: Mandatory_EU-AI-Act_011</strong></p>
        </div>
        <form method="POST" style="margin-top:20px">
            <input type="hidden" name="next" value="{safe_next}">
            <input type="hidden" name="redirect_to" value="{safe_redirect_to}">
            {password_html}
            <div class="check-group">
                <input type="checkbox" id="ai-check" name="ai_training" value="1" required>
                <label for="ai-check">I have completed the AI training
                (Artificial intelligence: Basic course &mdash; Course ID: Mandatory_EU-AI-Act_011).</label>
            </div>
            <div class="check-group">
                <input type="checkbox" id="tou-check" name="accepted_tou" value="1" required>
                <label for="tou-check">I accept the Terms of Use.</label>
            </div>
            <button class="btn-primary" type="submit">Continue</button>
        </form>
    """
    return _html_page("Consent", body)


@router.post("/consent")
async def consent_handler(
    request: Request,
    next: str = Form(""),
    redirect_to: str = Form(""),
    ai_training: str = Form(""),
    accepted_tou: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Handle consent form submission.

    Requires acceptance of the Terms of Use and confirmation of AI-training
    participation. Users who are not yet registered must also provide a matching
    new password. On success, registered and accepted_tou are set to True (and
    the password is updated for unregistered users).
    """
    from app.auth.session import get_session as _get_session

    session_id = request.cookies.get("session_id")
    session = _get_session(session_id) if session_id else None
    if not session:
        return RedirectResponse(url="/login", status_code=302)

    user = get_user_by_id(db, session["user_id"])
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    def _error(code: str) -> RedirectResponse:
        params: dict[str, str] = {"error": code}
        if next:
            params["next"] = next
        elif redirect_to:
            params["redirect_to"] = redirect_to
        return RedirectResponse(url="/consent?" + urlencode(params), status_code=302)

    if not ai_training or not accepted_tou:
        return _error("1")

    # Unregistered users must set a new password to complete onboarding.
    if not user.registered:
        if not new_password or not confirm_password:
            return _error("pw_required")
        if new_password != confirm_password:
            return _error("pw_mismatch")
        user.password_hash = hash_password(new_password)

    # Sets registered=True and accepted_tou=True (commits any password change too).
    accept_user_consent(db, user.id)

    # Redirect to the original target.
    if next and next.startswith("/oauth/authorize"):
        return RedirectResponse(url=next, status_code=302)
    if redirect_to and redirect_to.startswith("/"):
        return RedirectResponse(url=redirect_to, status_code=302)
    return RedirectResponse(url="/login", status_code=302)

