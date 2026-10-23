import os
import hmac
import secrets
import sqlite3

from functools import wraps
from flask import (
    Flask, request, redirect, url_for,
    session, g, render_template_string, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Local development key. Set a strong SECRET_KEY environment variable
# before deploying the application.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", secrets.token_hex(32)
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = "trustvault.db"

DEMO_USERS = [
    ("admin", "Admin@12345", "Admin"),
    ("owner", "Owner@12345", "Document Owner"),
    ("viewer", "Viewer@12345", "Viewer"),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (
                    role IN ('Admin', 'Document Owner', 'Viewer')
                )
            )
        """)

        for username, password, role in DEMO_USERS:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing is None:
                db.execute(
                    """INSERT INTO users
                       (username, password_hash, role)
                       VALUES (?, ?, ?)""",
                    (username, generate_password_hash(password), role)
                )

        db.commit()


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")

        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, description="Invalid security token. Refresh and retry.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)
        return decorator_wrapper(view, wrapped)
    return decorator


def decorator_wrapper(original, wrapped):
    return wrapped


PAGE_STYLE = """
<style>
* { box-sizing: border-box; }
body {
    margin: 0; font-family: Arial, sans-serif;
    background: #0f172a; color: #f8fafc;
}
header {
    background: #1e293b; padding: 24px;
    text-align: center; border-bottom: 1px solid #334155;
}
h1 { color: #60a5fa; margin: 0 0 8px; }
main {
    max-width: 680px; margin: 55px auto; padding: 28px;
}
.card {
    background: #1e293b; padding: 28px;
    border: 1px solid #334155; border-radius: 16px;
}
input, button {
    width: 100%; padding: 12px; margin: 8px 0;
    border-radius: 8px; font-size: 16px;
}
input { background: #0f172a; color: white; border: 1px solid #475569; }
button {
    background: #2563eb; color: white;
    border: none; cursor: pointer;
}
button:hover { background: #1d4ed8; }
a { color: #93c5fd; }
.muted { color: #cbd5e1; line-height: 1.6; }
.error { color: #fca5a5; }
.badge {
    display: inline-block; padding: 8px 12px;
    background: #064e3b; color: #a7f3d0; border-radius: 18px;
}
</style>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrustVault | Login</title>
""" + PAGE_STYLE + """
</head>
<body>
<header>
    <h1>🔐 TrustVault</h1>
    <p>Secure Document Sharing with a Real Audit Trail</p>
</header>
<main>
<div class="card">
    <h2>Sign in to your workspace</h2>
    <p class="muted">Use your authorised TrustVault account.</p>

    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}

    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label for="username">Username</label>
        <input id="username" name="username" required
               autocomplete="username" maxlength="80">

        <label for="password">Password</label>
        <input id="password" name="password" type="password" required
               autocomplete="current-password">

        <button type="submit">Login securely</button>
    </form>
</div>
</main>
</body>
</html>
"""


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            """SELECT id, username, password_hash, role
               FROM users WHERE username = ?""",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]
    role = session["role"]

    role_info = {
        "Admin": "Monitor users and security activity.",
        "Document Owner": "Manage your documents and their permissions.",
        "Viewer": "Access documents shared with you."
    }

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>TrustVault | Dashboard</title>
        """ + PAGE_STYLE + """
    </head>
    <body>
    <header>
        <h1>🔐 TrustVault</h1>
        <p>Secure Document Sharing</p>
    </header>
    <main>
        <div class="card">
            <h2>Welcome, {{ username }}!</h2>
            <p>Your assigned role:</p>
            <span class="badge">{{ role }}</span>
            <p class="muted">{{ role_info[role] }}</p>

            {% if role == "Admin" %}
                <h3>Admin Dashboard</h3>
                <p class="muted">User management and security monitoring
                will be added in the next development step.</p>
            {% elif role == "Document Owner" %}
                <h3>Document Owner Workspace</h3>
                <p class="muted">Document uploads and permission management
                will be added next.</p>
            {% else %}
                <h3>Viewer Workspace</h3>
                <p class="muted">Authorised document viewing will be
                added next.</p>
            {% endif %}

            <form method="POST" action="{{ url_for('logout') }}">
                <input type="hidden" name="csrf_token"
                       value="{{ csrf_token() }}">
                <button type="submit">Logout</button>
            </form>
        </div>
    </main>
    </body>
    </html>
    """, username=username, role=role, role_info=role_info)


@app.route("/admin")
@role_required("Admin")
def admin_only():
    return "Admin-only route. More dashboard features will be added next."


@app.route("/owner")
@role_required("Document Owner")
def owner_only():
    return "Document Owner-only route. Document management comes next."


@app.route("/viewer")
@role_required("Viewer")
def viewer_only():
    return "Viewer-only route. Document viewing comes next."


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(error):
    return "403 Forbidden: You do not have permission to access this page.", 403


init_db()

if __name__ == "__main__":
    app.run(debug=True)