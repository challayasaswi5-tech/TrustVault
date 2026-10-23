import os
import hmac
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session, g,
    render_template_string, abort, send_from_directory, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit

BASE_DIR = Path(__file__).resolve().parent
DATABASE = str(BASE_DIR / "trustvault.db")
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"}
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
                role TEXT NOT NULL CHECK (role IN ('Admin', 'Document Owner', 'Viewer'))
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                access_level TEXT NOT NULL CHECK (access_level IN ('read', 'edit')),
                UNIQUE(document_id, user_id),
                FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(actor_id) REFERENCES users(id)
            )
        """)
        for username, password, role in DEMO_USERS:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), role)
                )
        db.commit()

def log_action(action, details):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (actor_id, action, details) VALUES (?, ?, ?)",
        (session.get("user_id"), action, details[:500])
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
        return wrapped
    return decorator

PAGE_STYLE = """
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#0f172a;color:#f8fafc}
header{background:#1e293b;padding:24px;text-align:center;border-bottom:1px solid #334155}
h1{color:#60a5fa;margin:0 0 8px}main{max-width:1000px;margin:35px auto;padding:20px}
.card{background:#1e293b;padding:24px;border:1px solid #334155;border-radius:16px;margin-bottom:20px}
input,select,button{padding:11px;margin:6px 0;border-radius:8px;font-size:15px;max-width:100%}
input,select{background:#0f172a;color:white;border:1px solid #475569}
button{background:#2563eb;color:white;border:0;cursor:pointer}button:hover{background:#1d4ed8}
a{color:#93c5fd}.muted{color:#cbd5e1;line-height:1.6}.error{color:#fca5a5}
.badge{display:inline-block;padding:7px 11px;background:#064e3b;color:#a7f3d0;border-radius:18px}
table{width:100%;border-collapse:collapse;margin-top:12px}th,td{text-align:left;padding:10px;border-bottom:1px solid #475569;overflow-wrap:anywhere}
.inline{display:inline-block;margin-right:8px}.message{padding:10px;background:#164e63;border-radius:8px;margin:12px 0}
input[type=file]{width:100%}.wide{width:100%}
</style>
"""
LOGIN_PAGE = """
<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrustVault | Login</title>""" + PAGE_STYLE + """
</head><body><header><h1>🔐 TrustVault</h1><p>Secure Document Sharing with a Real Audit Trail</p></header>
<main><div class="card" style="max-width:680px;margin:35px auto"><h2>Sign in to your workspace</h2>
<p class="muted">Use your authorised TrustVault account.</p>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="POST"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label for="username">Username</label><input class="wide" id="username" name="username" required autocomplete="username" maxlength="80">
<label for="password">Password</label><input class="wide" id="password" name="password" type="password" required autocomplete="current-password">
<button class="wide" type="submit">Login securely</button></form>
<p class="muted">Demo accounts: admin / Admin@12345 · owner / Owner@12345 · viewer / Viewer@12345</p></div></main></body></html>
"""

@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            log_action("LOGIN", f"{user['username']} signed in")
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template_string(LOGIN_PAGE, error=error)

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    role = session["role"]
    if role == "Admin":
        users = db.execute("SELECT id, username, role FROM users ORDER BY username").fetchall()
        logs = db.execute("""
            SELECT audit_logs.created_at, users.username, audit_logs.action, audit_logs.details
            FROM audit_logs LEFT JOIN users ON users.id = audit_logs.actor_id
            ORDER BY audit_logs.id DESC LIMIT 30
        """).fetchall()
        return render_template_string("""
        <!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>TrustVault Admin</title>""" + PAGE_STYLE + """</head><body><header><h1>🔐 TrustVault</h1><p>Admin Security Dashboard</p></header>
        <main><div class="card"><h2>Welcome, {{ session.username }}!</h2><span class="badge">Admin</span>
        <h3>Users</h3><table><tr><th>Username</th><th>Role</th></tr>{% for u in users %}<tr><td>{{u.username}}</td><td>{{u.role}}</td></tr>{% endfor %}</table>
        <h3>Recent Audit Trail</h3><table><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr>
        {% for l in logs %}<tr><td>{{l.created_at}}</td><td>{{l.username or 'System'}}</td><td>{{l.action}}</td><td>{{l.details}}</td></tr>{% endfor %}</table>
        <form method="POST" action="{{url_for('logout')}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button>Logout</button></form>
        </div></main></body></html>""", users=users, logs=logs)

    docs = db.execute("""
        SELECT DISTINCT d.id, d.original_name, d.uploaded_at, u.username AS owner_name,
        CASE WHEN d.owner_id = ? THEN 'Owner' ELSE p.access_level END AS my_access
        FROM documents d JOIN users u ON u.id = d.owner_id
        LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
        WHERE d.owner_id = ? OR p.user_id = ?
        ORDER BY d.id DESC
    """, (session["user_id"], session["user_id"], session["user_id"], session["user_id"])).fetchall()

    owner_users = []
    if role == "Document Owner":
        owner_users = db.execute(
            "SELECT id, username, role FROM users WHERE id != ? AND role != 'Admin' ORDER BY username",
            (session["user_id"],)
        ).fetchall()
    return render_template_string("""
    <!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>TrustVault Workspace</title>""" + PAGE_STYLE + """</head><body><header><h1>🔐 TrustVault</h1><p>Secure Document Sharing with a Real Audit Trail</p></header>
    <main><div class="card"><h2>Welcome, {{session.username}}!</h2><p>Your role: <span class="badge">{{session.role}}</span></p>
    {% with messages = get_flashed_messages() %}{% for message in messages %}<p class="message">{{message}}</p>{% endfor %}{% endwith %}
    {% if session.role == 'Document Owner' %}<h3>Upload a document</h3>
    <form method="POST" action="{{url_for('upload_document')}}" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="file" name="document" required>
    <button type="submit">Upload securely</button></form><p class="muted">Allowed: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG. Maximum 10 MB.</p>{% endif %}
    <h3>{% if session.role == 'Viewer' %}Shared with me{% else %}My documents and shared documents{% endif %}</h3>
    {% if docs %}<table><tr><th>Document</th><th>Owner</th><th>Uploaded</th><th>Access</th><th>Actions</th></tr>
    {% for d in docs %}<tr><td>{{d.original_name}}</td><td>{{d.owner_name}}</td><td>{{d.uploaded_at}}</td><td>{{d.my_access}}</td><td>
    <a href="{{url_for('download_document', document_id=d.id)}}">Download</a>
    {% if d.my_access == 'edit' %}
    <details><summary>Replace document (edit access)</summary>
    <form method="POST" action="{{url_for('replace_document',document_id=d.id)}}" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="file" name="document" required>
    <button type="submit">Replace file</button></form></details>
    {% endif %}
    {% if session.role == 'Document Owner' and d.my_access == 'Owner' %}
    <form class="inline" method="POST" action="{{url_for('delete_document',document_id=d.id)}}" onsubmit="return confirm('Delete this document?')">
    <input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button type="submit">Delete</button></form>
    <details><summary>Manage permissions</summary><form method="POST" action="{{url_for('grant_permission',document_id=d.id)}}">
    <input type="hidden" name="csrf_token" value="{{csrf_token()}}"><select name="user_id" required>
    {% for u in owner_users %}<option value="{{u.id}}">{{u.username}} ({{u.role}})</option>{% endfor %}</select>
    <select name="access_level"><option value="read">Read</option><option value="edit">Edit</option></select><button>Grant / Update</button></form>
    <form method="POST" action="{{url_for('revoke_permission',document_id=d.id)}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
    <select name="user_id" required>{% for u in owner_users %}<option value="{{u.id}}">{{u.username}}</option>{% endfor %}</select><button>Revoke access</button></form></details>
    {% endif %}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No documents available yet.</p>{% endif %}
    <form method="POST" action="{{url_for('logout')}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button>Logout</button></form>
    </div></main></body></html>""", docs=docs, owner_users=owner_users)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_document(document_id):
    return get_db().execute("""
        SELECT d.*, u.username AS owner_name FROM documents d
        JOIN users u ON u.id = d.owner_id WHERE d.id = ?
    """, (document_id,)).fetchone()

def can_access_document(document, need_edit=False):
    if document is None:
        return False
    if session.get("role") == "Admin":
        return True
    if document["owner_id"] == session.get("user_id"):
        return True
    permission = get_db().execute(
        "SELECT access_level FROM permissions WHERE document_id = ? AND user_id = ?",
        (document["id"], session.get("user_id"))
    ).fetchone()
    if not permission:
        return False
    return not need_edit or permission["access_level"] == "edit"

@app.route("/upload", methods=["POST"])
@role_required("Document Owner")
def upload_document():
    file = request.files.get("document")
    if not file or not file.filename:
        flash("Please choose a file.")
        return redirect(url_for("dashboard"))
    safe_name = secure_filename(file.filename)
    if not safe_name or not allowed_file(safe_name):
        flash("File type not allowed. Please upload a supported document.")
        return redirect(url_for("dashboard"))
    stored_name = secrets.token_hex(16) + "_" + safe_name
    file.save(UPLOAD_FOLDER / stored_name)
    db = get_db()
    cur = db.execute(
        "INSERT INTO documents (owner_id, original_name, stored_name) VALUES (?, ?, ?)",
        (session["user_id"], safe_name, stored_name)
    )
    db.commit()
    log_action("UPLOAD", f"Uploaded document ID {cur.lastrowid}: {safe_name}")
    flash("Document uploaded successfully.")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):
    document = get_document(document_id)
    if not can_access_document(document):
        log_action("ACCESS_DENIED", f"Denied download for document ID {document_id}")
        abort(403)
    path = UPLOAD_FOLDER / document["stored_name"]
    if not path.is_file():
        abort(404)
    log_action("DOWNLOAD", f"Downloaded document ID {document_id}: {document['original_name']}")
    return send_from_directory(app.config["UPLOAD_FOLDER"], document["stored_name"],
                               as_attachment=True, download_name=document["original_name"])

@app.route("/permissions/<int:document_id>/grant", methods=["POST"])
@role_required("Document Owner")
def grant_permission(document_id):
    document = get_document(document_id)
    if not document or document["owner_id"] != session["user_id"]:
        abort(403)
    try:
        user_id = int(request.form.get("user_id", ""))
    except ValueError:
        abort(400)
    access_level = request.form.get("access_level", "read")
    if access_level not in {"read", "edit"}:
        abort(400)
    target = get_db().execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target or user_id == session["user_id"]:
        flash("Please choose another valid user.")
        return redirect(url_for("dashboard"))
    db = get_db()
    db.execute("""
        INSERT INTO permissions (document_id, user_id, access_level) VALUES (?, ?, ?)
        ON CONFLICT(document_id, user_id) DO UPDATE SET access_level = excluded.access_level
    """, (document_id, user_id, access_level))
    db.commit()
    log_action("PERMISSION_GRANTED", f"{access_level} access to document {document_id} granted to {target['username']}")
    flash(f"{access_level.title()} access granted to {target['username']}.")
    return redirect(url_for("dashboard"))

@app.route("/permissions/<int:document_id>/revoke", methods=["POST"])
@role_required("Document Owner")
def revoke_permission(document_id):
    document = get_document(document_id)
    if not document or document["owner_id"] != session["user_id"]:
        abort(403)
    try:
        user_id = int(request.form.get("user_id", ""))
    except ValueError:
        abort(400)
    target = get_db().execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    db = get_db()
    db.execute("DELETE FROM permissions WHERE document_id = ? AND user_id = ?", (document_id, user_id))
    db.commit()
    log_action("PERMISSION_REVOKED", f"Access to document {document_id} revoked for {target['username'] if target else user_id}")
    flash("Access revoked if that user had permission.")
    return redirect(url_for("dashboard"))

@app.route("/documents/<int:document_id>/replace", methods=["POST"])
@login_required
def replace_document(document_id):
    document = get_document(document_id)
    if not can_access_document(document, need_edit=True):
        abort(403)
    file = request.files.get("document")
    if not file or not file.filename:
        flash("Please choose a replacement file.")
        return redirect(url_for("dashboard"))
    safe_name = secure_filename(file.filename)
    if not safe_name or not allowed_file(safe_name):
        flash("File type not allowed. Please upload a supported document.")
        return redirect(url_for("dashboard"))
    stored_name = secrets.token_hex(16) + "_" + safe_name
    file.save(UPLOAD_FOLDER / stored_name)
    old_path = UPLOAD_FOLDER / document["stored_name"]
    db = get_db()
    db.execute(
        "UPDATE documents SET original_name = ?, stored_name = ?, uploaded_at = CURRENT_TIMESTAMP WHERE id = ?",
        (safe_name, stored_name, document_id)
    )
    db.commit()
    try:
        old_path.unlink(missing_ok=True)
    except OSError:
        pass
    log_action("REPLACE", f"Replaced document ID {document_id}: {safe_name}")
    flash("Document replaced successfully.")
    return redirect(url_for("dashboard"))

@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@role_required("Document Owner")
def delete_document(document_id):
    document = get_document(document_id)
    if not document or document["owner_id"] != session["user_id"]:
        abort(403)
    db = get_db()
    db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    db.commit()
    try:
        (UPLOAD_FOLDER / document["stored_name"]).unlink(missing_ok=True)
    except OSError:
        pass
    log_action("DELETE", f"Deleted document ID {document_id}: {document['original_name']}")
    flash("Document deleted.")
    return redirect(url_for("dashboard"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action("LOGOUT", f"{session.get('username')} signed out")
    session.clear()
    return redirect(url_for("login"))

@app.errorhandler(403)
def forbidden(error):
    return "403 Forbidden: You do not have permission to access this page.", 403

@app.errorhandler(413)
def too_large(error):
    return "File too large. Maximum upload size is 10 MB.", 413

init_db()
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)