import os
import sqlite3
import secrets
from pathlib import Path

from flask import (
    Flask, request, redirect, session, url_for,
    abort, send_file, render_template, render_template_string
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from database import (
    init_db, get_db_connection, add_audit_log, get_audit_logs
)

app = Flask(__name__)
init_db()

app.secret_key = (
    os.environ.get("TRUSTVAULT_SECRET_KEY")
    or secrets.token_hex(32)
)

BASE_DIR = Path(app.root_path)
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf", ".txt", ".doc", ".docx",
    ".png", ".jpg", ".jpeg", ".csv"
}


def ensure_deployment_admin():
    username = os.environ.get("TRUSTVAULT_ADMIN_USERNAME", "").strip()
    password = os.environ.get("TRUSTVAULT_ADMIN_PASSWORD", "")

    if not username or not password:
        return

    connection = get_db_connection()
    try:
        existing = connection.execute(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()

        if existing is None:
            connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, 'admin')
                """,
                (username, generate_password_hash(password)),
            )
            connection.commit()
    except sqlite3.IntegrityError:
        connection.rollback()
    finally:
        connection.close()


ensure_deployment_admin()


def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None

    connection = get_db_connection()
    try:
        return connection.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        connection.close()


def log_action(action, document_id=None):
    user_id = session.get("user_id")
    if user_id is not None:
        add_audit_log(user_id, action, document_id)


def get_document(document_id):
    connection = get_db_connection()
    try:
        return connection.execute(
            """
            SELECT id, original_filename, stored_filename,
                   owner_id, uploaded_at
            FROM documents WHERE id = ?
            """,
            (document_id,),
        ).fetchone()
    finally:
        connection.close()


def can_access_document(user, document):
    if user is None or document is None:
        return False

    if user["role"] == "admin":
        return True

    if (
        user["role"] == "owner"
        and document["owner_id"] == user["id"]
    ):
        return True

    connection = get_db_connection()
    try:
        grant = connection.execute(
            """
            SELECT 1 FROM document_permissions
            WHERE document_id = ? AND user_id = ?
            """,
            (document["id"], user["id"]),
        ).fetchone()
        return grant is not None
    finally:
        connection.close()


def can_manage_sharing(user, document):
    return bool(
        user and document and (
            user["role"] == "admin"
            or (
                user["role"] == "owner"
                and document["owner_id"] == user["id"]
            )
        )
    )


@app.route("/")
def home():
    user = current_user()

    if user is None:
        if "user_id" in session:
            session.clear()
        return render_template("home.html")

    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>TrustVault Dashboard</title>
        </head>
        <body>
            <h1>TrustVault</h1>
            <h2>Secure Document Sharing</h2>
            <p>Welcome, {{ username }}!</p>
            <p>Role: {{ role }}</p>
            <hr>
            {% if role in ('admin', 'owner') %}
            <p><a href="{{ url_for('upload_document') }}">Upload Document</a></p>
            {% endif %}
            <p><a href="{{ url_for('view_documents') }}">View Documents</a></p>
            {% if role == 'admin' %}
            <p><a href="{{ url_for('audit_logs_page') }}">View Audit Logs</a></p>
            {% endif %}
            <form action="{{ url_for('logout') }}" method="POST">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
    """, username=user["username"], role=user["role"])


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    connection = get_db_connection()
    try:
        user = connection.execute(
            """
            SELECT id, username, password_hash, role
            FROM users WHERE username = ?
            """,
            (username,),
        ).fetchone()
    finally:
        connection.close()

    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        log_action("LOGIN")
        return redirect(url_for("home"))

    if user:
        connection = get_db_connection()
        try:
            connection.execute(
                "INSERT INTO audit_logs (user_id, action) VALUES (?, ?)",
                (user["id"], "LOGIN_FAILED"),
            )
            connection.commit()
        finally:
            connection.close()

    return "Invalid username or password.", 401
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Username and password are required.", 400

        if len(password) < 8:
            return "Password must be at least 8 characters.", 400

        connection = get_db_connection()
        try:
            existing = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing:
                return "Username already exists. Choose another.", 400

            connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, 'viewer')
                """,
                (username, generate_password_hash(password))
            )
            connection.commit()
        finally:
            connection.close()

        return redirect(url_for("login"))

    return """
    <h2>Create Viewer Account</h2>
    <form method="POST">
        <label>Username:</label>
        <input name="username" required>
        <br><br>
        <label>Password:</label>
        <input name="password" type="password" minlength="8" required>
        <br><br>
        <button type="submit">Create Viewer Account</button>
    </form>
    <a href="/">Back to Login</a>
    """

@app.route("/admin/create-viewer", methods=["GET", "POST"])
def create_viewer():
    if session.get("role") != "admin":
        return "Access denied", 403

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Username and password are required.", 400

        if len(password) < 8:
            return "Password must be at least 8 characters.", 400

        connection = get_db_connection()
        try:
            existing_user = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if existing_user:
                return "Username already exists.", 409

            connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, 'viewer')
                """,
                (username, generate_password_hash(password)),
            )
            connection.commit()

        finally:
            connection.close()

        return "Viewer account created successfully. You can now log in."

    return """
    <h2>Create Viewer Account</h2>
    <form method="POST">
        <label>Viewer Username:</label>
        <input name="username" required>
        <br><br>
        <label>Viewer Password:</label>
        <input name="password" type="password" minlength="8" required>
        <br><br>
        <button type="submit">Create Viewer</button>
    </form>
    """
@app.route("/logout", methods=["POST"])
def logout():
    if "user_id" in session:
        log_action("LOGOUT")
    session.clear()
    return redirect(url_for("home"))


@app.route("/upload", methods=["GET", "POST"])
def upload_document():
    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("home"))

    if user["role"] not in ("admin", "owner"):
        log_action("UPLOAD_DENIED")
        abort(403)

    if request.method == "GET":
        return render_template_string("""
            <h2>Upload Document</h2>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="document" required>
                <button type="submit">Upload</button>
            </form>
            <a href="{{ url_for('home') }}">Back to Dashboard</a>
        """)

    file = request.files.get("document")
    if file is None or not file.filename:
        return "Please select a file.", 400

    original_filename = secure_filename(file.filename)
    extension = Path(original_filename).suffix.lower()

    if not original_filename or extension not in ALLOWED_EXTENSIONS:
        log_action("UPLOAD_REJECTED")
        return "File type not allowed.", 400

    stored_filename = secrets.token_hex(16) + extension
    save_path = UPLOAD_FOLDER / stored_filename

    connection = get_db_connection()
    try:
        cursor = connection.execute(
            """
            INSERT INTO documents
                (original_filename, stored_filename, owner_id)
            VALUES (?, ?, ?)
            """,
            (original_filename, stored_filename, user["id"]),
        )
        document_id = cursor.lastrowid
        file.save(save_path)
        connection.commit()
    except Exception:
        connection.rollback()
        if save_path.exists():
            save_path.unlink()
        raise
    finally:
        connection.close()

    log_action("DOCUMENT_UPLOAD", document_id)

    return render_template_string("""
        <h2>Upload successful!</h2>
        <p>File saved: {{ filename }}</p>
        <p><a href="{{ url_for('view_documents') }}">View Documents</a></p>
        <p><a href="{{ url_for('home') }}">Back to Dashboard</a></p>
    """, filename=original_filename)


@app.route("/documents")
def view_documents():
    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("home"))

    connection = get_db_connection()
    try:
        if user["role"] == "admin":
            documents = connection.execute(
                """
                SELECT id, original_filename, owner_id, uploaded_at
                FROM documents ORDER BY id DESC
                """
            ).fetchall()
        elif user["role"] == "owner":
            documents = connection.execute(
                """
                SELECT id, original_filename, owner_id, uploaded_at
                FROM documents WHERE owner_id = ?
                ORDER BY id DESC
                """,
                (user["id"],),
            ).fetchall()
        else:
            documents = connection.execute(
                """
                SELECT d.id, d.original_filename, d.owner_id, d.uploaded_at
                FROM documents d
                JOIN document_permissions p ON p.document_id = d.id
                WHERE p.user_id = ?
                ORDER BY d.id DESC
                """,
                (user["id"],),
            ).fetchall()
    finally:
        connection.close()

    for document in documents:
        log_action("DOCUMENT_LIST_VIEW", document["id"])

    return render_template_string("""
        <h2>View Documents</h2>
        {% if documents %}
        <ul>
        {% for doc in documents %}
            <li>
                {{ doc["original_filename"] }}
                — <a href="{{ url_for('open_document', document_id=doc['id']) }}">Open</a>
                {% if role == 'admin' or
                    (role == 'owner' and doc['owner_id'] == user_id) %}
                — <a href="{{ url_for('share_document', document_id=doc['id']) }}">
                    Share / Manage Access
                  </a>
                {% endif %}
            </li>
        {% endfor %}
        </ul>
        {% else %}
        <p>No documents available.</p>
        {% endif %}
        <a href="{{ url_for('home') }}">Back to Dashboard</a>
    """, documents=documents, role=user["role"], user_id=user["id"])


@app.route("/documents/<int:document_id>/open")
def open_document(document_id):
    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("home"))

    document = get_document(document_id)
    if document is None:
        log_action("DOCUMENT_NOT_FOUND")
        abort(404)

    if not can_access_document(user, document):
        log_action("DOCUMENT_ACCESS_DENIED", document_id)
        abort(403)

    file_path = UPLOAD_FOLDER / document["stored_filename"]
    if not file_path.is_file():
        log_action("DOCUMENT_FILE_MISSING", document_id)
        abort(404)

    log_action("DOCUMENT_OPEN", document_id)
    return send_file(
        file_path,
        as_attachment=False,
        download_name=document["original_filename"],
    )


@app.route("/documents/<int:document_id>/share", methods=["GET", "POST"])
def share_document(document_id):
    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("home"))

    document = get_document(document_id)
    if document is None:
        abort(404)

    if not can_manage_sharing(user, document):
        log_action("DOCUMENT_SHARE_DENIED", document_id)
        abort(403)

    connection = get_db_connection()
    try:
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            target = connection.execute(
                "SELECT id, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if target is None or target["role"] != "viewer":
                return "Enter an existing viewer username.", 400

            try:
                connection.execute(
                    """
                    INSERT INTO document_permissions
                        (document_id, user_id, granted_by)
                    VALUES (?, ?, ?)
                    """,
                    (document_id, target["id"], user["id"]),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                return "This viewer already has access.", 409

            log_action("DOCUMENT_ACCESS_GRANTED", document_id)
            return redirect(url_for(
                "share_document", document_id=document_id
            ))

        viewers = connection.execute(
            """
            SELECT u.username
            FROM document_permissions p
            JOIN users u ON u.id = p.user_id
            WHERE p.document_id = ?
            ORDER BY u.username
            """,
            (document_id,),
        ).fetchall()
    finally:
        connection.close()

    return render_template_string("""
        <h2>Share Document</h2>
        <p>Document: {{ filename }}</p>
        <form method="POST">
            <label>Viewer username:</label>
            <input name="username" required>
            <button type="submit">Grant Access</button>
        </form>
        <h3>Users with access</h3>
        <ul>
        {% for viewer in viewers %}
            <li>
                {{ viewer["username"] }}
                <form method="POST"
                    action="{{ url_for('revoke_document_access',
                                       document_id=document_id) }}">
                    <input type="hidden" name="username"
                           value="{{ viewer['username'] }}">
                    <button type="submit">Revoke Access</button>
                </form>
            </li>
        {% else %}
            <li>No viewers have access.</li>
        {% endfor %}
        </ul>
        <a href="{{ url_for('view_documents') }}">Back to Documents</a>
    """, filename=document["original_filename"],
       viewers=viewers, document_id=document_id)


@app.route("/documents/<int:document_id>/revoke", methods=["POST"])
def revoke_document_access(document_id):
    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("home"))

    document = get_document(document_id)
    if document is None:
        abort(404)

    if not can_manage_sharing(user, document):
        log_action("DOCUMENT_REVOKE_DENIED", document_id)
        abort(403)

    username = request.form.get("username", "").strip()
    connection = get_db_connection()
    try:
        target = connection.execute(
            "SELECT id, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if target is None or target["role"] != "viewer":
            return "Viewer not found.", 404

        cursor = connection.execute(
            """
            DELETE FROM document_permissions
            WHERE document_id = ? AND user_id = ?
            """,
            (document_id, target["id"]),
        )
        connection.commit()

        if cursor.rowcount == 0:
            return "No active access grant was found.", 404
    finally:
        connection.close()

    log_action("DOCUMENT_ACCESS_REVOKED", document_id)
    return redirect(url_for(
        "share_document", document_id=document_id
    ))


@app.route("/admin/audit-logs")
def audit_logs_page():
    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("home"))

    if user["role"] != "admin":
        log_action("AUDIT_LOG_ACCESS_DENIED")
        abort(403)

    logs = get_audit_logs()

    return render_template_string("""
        <h2>TrustVault Audit Logs</h2>
        <table border="1" cellpadding="6">
            <tr>
                <th>User</th>
                <th>Document ID</th>
                <th>Action</th>
                <th>Timestamp</th>
            </tr>
            {% for item in logs %}
            <tr>
                <td>{{ item["username"] }}</td>
                <td>{{ item["document_id"] or "" }}</td>
                <td>{{ item["action"] }}</td>
                <td>{{ item["timestamp"] }}</td>
            </tr>
            {% endfor %}
        </table>
        <a href="{{ url_for('home') }}">Back to Dashboard</a>
    """, logs=logs)


@app.errorhandler(403)
def forbidden(error):
    return "Access denied. You do not have permission.", 403


@app.errorhandler(404)
def not_found(error):
    return "The requested resource was not found.", 404


@app.errorhandler(413)
def file_too_large(error):
    return "File too large. Maximum upload size is 10 MB.", 413


if __name__ == "__main__":
    app.run(debug=True)