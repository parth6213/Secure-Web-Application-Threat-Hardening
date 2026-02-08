from flask import Flask, request, session, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import sqlite3
import secrets
import re
import os
import time

app = Flask(__name__)

# -------------------- SECRET KEY --------------------
# Dev-safe fallback, production ready
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# -------------------- SESSION SECURITY --------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # True only when HTTPS
)

# -------------------- DATABASE --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()

# -------------------- PASSWORD POLICY --------------------
COMMON_PASSWORDS = {
    "admin",
    "admin123",
    "password",
    "password123",
    "welcome",
    "qwerty",
    "qwerty123",
    "user",
    "user123",
}


def is_strong_password(password, username):
    errors = []

    if len(password) < 8:
        errors.append("Minimum 8 characters required")
    if not re.search(r"[A-Z]", password):
        errors.append("At least one uppercase letter required")
    if not re.search(r"[a-z]", password):
        errors.append("At least one lowercase letter required")
    if not re.search(r"[0-9]", password):
        errors.append("At least one number required")
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]:;\"'<>,.?/]", password):
        errors.append("At least one special character required")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("Common passwords are not allowed")
    if username.lower() in password.lower():
        errors.append("Password too similar to username")

    return errors


# -------------------- CSRF --------------------
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf(token):
    return token and token == session.get("csrf_token")


# -------------------- ROUTES --------------------
@app.route("/")
def home():
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if not validate_csrf(request.form.get("csrf_token")):
            return "Invalid CSRF token", 403

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if password != confirm_password:
            return render_template(
                "register.html",
                errors=["Passwords do not match"],
                csrf_token=generate_csrf_token(),
            )

        errors = is_strong_password(password, username)
        if errors:
            return render_template(
                "register.html", errors=errors, csrf_token=generate_csrf_token()
            )

        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            conn.commit()
            conn.close()
            return redirect("/login")

        except sqlite3.IntegrityError:
            return render_template(
                "register.html",
                errors=["Username already exists"],
                csrf_token=generate_csrf_token(),
            )

    return render_template(
        "register.html", errors=None, csrf_token=generate_csrf_token()
    )


MAX_ATTEMPTS = 5
LOCK_TIME = 300  # 5 minutes


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    now = time.time()

    # init brute-force counters
    if "failed_attempts" not in session:
        session["failed_attempts"] = 0
    if "lock_until" not in session:
        session["lock_until"] = 0

    # check lock
    if session["lock_until"] > now:
        remaining = int(session["lock_until"] - now)
        error = f"Too many failed attempts. Try again in {remaining} seconds."
        return render_template(
            "login.html", error=error, csrf_token=generate_csrf_token()
        )

    if request.method == "POST":
        if not validate_csrf(request.form.get("csrf_token")):
            error = "Invalid request"
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            conn = get_db_connection()
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            conn.close()

            if user and check_password_hash(user["password"], password):
                # success → reset only brute-force data
                session.pop("failed_attempts", None)
                session.pop("lock_until", None)
                session["user"] = username
                return redirect("/dashboard")
            else:
                session["failed_attempts"] += 1
                left = MAX_ATTEMPTS - session["failed_attempts"]

                if left <= 0:
                    session["lock_until"] = now + LOCK_TIME
                    error = "Too many failed attempts. Account locked for 5 minutes."
                else:
                    error = f"Invalid username or password. {left} attempts left."

    return render_template("login.html", error=error, csrf_token=generate_csrf_token())


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=escape(session["user"]),
        csrf_token=generate_csrf_token(),
    )


@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf(request.form.get("csrf_token")):
        return "Invalid CSRF token", 403
    session.clear()
    return redirect("/login")


# -------------------- ENTRY POINT --------------------
if __name__ == "__main__":
    app.run()
