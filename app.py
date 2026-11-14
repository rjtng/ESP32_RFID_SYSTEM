from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import closing
from datetime import datetime
from pathlib import Path
import click
import hashlib
import hmac
import math
import os
import re
import secrets
import sqlite3
import sys
import time

app = Flask(__name__)



@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"

    return response

# ==========================================
# DATABASE CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "rfid_system.db"

# ==========================================
# PHASE 9: DEVICE SECURITY CONFIGURATION
# ==========================================

# This key must match DEVICE_API_KEY in the ESP32 sketch.
# Rotate it by changing the value in BOTH files.
DEVICE_API_KEY = "f9753aeeb289bf822555b5aa287c4dd57de6675052c1f5daec0c4e3ce1bcba5c"

# Ignore repeated scans of the same card within this interval.
DUPLICATE_SCAN_WINDOW_SECONDS = 2


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    return connection



def valid_device_request():

    supplied_key = request.headers.get("X-Device-Key", "")

    return bool(supplied_key) and hmac.compare_digest(
        supplied_key,
        DEVICE_API_KEY
    )


# ==========================================
# INITIALIZE DATABASE
# ==========================================

def initialize_database():

    connection = get_db_connection()

    # RFID SCAN HISTORY
    # cardholder_name is saved at scan time, so the history stays
    # accurate even after a card is renamed or deleted.

    connection.execute("""
        CREATE TABLE IF NOT EXISTS rfid_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_uid TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK(status IN ('authorized', 'unauthorized')),
            timestamp TEXT NOT NULL,
            cardholder_name TEXT
        )
    """)

    # REGISTERED RFID CARDS

    connection.execute("""
        CREATE TABLE IF NOT EXISTS rfid_cards (

            card_uid TEXT PRIMARY KEY,

            cardholder_name TEXT NOT NULL,

            status TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('active', 'inactive')),

            created_at TEXT NOT NULL,

            updated_at TEXT NOT NULL

        )
    """)

    # DASHBOARD LOGIN ACCOUNTS
    # Only password hashes are stored, never the passwords themselves.

    connection.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # FAILED LOGIN ATTEMPTS
    # Used to slow down password guessing from one IP address.

    connection.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            attempted_at REAL NOT NULL
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
        ON login_attempts (ip_address, attempted_at)
    """)

    # UPGRADE OLDER DATABASES
    # Databases created before scan history stored cardholder names
    # get the new column here. Their existing scans keep a NULL name
    # because who held the card at the time was never recorded.

    log_columns = [
        row["name"]
        for row in connection.execute("PRAGMA table_info(rfid_logs)")
    ]

    if "cardholder_name" not in log_columns:

        try:

            connection.execute("""
                ALTER TABLE rfid_logs
                ADD COLUMN cardholder_name TEXT
            """)

        except sqlite3.OperationalError as error:

            # Another worker process may have added it first.
            if "duplicate column name" not in str(error).lower():
                raise

    connection.commit()
    connection.close()

    print("SQLite database initialized successfully!")
    print("RFID card management table initialized!")
    print("Dashboard login tables initialized!")


# ==========================================
# RUN INITIALIZATION ON IMPORT
# ==========================================

# Creates or upgrades the tables however the app is started:
# "python app.py", "flask run" or a production server.

initialize_database()


# ==========================================
# PHASE 10: DASHBOARD LOGIN
# ==========================================

# Everything is private by default. Only these endpoints work without
# signing in:
#   static             the CSS and JavaScript the login page needs
#   login              the sign-in page itself
#   api_status         health check (the ESP32 calls it when it boots)
#   receive_rfid_scan  protected by the device key instead of a login

PUBLIC_ENDPOINTS = {"static", "login", "api_status", "receive_rfid_scan"}

# A login stays valid this long. The dashboard polls the server
# constantly, so this is a fixed limit, not an idle timeout.
SESSION_MAX_AGE_SECONDS = 12 * 60 * 60

# After this many wrong passwords from one IP address inside the window
# below, that address is blocked until its oldest failure expires.
MAX_FAILED_LOGINS = 5
LOCKOUT_WINDOW_SECONDS = 5 * 60

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 256

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
PASSWORD_HASH_METHOD = "pbkdf2:sha256"


# ------------------------------------------
# Session settings
# ------------------------------------------

def load_secret_key():

    # The key that signs the login cookie. Use RFID_SECRET_KEY if it is
    # set, otherwise create a random key once and keep it in
    # secret_key.txt (keep that file private: do not upload it to GitHub).

    from_environment = os.environ.get("RFID_SECRET_KEY")

    if from_environment:
        return from_environment

    key_file = BASE_DIR / "secret_key.txt"

    try:

        # Mode "x" only creates the file if it does not exist yet, so two
        # server processes can never overwrite each other's key.
        with open(key_file, "x", encoding="utf-8") as file:
            file.write(secrets.token_hex(32))

        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass

    except FileExistsError:
        pass

    except OSError as error:
        print(f"WARNING: could not save secret_key.txt ({error}).")
        print("Dashboard logins will end whenever the server restarts.")
        return secrets.token_hex(32)

    for _ in range(20):

        key = key_file.read_text(encoding="utf-8").strip()

        if key:
            return key

        time.sleep(0.1)     # another process is still writing it

    raise RuntimeError("secret_key.txt is empty. Delete it and restart.")


app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_NAME="rfid_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    # Set RFID_HTTPS=1 once the dashboard is served over HTTPS. Turning
    # this on while using plain HTTP would stop the browser sending the
    # cookie, so it is off by default.
    SESSION_COOKIE_SECURE=os.environ.get("RFID_HTTPS") == "1",

    PERMANENT_SESSION_LIFETIME=SESSION_MAX_AGE_SECONDS,
)


# ------------------------------------------
# Admin accounts (only password hashes are stored)
# ------------------------------------------

def get_admin_password_hash(username):

    with closing(get_db_connection()) as connection:

        row = connection.execute(
            "SELECT password_hash FROM admin_users WHERE username = ?",
            (username,)
        ).fetchone()

    return row["password_hash"] if row else None


def admin_exists():

    with closing(get_db_connection()) as connection:

        row = connection.execute(
            "SELECT 1 FROM admin_users LIMIT 1"
        ).fetchone()

    return row is not None


def validate_new_account(username, password):

    if not USERNAME_PATTERN.match(username):
        return (
            "Username must be 3-32 characters: lowercase letters, "
            "numbers, dots, dashes or underscores."
        )

    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters."

    if password.lower() == username:
        return "Password must not be the same as the username."

    return None


def save_admin_account(username, password):

    password_hash = generate_password_hash(
        password,
        method=PASSWORD_HASH_METHOD
    )

    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    with closing(get_db_connection()) as connection:

        updated = connection.execute("""
            UPDATE admin_users
            SET password_hash = ?, updated_at = ?
            WHERE username = ?
        """, (password_hash, timestamp, username)).rowcount

        if updated == 0:

            connection.execute("""
                INSERT INTO admin_users (
                    username,
                    password_hash,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, timestamp, timestamp))

        connection.commit()


_dummy_password_hash = None


def dummy_password_hash():

    # Checked when the username does not exist, so a wrong username
    # takes as long to reject as a wrong password.

    global _dummy_password_hash

    if _dummy_password_hash is None:
        _dummy_password_hash = generate_password_hash(
            secrets.token_hex(16),
            method=PASSWORD_HASH_METHOD
        )

    return _dummy_password_hash


def prompt_for_admin_account(default_username="admin"):

    # Asks on the console, so the password never appears in a file,
    # in a command line or in the shell history.

    while True:

        username = click.prompt(
            "Dashboard username",
            default=default_username
        ).strip().lower()

        password = click.prompt(
            "Dashboard password",
            hide_input=True,
            confirmation_prompt=True
        )

        problem = validate_new_account(username, password)

        if problem is None:
            break

        click.echo(f"\n{problem}\n")

    save_admin_account(username, password)

    click.echo(f"\nSaved. You can now sign in as '{username}'.")

    return username


@app.cli.command("set-admin-password")
@click.option(
    "--username",
    default="admin",
    show_default=True,
    help="Account to create, or to reset the password of."
)
def set_admin_password_command(username):
    """Create the dashboard login, or reset its password.

    Resetting a password signs out everyone who is logged in.
    """

    prompt_for_admin_account(default_username=username)


# ------------------------------------------
# Slowing down password guessing
# ------------------------------------------

def client_ip():

    return request.remote_addr or "unknown"


def seconds_until_unlocked(ip_address):

    cutoff = time.time() - LOCKOUT_WINDOW_SECONDS

    with closing(get_db_connection()) as connection:

        attempts = [
            row["attempted_at"]
            for row in connection.execute("""
                SELECT attempted_at
                FROM login_attempts
                WHERE ip_address = ? AND attempted_at > ?
                ORDER BY attempted_at
            """, (ip_address, cutoff))
        ]

    if len(attempts) < MAX_FAILED_LOGINS:
        return 0

    # Blocked until the oldest counted failure leaves the window.
    unlock_at = attempts[-MAX_FAILED_LOGINS] + LOCKOUT_WINDOW_SECONDS

    return max(1, math.ceil(unlock_at - time.time()))


def record_failed_login(ip_address):

    now = time.time()

    with closing(get_db_connection()) as connection:

        connection.execute(
            "DELETE FROM login_attempts WHERE attempted_at < ?",
            (now - LOCKOUT_WINDOW_SECONDS,)
        )

        connection.execute(
            "INSERT INTO login_attempts (ip_address, attempted_at) VALUES (?, ?)",
            (ip_address, now)
        )

        connection.commit()


def clear_failed_logins(ip_address):

    with closing(get_db_connection()) as connection:

        connection.execute(
            "DELETE FROM login_attempts WHERE ip_address = ?",
            (ip_address,)
        )

        connection.commit()


# ------------------------------------------
# Who is signed in, and CSRF protection
# ------------------------------------------

def password_fingerprint(password_hash):

    # Stored in the session so that resetting the password signs out
    # every browser that was logged in with the old one.

    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()[:32]


def current_username():

    username = session.get("username")
    login_at = session.get("login_at")

    if not username or not isinstance(login_at, (int, float)):
        return None

    if time.time() - login_at > SESSION_MAX_AGE_SECONDS:
        session.clear()
        return None

    password_hash = get_admin_password_hash(username)

    if password_hash is None or not hmac.compare_digest(
        str(session.get("fingerprint", "")),
        password_fingerprint(password_hash)
    ):
        session.clear()
        return None

    return username


def get_csrf_token():

    token = session.get("csrf_token")

    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token

    return token


def csrf_token_is_valid():

    expected = session.get("csrf_token")

    supplied = (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
        or ""
    )

    return bool(expected) and hmac.compare_digest(
        supplied.encode("utf-8"),
        expected.encode("utf-8")
    )


# ------------------------------------------
# Checks that run before every request
# ------------------------------------------

@app.before_request
def require_login():

    # Unknown URLs fall through to Flask's normal 404 page.
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
        return None

    if current_username() is None:

        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "message": "Please sign in to use the dashboard."
            }), 401

        return redirect(url_for("login"))

    # Anything that changes data must carry the token that the server
    # put into the page, which proves the request came from our own page.
    if request.method not in ("GET", "HEAD", "OPTIONS"):

        if not csrf_token_is_valid():
            return jsonify({
                "success": False,
                "message": "Security check failed. Refresh the page and try again."
            }), 403

    return None


@app.context_processor
def inject_login_context():

    return {
        "csrf_token": get_csrf_token(),
        "username": current_username()
    }


@app.after_request
def prevent_caching(response):

    # Dashboard pages and data must never be cached: after logging out,
    # the Back button must not show the dashboard again.
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"

    return response


# ------------------------------------------
# Login and logout pages
# ------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_username() is not None:
        return redirect(url_for("dashboard"))

    setup_needed = not admin_exists()

    if request.method == "GET":
        return render_template("login.html", setup_needed=setup_needed)

    if setup_needed:
        return render_template("login.html", setup_needed=True), 403

    if not csrf_token_is_valid():
        return render_template(
            "login.html",
            setup_needed=False,
            error="Your page expired. Please try again."
        ), 400

    ip_address = client_ip()
    wait_seconds = seconds_until_unlocked(ip_address)

    if wait_seconds > 0:

        minutes = math.ceil(wait_seconds / 60)
        unit = "minute" if minutes == 1 else "minutes"

        print(f"Dashboard login: {ip_address} is blocked for {wait_seconds} seconds")

        return render_template(
            "login.html",
            setup_needed=False,
            error=f"Too many failed attempts. Try again in {minutes} {unit}."
        ), 429, {"Retry-After": str(wait_seconds)}

    username = request.form.get("username", "").strip().lower()[:64]
    password = request.form.get("password", "")[:MAX_PASSWORD_LENGTH + 1]

    stored_hash = get_admin_password_hash(username)

    password_ok = check_password_hash(
        stored_hash or dummy_password_hash(),
        password
    ) and stored_hash is not None

    if not password_ok:

        record_failed_login(ip_address)

        print(f"Dashboard login: failed attempt from {ip_address}")

        # The same message whether the username or the password was wrong.
        # (Status 200 on purpose: an ordinary typo should not show up as a
        # failed request in the browser's developer console.)
        return render_template(
            "login.html",
            setup_needed=False,
            error="Incorrect username or password.",
            entered_username=username
        )

    clear_failed_logins(ip_address)

    # Start a brand-new session on every login (prevents session fixation).
    session.clear()
    session.permanent = True
    session["username"] = username
    session["login_at"] = int(time.time())
    session["fingerprint"] = password_fingerprint(stored_hash)
    session["csrf_token"] = secrets.token_hex(32)

    print(f"Dashboard login: '{username}' signed in from {ip_address}")

    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# ==========================================
# WEB DASHBOARD
# ==========================================

@app.route("/", methods=["GET"])
def dashboard():

    return render_template("index.html")


# ==========================================
# API STATUS
# ==========================================

@app.route("/api/status", methods=["GET"])
def api_status():

    try:
        with get_db_connection() as connection:
            connection.execute("SELECT 1").fetchone()

        return jsonify({
            "success": True,
            "status": "online",
            "database": "online",
            "message": "Flask API and SQLite database are running."
        }), 200

    except sqlite3.Error as error:
        print(f"Health Check Database Error: {error}")

        return jsonify({
            "success": False,
            "status": "degraded",
            "database": "offline",
            "message": "The Flask API is running, but SQLite is unavailable."
        }), 503


# ==========================================
# RECEIVE RFID SCAN
# SERVER-SIDE AUTHENTICATION
# ==========================================

@app.route("/api/rfid/scan", methods=["POST"])
def receive_rfid_scan():

    # PHASE 9: accept scan requests only from the ESP32 holding the key.
    if not valid_device_request():
        return jsonify({
            "success": False,
            "message": "Unauthorized device request."
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid JSON request."
        }), 400

    uid = data.get("uid")

    if not isinstance(uid, str) or not uid.strip():
        return jsonify({
            "success": False,
            "message": "RFID UID is required."
        }), 400

    uid = uid.strip().upper()

    if (
        len(uid) > 32
        or len(uid) % 2 != 0
        or any(character not in "0123456789ABCDEF" for character in uid)
    ):
        return jsonify({
            "success": False,
            "message": "Invalid hexadecimal RFID UID."
        }), 400

    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    try:
        with get_db_connection() as connection:

            card = connection.execute("""
                SELECT card_uid, cardholder_name, status
                FROM rfid_cards
                WHERE card_uid = ?
            """, (uid,)).fetchone()

            if card and card["status"] == "active":
                access_status = "authorized"
                cardholder = card["cardholder_name"]
            else:
                access_status = "unauthorized"
                cardholder = "Unknown / Inactive Card"

            # Name saved with the scan. Registered cards keep their name
            # even while inactive; unknown UIDs are labelled so the
            # history stays readable.
            logged_name = (
                card["cardholder_name"]
                if card is not None
                else "Unregistered card"
            )

            # Suppress a second database entry for the same UID within
            # the configured short interval. Authorization is still
            # recalculated from the current card status above.
            previous_scan = connection.execute("""
                SELECT id, timestamp
                FROM rfid_logs
                WHERE card_uid = ?
                ORDER BY id DESC
                LIMIT 1
            """, (uid,)).fetchone()

            duplicate = False
            scan_id = None
            saved_timestamp = timestamp

            if previous_scan:
                try:
                    previous_time = datetime.fromisoformat(
                        previous_scan["timestamp"]
                    )
                    current_time = datetime.fromisoformat(timestamp)
                    elapsed = (current_time - previous_time).total_seconds()

                    if 0 <= elapsed < DUPLICATE_SCAN_WINDOW_SECONDS:
                        duplicate = True
                        scan_id = previous_scan["id"]
                        saved_timestamp = previous_scan["timestamp"]
                except (TypeError, ValueError):
                    # If an old timestamp cannot be parsed, record this scan.
                    pass

            if not duplicate:
                cursor = connection.execute("""
                    INSERT INTO rfid_logs (
                        card_uid,
                        cardholder_name,
                        status,
                        timestamp
                    )
                    VALUES (?, ?, ?, ?)
                """, (uid, logged_name, access_status, timestamp))

                scan_id = cursor.lastrowid

        print("\n================================")
        print("       RFID SCAN RECEIVED")
        print("================================")
        print(f"Scan ID    : {scan_id}")
        print(f"Card UID   : {uid}")
        print(f"Cardholder : {cardholder}")
        print(f"Status     : {access_status.upper()}")
        print(f"Duplicate  : {'YES - SUPPRESSED' if duplicate else 'NO'}")
        print(f"Time       : {saved_timestamp}")
        print("================================")

        return jsonify({
            "success": True,
            "message": "RFID scan processed successfully.",
            "id": scan_id,
            "uid": uid,
            "cardholder": cardholder,
            "cardholder_name": cardholder,
            "status": access_status,
            "authorized": access_status == "authorized",
            "duplicate": duplicate,
            "timestamp": saved_timestamp
        }), 200

    except sqlite3.Error as error:
        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to process RFID scan."
        }), 500


# ==========================================
# GET RFID SCAN HISTORY
# ==========================================

@app.route("/api/rfid/logs", methods=["GET"])
def get_rfid_logs():

    try:

        limit = request.args.get(
            "limit",
            default=100,
            type=int
        )

        if limit is None or limit < 1:

            return jsonify({
                "success": False,
                "message": "Invalid limit."
            }), 400

        limit = min(limit, 1000)

        with get_db_connection() as connection:

            records = connection.execute("""
                SELECT
                    id,
                    card_uid,
                    cardholder_name,
                    status,
                    timestamp
                FROM rfid_logs
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        logs = [dict(record) for record in records]

        return jsonify({
            "success": True,
            "total": len(logs),
            "logs": logs
        }), 200

    except sqlite3.Error as error:

        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to retrieve RFID logs."
        }), 500


# ==========================================
# RFID STATISTICS
# ==========================================

@app.route("/api/rfid/statistics", methods=["GET"])
def get_statistics():

    try:

        with get_db_connection() as connection:

            total_scans = connection.execute("""
                SELECT COUNT(*) FROM rfid_logs
            """).fetchone()[0]

            authorized_scans = connection.execute("""
                SELECT COUNT(*)
                FROM rfid_logs
                WHERE status = 'authorized'
            """).fetchone()[0]

            unauthorized_scans = connection.execute("""
                SELECT COUNT(*)
                FROM rfid_logs
                WHERE status = 'unauthorized'
            """).fetchone()[0]

            registered_cards = connection.execute("""
                SELECT COUNT(*)
                FROM rfid_cards
                WHERE status = 'active'
            """).fetchone()[0]

        return jsonify({

            "success": True,

            "statistics": {

                "total_scans": total_scans,

                "authorized_scans": authorized_scans,

                "unauthorized_scans": unauthorized_scans,

                "registered_cards": registered_cards

            }

        }), 200

    except sqlite3.Error as error:

        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to retrieve statistics."
        }), 500


# ==========================================
# GET ALL REGISTERED RFID CARDS
# ==========================================

@app.route("/api/rfid/cards", methods=["GET"])
def get_registered_cards():

    try:

        with get_db_connection() as connection:

            records = connection.execute("""
                SELECT
                    card_uid,
                    cardholder_name,
                    status,
                    created_at,
                    updated_at
                FROM rfid_cards
                ORDER BY created_at DESC
            """).fetchall()

        cards = [dict(record) for record in records]

        return jsonify({
            "success": True,
            "total": len(cards),
            "cards": cards
        }), 200

    except sqlite3.Error as error:

        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to retrieve registered cards."
        }), 500


# ==========================================
# REGISTER NEW RFID CARD
# ==========================================

@app.route("/api/rfid/cards", methods=["POST"])
def register_rfid_card():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request."
        }), 400

    uid = data.get("card_uid")
    name = data.get("cardholder_name")

    if not isinstance(uid, str) or not uid.strip():

        return jsonify({
            "success": False,
            "message": "RFID UID is required."
        }), 400

    if not isinstance(name, str) or not name.strip():

        return jsonify({
            "success": False,
            "message": "Cardholder name is required."
        }), 400

    uid = uid.strip().upper()
    name = name.strip()

    if len(uid) > 32 or not all(
        character in "0123456789ABCDEF" for character in uid
    ) or len(uid) % 2 != 0:

        return jsonify({
            "success": False,
            "message": "Invalid hexadecimal RFID UID."
        }), 400

    if len(name) > 100:

        return jsonify({
            "success": False,
            "message": "Cardholder name is too long."
        }), 400

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    try:

        with get_db_connection() as connection:

            existing = connection.execute("""
                SELECT card_uid
                FROM rfid_cards
                WHERE card_uid = ?
            """, (uid,)).fetchone()

            if existing:

                return jsonify({
                    "success": False,
                    "message": "This RFID card is already registered."
                }), 409

            connection.execute("""
                INSERT INTO rfid_cards (
                    card_uid,
                    cardholder_name,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, 'active', ?, ?)
            """, (
                uid,
                name,
                timestamp,
                timestamp
            ))

        return jsonify({
            "success": True,
            "message": "RFID card registered successfully.",
            "card_uid": uid,
            "cardholder_name": name
        }), 201

    except sqlite3.Error as error:

        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to register RFID card."
        }), 500


# ==========================================
# UPDATE CARDHOLDER INFORMATION
# ==========================================

@app.route("/api/rfid/cards/<uid>", methods=["PUT"])
def update_rfid_card(uid):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request."
        }), 400

    name = data.get("cardholder_name")

    if not isinstance(name, str) or not name.strip():

        return jsonify({
            "success": False,
            "message": "Cardholder name is required."
        }), 400

    name = name.strip()

    if len(name) > 100:

        return jsonify({
            "success": False,
            "message": "Cardholder name is too long."
        }), 400

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    try:

        with get_db_connection() as connection:

            cursor = connection.execute("""
                UPDATE rfid_cards
                SET
                    cardholder_name = ?,
                    updated_at = ?
                WHERE card_uid = ?
            """, (
                name,
                timestamp,
                uid.upper()
            ))

            if cursor.rowcount == 0:

                return jsonify({
                    "success": False,
                    "message": "RFID card not found."
                }), 404

        return jsonify({
            "success": True,
            "message": "Cardholder information updated."
        }), 200

    except sqlite3.Error as error:

        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to update RFID card."
        }), 500


# ==========================================
# ACTIVATE / DEACTIVATE RFID CARD
# ==========================================

@app.route("/api/rfid/cards/<uid>/status", methods=["PATCH"])
def update_card_status(uid):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request."
        }), 400

    status = data.get("status")

    if status not in ["active", "inactive"]:

        return jsonify({
            "success": False,
            "message": "Status must be active or inactive."
        }), 400

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    try:

        with get_db_connection() as connection:

            cursor = connection.execute("""
                UPDATE rfid_cards
                SET
                    status = ?,
                    updated_at = ?
                WHERE card_uid = ?
            """, (
                status,
                timestamp,
                uid.upper()
            ))

            if cursor.rowcount == 0:

                return jsonify({
                    "success": False,
                    "message": "RFID card not found."
                }), 404

        return jsonify({
            "success": True,
            "message": f"RFID card {status} successfully."
        }), 200

    except sqlite3.Error as error:

        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to update card status."
        }), 500


# ==========================================
# DELETE RFID CARD
# ==========================================

@app.route("/api/rfid/cards/<uid>", methods=["DELETE"])
def delete_rfid_card(uid):

    try:

        with get_db_connection() as connection:

            cursor = connection.execute("""
                DELETE FROM rfid_cards
                WHERE card_uid = ?
            """, (uid.upper(),))

            if cursor.rowcount == 0:

                return jsonify({
                    "success": False,
                    "message": "RFID card not found."
                }), 404

        return jsonify({
            "success": True,
            "message": "RFID card deleted successfully."
        }), 200

    except sqlite3.Error as error:

        print(f"Database Error: {error}")

        return jsonify({
            "success": False,
            "message": "Failed to delete RFID card."
        }), 500


# ==========================================
# MAIN APPLICATION
# ==========================================

if __name__ == "__main__":

    print("\n================================")
    print("   ESP32 RFID SYSTEM STARTING")
    print("================================")

    # First run: offer to create the dashboard login right here.
    if not admin_exists():

        if sys.stdin.isatty():
            print("\nNo dashboard login exists yet. Let's create one.\n")
            prompt_for_admin_account()
        else:
            print("\nNo dashboard login exists yet. Create one with:")
            print("    python -m flask --app app set-admin-password")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )