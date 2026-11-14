from flask import Flask, request, jsonify, render_template
from datetime import datetime
from pathlib import Path
import sqlite3
import hmac

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


# ==========================================
# RUN INITIALIZATION ON IMPORT
# ==========================================

# Creates or upgrades the tables however the app is started:
# "python app.py", "flask run" or a production server.

initialize_database()


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

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )