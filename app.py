from flask import Flask, request, jsonify, render_template
from datetime import datetime
from pathlib import Path
import sqlite3

app = Flask(__name__)

# ==========================================
# DATABASE CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "rfid_system.db"


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# INITIALIZE DATABASE
# ==========================================

def initialize_database():

    connection = get_db_connection()

    # RFID SCAN HISTORY

    connection.execute("""
        CREATE TABLE IF NOT EXISTS rfid_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_uid TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK(status IN ('authorized', 'unauthorized')),
            timestamp TEXT NOT NULL
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

    # PRESERVE EXISTING AUTHORIZED RFID CARD

    existing_card = connection.execute("""
        SELECT card_uid
        FROM rfid_cards
        WHERE card_uid = ?
    """, ("5F4A9BDA",)).fetchone()

    if existing_card is None:

        timestamp = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        connection.execute("""
            INSERT INTO rfid_cards (
                card_uid,
                cardholder_name,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "5F4A9BDA",
            "Administrator",
            "active",
            timestamp,
            timestamp
        ))

    connection.commit()
    connection.close()

    print("SQLite database initialized successfully!")
    print("RFID card management table initialized!")


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

    return jsonify({
        "success": True,
        "status": "online",
        "message": "ESP32 RFID REST API is running!"
    })


# ==========================================
# RECEIVE RFID SCAN
# SERVER-SIDE AUTHENTICATION
# ==========================================

@app.route("/api/rfid/scan", methods=["POST"])
def receive_rfid_scan():

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

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    try:

        with get_db_connection() as connection:

            # CHECK REGISTERED CARD

            card = connection.execute("""
                SELECT card_uid, cardholder_name, status
                FROM rfid_cards
                WHERE card_uid = ?
            """, (uid,)).fetchone()

            # DETERMINE AUTHORIZATION

            if card and card["status"] == "active":

                access_status = "authorized"
                cardholder = card["cardholder_name"]

            else:

                access_status = "unauthorized"
                cardholder = "Unknown / Inactive Card"

            # SAVE SCAN HISTORY

            cursor = connection.execute("""
                INSERT INTO rfid_logs (
                    card_uid,
                    status,
                    timestamp
                )
                VALUES (?, ?, ?)
            """, (
                uid,
                access_status,
                timestamp
            ))

            scan_id = cursor.lastrowid

        print("\n================================")
        print("       RFID SCAN RECEIVED")
        print("================================")
        print(f"Scan ID    : {scan_id}")
        print(f"Card UID   : {uid}")
        print(f"Cardholder : {cardholder}")
        print(f"Status     : {access_status.upper()}")
        print(f"Time       : {timestamp}")
        print("Database   : SAVED SUCCESSFULLY")
        print("================================")

        return jsonify({

            "success": True,

            "message": "RFID scan processed successfully.",

            "id": scan_id,

            "uid": uid,

            "cardholder": cardholder,

            "status": access_status,

            "timestamp": timestamp

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

    initialize_database()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )