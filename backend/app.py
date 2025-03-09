from flask import Flask, request, jsonify, make_response
import sqlite3
import pyotp
import secrets
import ccxt
from datetime import datetime, timedelta
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # This will allow requests from all URLs

db_file = "hedge_fund.db"
admin_password = "osc7458OZ2011!"
exchange = ccxt.bybit()

exchange.apiKey = "NYppUjqTatEe6hJO67"
exchange.secret = "9CiKRIkgAFtw3KeBjPDOoqtQQjn5Q2U82iQ2"

# Optional: Enable testnet if needed
# exchange.set_sandbox_mode(True)

# Check authentication by fetching account balance
try:
    balance = exchange.fetch_balance()
    print("Bybit API authentication successful.")
except Exception as e:
    print(f"Bybit API authentication failed: {e}")


def init_db():
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            full_name TEXT,
            totp_secret TEXT,
            percentage_of_port REAL,
            initial_investment REAL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
            cookie TEXT PRIMARY KEY,
            email TEXT,
            full_name TEXT,
            expires_at DATETIME
        )''')
        conn.commit()

init_db()

def generate_totp():
    return pyotp.random_base32()

def validate_totp(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def create_session(email, full_name):
    session_cookie = secrets.token_hex(16)
    expires_at = datetime.utcnow() + timedelta(hours=24)
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO sessions (cookie, email, full_name, expires_at) VALUES (?, ?, ?, ?)",
                       (session_cookie, email, full_name, expires_at))
        conn.commit()
    return session_cookie

def get_user_by_cookie(cookie):
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email, full_name FROM sessions WHERE cookie = ? AND expires_at > ?", (cookie, datetime.utcnow()))
        return cursor.fetchone()

def update_portfolio():
    balance = exchange.fetch_balance()["total"]["USDT"]
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email, percentage_of_port, initial_investment FROM users")
        users = cursor.fetchall()
        total_port = sum(u[1] * balance + u[2] for u in users)
        for email, old_percentage, initial in users:
            new_percentage = (old_percentage * balance + initial) / total_port
            cursor.execute("UPDATE users SET percentage_of_port = ? WHERE email = ?", (new_percentage, email))
        conn.commit()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email, token = data["email"], data["totp"]
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT full_name, totp_secret FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user and validate_totp(user[1], token):
            session_cookie = create_session(email, user[0])
            return jsonify({"login_successful": True, "cookie": session_cookie})
    return jsonify({"login_successful": False}), 401

@app.route("/logout", methods=["POST"])
def logout():
    cookie = request.json.get("cookie")
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE cookie = ?", (cookie,))
        conn.commit()
    return jsonify({"message": "Logged out"})

@app.route("/deposit", methods=["POST"])
def deposit():
    data = request.json
    if data["admin_password"] != admin_password:
        return jsonify({"error": "Unauthorized"}), 403
    email, full_name, amount = data["email"], data["full_name"], float(data["amount"])
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT initial_investment FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user:
            new_investment = user[0] + amount
            cursor.execute("UPDATE users SET initial_investment = ? WHERE email = ?", (new_investment, email))
        else:
            totp_secret = generate_totp()
            cursor.execute("INSERT INTO users (email, full_name, totp_secret, percentage_of_port, initial_investment) VALUES (?, ?, ?, ?, ?)",
                           (email, full_name, totp_secret, 0, amount))
            return jsonify({"totp_secret": totp_secret})
        conn.commit()
    update_portfolio()
    return jsonify({"message": "Deposit successful"})

@app.route("/dashboard", methods=["POST"])
def dashboard():
    cookie = request.json.get("cookie")
    user = get_user_by_cookie(cookie)
    if not user:
        return jsonify({"error": "Invalid session"}), 401
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT percentage_of_port, initial_investment FROM users WHERE email = ?", (user[0],))
        data = cursor.fetchone()
    return jsonify({"percentage_of_port": data[0], "initial_investment": data[1]})

@app.route("/percentage", methods=["POST"])
def get_percentage():
    cookie = request.json.get("cookie")
    user = get_user_by_cookie(cookie)
    if not user:
        return jsonify({"error": "Invalid session"}), 401
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT percentage_of_port FROM users WHERE email = ?", (user[0],))
        percentage = cursor.fetchone()[0]
    return jsonify({"percentage_of_port": percentage})

@app.route("/amount", methods=["POST"])
def get_amount():
    cookie = request.json.get("cookie")
    user = get_user_by_cookie(cookie)
    if not user:
        return jsonify({"error": "Invalid session"}), 401
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT initial_investment FROM users WHERE email = ?", (user[0],))
        amount = cursor.fetchone()[0]
    return jsonify({"initial_investment": amount})


@app.route("/about", methods=["POST"])
def about():
    cookie = request.json.get("cookie")
    user = get_user_by_cookie(cookie)
    if not user:
        return jsonify({"error": "Invalid session"}), 401
    return jsonify({"name": user[1], "email": user[0]})

if __name__ == "__main__":
    app.run(debug=True)
