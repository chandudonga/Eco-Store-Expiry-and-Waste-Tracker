import sqlite3
import bcrypt
import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g, render_template
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from apscheduler.schedulers.background import BackgroundScheduler

# ── 1. APP INITIALIZATION (MUST BE FIRST) ──────────────────────────────────
app = Flask(__name__)

# ── 2. CONFIGURATION ─────────────────────────────────────────────────────────
class Config:
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "eco-tracker-secure-key-2026")
    # This database path works for both local development and Render
    DATABASE = "eco_tracker.db" 

app.config["JWT_SECRET_KEY"] = Config.JWT_SECRET_KEY
jwt = JWTManager(app)

# ── 3. DATABASE HELPERS ──────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(Config.DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(Config.DATABASE) as conn:
        c = conn.cursor()
        # Create Users Table
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, email TEXT UNIQUE, store_name TEXT, password TEXT, role TEXT)""")
        # Create Products Table
        c.execute("""CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT, store_name TEXT, name TEXT, 
            qty INTEGER, min_qty INTEGER, exp TEXT, added_by INTEGER)""")
        # Create Email/Alert Log Table
        c.execute("""CREATE TABLE IF NOT EXISTS email_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, store_name TEXT, type TEXT, name TEXT, msg TEXT)""")
        conn.commit()

# ── 4. API ROUTES ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('store.html')

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    hashed = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db = get_db()
    try:
        db.execute("INSERT INTO users (name, email, store_name, password, role) VALUES (?,?,?,?,?)",
                   (data["name"], data["email"].lower(), data["store_name"], hashed, data["role"]))
        db.commit()
        return jsonify({"message": "Registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (data["email"].lower(),)).fetchone()
    
    if user and bcrypt.checkpw(data["password"].encode('utf-8'), user["password"].encode('utf-8')):
        # Token carries store_name to isolate data
        token = create_access_token(
            identity={"id": user["id"], "store_name": user["store_name"]}, 
            expires_delta=timedelta(days=1)
        )
        return jsonify({"token": token, "user": {"name": user["name"]}})
    return jsonify({"error": "Invalid email or password"}), 401

@app.route("/api/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    identity = get_jwt_identity()
    store = identity["store_name"]
    db = get_db()
    
    # Isolation: Only fetch products belonging to this specific store
    rows = db.execute("SELECT * FROM products WHERE store_name = ?", (store,)).fetchall()
    products = [dict(r) for r in rows]
    
    now = datetime.now()
    expiry_alerts = []
    low_stock_alerts = []
    
    for p in products:
        # Expiry Logic (Requirement: 3-4 day window)
        if p["exp"]:
            try:
                expiry_date = datetime.strptime(p["exp"], "%Y-%m-%d")
                d_left = (expiry_date - now).days
                if d_left <= 4:
                    p["days_left"] = d_left
                    expiry_alerts.append(p)
            except: pass

        # Stock Logic
        if p["qty"] <= (p["min_qty"] or 0):
            low_stock_alerts.append(p)

    return jsonify({
        "metrics": {
            "total_products": len(products),
            "expiry_count": len(expiry_alerts),
            "low_stock_count": len(low_stock_alerts)
        },
        "expiry_alerts": expiry_alerts,
        "low_stock_alerts": low_stock_alerts
    })

@app.route("/api/products", methods=["POST"])
@jwt_required()
def add_product():
    identity = get_jwt_identity()
    data = request.get_json()
    db = get_db()
    db.execute("""INSERT INTO products (store_name, name, qty, min_qty, exp, added_by) 
                  VALUES (?, ?, ?, ?, ?, ?)""",
               (identity["store_name"], data["name"], data["qty"], 
                data.get("min", 0), data.get("exp"), identity["id"]))
    db.commit()
    return jsonify({"message": "Product added successfully"}), 201

# ── 5. RUNNER ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    
    # Background scheduler can be used here for automated email tasks in the future
    scheduler = BackgroundScheduler()
    scheduler.start()
    
    # Render and other hosts use the PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
