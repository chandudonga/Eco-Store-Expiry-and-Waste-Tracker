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
import resend

# ── 1. APP INITIALIZATION ──────────────────────────────────────────────────
app = Flask(__name__)

# ── 2. CONFIGURATION ─────────────────────────────────────────────────────────
class Config:
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "eco-tracker-secure-key-2026")
    DATABASE = "eco_tracker.db" 
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY")

app.config["JWT_SECRET_KEY"] = Config.JWT_SECRET_KEY
jwt = JWTManager(app)

if Config.RESEND_API_KEY:
    resend.api_key = Config.RESEND_API_KEY

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
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, email TEXT UNIQUE, store_name TEXT, password TEXT, role TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT, store_name TEXT, name TEXT, 
            qty INTEGER, min_qty INTEGER, exp TEXT, added_by INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS email_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, store_name TEXT, type TEXT, name TEXT, msg TEXT)""")
        conn.commit()

# ── 4. EMAIL AUTOMATION TASK ──────────────────────────────────────────────────
def check_and_send_emails():
    if not os.environ.get("RESEND_API_KEY"):
        print("Resend API key missing. Skipping background email verification.")
        return

    with sqlite3.connect(Config.DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        db = conn.cursor()
        
        users = db.execute("SELECT email, store_name FROM users WHERE role = 'admin'").fetchall()
        now = datetime.now()
        
        for user in users:
            store = user["store_name"]
            recipient_email = user["email"]
            
            products = db.execute("SELECT * FROM products WHERE store_name = ?", (store,)).fetchall()
            expiring_items = []
            
            for p in products:
                if p["exp"]:
                    try:
                        expiry_date = datetime.strptime(p["exp"], "%Y-%m-%d")
                        d_left = (expiry_date - now).days
                        if d_left <= 4:
                            expiring_items.append(f"- {p['name']} (Expires in {max(0, d_left)} days | Current Stock: {p['qty']})")
                    except ValueError:
                        pass
            
            if expiring_items:
                email_body = f"Hello Admin,\n\nThe following items in your store '{store}' are approaching expiration limits:\n\n" + "\n".join(expiring_items)
                
                try:
                    resend.Emails.send({
                        "from": "Eco Tracker <onboarding@resend.dev>",
                        "to": recipient_email,
                        "subject": f"⚠️ Expiry Warning Summary: {store}",
                        "text": email_body
                    })
                    
                    db.execute("INSERT INTO email_log (store_name, type, name, msg) VALUES (?, ?, ?, ?)",
                               (store, "Expiry Alert Summary", recipient_email, "Dispatched successfully via background worker."))
                    conn.commit()
                    print(f"Background automation successfully emailed {recipient_email}")
                    
                except Exception as e:
                    print(f"Failed handling email execution context for {recipient_email}: {str(e)}")

# ── 5. HTML TEMPLATE ROUTING ──────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login')
def login_view():
    return render_template('login.html')

@app.route('/register')
def register_view():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard_view():
    return render_template('store.html')

# ── 6. API AUTH & DATA ENDPOINTS ──────────────────────────────────────────────
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
        token = create_access_token(
            identity={"id": user["id"], "store_name": user["store_name"]}, 
            expires_delta=timedelta(days=1)
        )
        return jsonify({"token": token, "user": {"name": user["name"], "username": user["name"]}})
    return jsonify({"error": "Invalid email or password"}), 401

@app.route("/api/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    identity = get_jwt_identity()
    store = identity["store_name"]
    db = get_db()
    
    rows = db.execute("SELECT * FROM products WHERE store_name = ?", (store,)).fetchall()
    products = [dict(r) for r in rows]
    
    now = datetime.now()
    expiry_alerts = []
    low_stock_alerts = []
    total_units = 0
    
    for p in products:
        # Calculate overall warehouse unit sums dynamically based on user records
        total_units += p["qty"]
        
        # Check Expiry thresholds
        if p["exp"]:
            try:
                expiry_date = datetime.strptime(p["exp"], "%Y-%m-%d")
                d_left = (expiry_date - now).days
                if d_left <= 4:
                    p["days_left"] = max(0, d_left)
                    expiry_alerts.append(p)
            except: 
                pass

        # Check Stock Level metrics
        if p["qty"] <= (p["min_qty"] or 0):
            low_stock_alerts.append(p)

    return jsonify({
        "metrics": {
            "total_products": len(products),
            "expiry_count": len(expiry_alerts),
            "low_stock_count": len(low_stock_alerts),
            "total_units": total_units
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

# ── 7. RUNNER ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=check_and_send_emails, trigger="interval", hours=24)
    scheduler.start()
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
