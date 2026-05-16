import os
import psycopg2
from psycopg2.extras import DictCursor
import bcrypt
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
    # Paste your Render Database URL string here as a fallback, or set it via Render Environment Variables
    DATABASE_URL = os.environ.get("DATABASE_URL", "your_render_connection_string_here")
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY")

app.config["JWT_SECRET_KEY"] = Config.JWT_SECRET_KEY
jwt = JWTManager(app)

if Config.RESEND_API_KEY:
    resend.api_key = Config.RESEND_API_KEY

# ── 3. DATABASE HELPERS (POSTGRESQL MULTI-THREAD SAFE) ──────────────────────
def get_db():
    if "db" not in g:
        # Establishes a connection to your cloud Render Postgres database
        g.db = psycopg2.connect(Config.DATABASE_URL)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    # Connect directly to initialize structure on application boot
    conn = psycopg2.connect(Config.DATABASE_URL)
    c = conn.cursor()
    
    # Create Users Table using Postgres-compatible syntax (SERIAL instead of AUTOINCREMENT)
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT, 
        email TEXT UNIQUE, 
        store_name TEXT, 
        password TEXT, 
        role TEXT)""")
        
    # Create Products Table
    c.execute("""CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY, 
        store_name TEXT, 
        name TEXT, 
        qty INTEGER, 
        min_qty INTEGER, 
        exp TEXT, 
        added_by INTEGER)""")
        
    # Create Email/Alert Log Table
    c.execute("""CREATE TABLE IF NOT EXISTS email_log (
        id SERIAL PRIMARY KEY, 
        store_name TEXT, 
        type TEXT, 
        name TEXT, 
        msg TEXT)""")
        
    conn.commit()
    c.close()
    conn.close()
    print("PostgreSQL Database initialized and tables verified successfully.")

# ── 4. EMAIL AUTOMATION TASK ──────────────────────────────────────────────────
def check_and_send_emails():
    if not os.environ.get("RESEND_API_KEY"):
        print("Resend API key missing. Skipping background email verification.")
        return

    try:
        with psycopg2.connect(Config.DATABASE_URL) as conn:
            with conn.cursor(cursor_factory=DictCursor) as db:
                db.execute("SELECT email, store_name FROM users WHERE role = 'admin'")
                users = db.fetchall()
                now = datetime.now()
                
                for user in users:
                    store = user["store_name"]
                    recipient_email = user["email"]
                    
                    db.execute("SELECT * FROM products WHERE store_name = %s", (store,))
                    products = db.fetchall()
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
                            
                            db.execute("INSERT INTO email_log (store_name, type, name, msg) VALUES (%s, %s, %s, %s)",
                                       (store, "Expiry Alert Summary", recipient_email, "Dispatched successfully via background worker."))
                            conn.commit()
                            print(f"Background automation successfully emailed {recipient_email}")
                            
                        except Exception as e:
                            print(f"Failed handling email execution context for {recipient_email}: {str(e)}")
    except Exception as db_err:
        print(f"Background Scheduler Database Error: {str(db_err)}")

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
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request payload"}), 400

        name = data.get("name")
        email = data.get("email")
        store_name = data.get("store_name")
        password = data.get("password")
        role = data.get("role", "member")

        if not all([name, email, store_name, password]):
            return jsonify({"error": "Missing required fields"}), 400

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        db = get_db()
        with db.cursor() as cursor:
            # PostgreSQL uses %s placeholders instead of ?
            cursor.execute("INSERT INTO users (name, email, store_name, password, role) VALUES (%s,%s,%s,%s,%s)",
                           (name, email.lower(), store_name, hashed, role))
        db.commit()
        return jsonify({"message": "Registered successfully"}), 201

    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({"error": "Email already exists"}), 409
    except Exception as e:
        db.rollback()
        print(f"CRITICAL REGISTRATION ERROR: {str(e)}")
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    db = get_db()
    with db.cursor(cursor_factory=DictCursor) as cursor:
        cursor.execute("SELECT * FROM users WHERE email = %s", (data["email"].lower(),))
        user = cursor.fetchone()
    
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
    
    with db.cursor(cursor_factory=DictCursor) as cursor:
        cursor.execute("SELECT * FROM products WHERE store_name = %s", (store,))
        rows = cursor.fetchall()
        
    products = [dict(r) for r in rows]
    now = datetime.now()
    expiry_alerts = []
    low_stock_alerts = []
    total_units = 0
    
    for p in products:
        total_units += p["qty"]
        if p["exp"]:
            try:
                expiry_date = datetime.strptime(p["exp"], "%Y-%m-%d")
                d_left = (expiry_date - now).days
                if d_left <= 4:
                    p["days_left"] = max(0, d_left)
                    expiry_alerts.append(p)
            except: 
                pass

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
    with db.cursor() as cursor:
        cursor.execute("""INSERT INTO products (store_name, name, qty, min_qty, exp, added_by) 
                      VALUES (%s, %s, %s, %s, %s, %s)""",
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
