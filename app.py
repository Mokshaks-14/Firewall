import sqlite3
import time
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# IMPORTANT: This allows your frontend to talk to the backend without "CORS" errors
CORS(app, resources={r"/api/*": {"origins": "*"}})

DB_PATH = 'aegis_v3.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # Create Users
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE NOT NULL, 
                  password TEXT NOT NULL, 
                  role TEXT DEFAULT 'USER')''')
    # Create Alerts
    conn.execute('''CREATE TABLE IF NOT EXISTS alerts 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  ip TEXT, type TEXT, payload TEXT, time TEXT)''')
    # Create Products
    conn.execute('''CREATE TABLE IF NOT EXISTS products 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, img TEXT)''')
    
    # Pre-populate products if empty
    if not conn.execute("SELECT id FROM products LIMIT 1").fetchone():
        for i in range(1, 41):
            conn.execute("INSERT INTO products (name, price, img) VALUES (?, ?, ?)",
                         (f"Luxe Item {i}", round(50.0 + (i * 12.5), 2), f"https://picsum.photos/seed/{i+20}/400/400"))
    
    # Create Admin
    try:
        admin_pw = generate_password_hash('admin123')
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', admin_pw, 'ADMIN'))
    except sqlite3.IntegrityError:
        pass # Admin already exists
        
    conn.commit()
    conn.close()

# --- THE SECURITY SHIELD ---
def security_scan(username, password):
    # Detects common attack patterns
    patterns = {
        "SQL Injection": r"('|\"|--|union|select|drop|--|#|OR 1=1|OR '1'='1')",
        "XSS": r"(<script>|alert\(|onerror=|javascript:|<|>)",
    }
    
    combined_input = f"{username} {password}".lower()
    for attack_name, regex in patterns.items():
        if re.search(regex, combined_input):
            conn = get_db_connection()
            conn.execute("INSERT INTO alerts (ip, type, payload, time) VALUES (?, ?, ?, ?)",
                         (request.remote_addr, attack_name, combined_input, time.strftime('%H:%M:%S')))
            conn.commit()
            conn.close()
            return True, attack_name
    return False, None

# --- API ROUTES ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # 1. Run Security Scan
    is_attack, attack_type = security_scan(username, password)
    if is_attack:
        return jsonify({"error": f"Security Protocol: {attack_type} blocked."}), 403

    # 2. Try Database Insertion
    try:
        conn = get_db_connection()
        hashed_pw = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        conn.close()
        return jsonify({"message": "Registration successful!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists."}), 409
    except Exception as e:
        return jsonify({"error": f"System error: {str(e)}"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    # 1. Run Security Scan
    is_attack, attack_type = security_scan(username, password)
    if is_attack:
        return jsonify({"error": "Authentication failed (Security Block)"}), 403

    # 2. Verify User
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        return jsonify({
            "username": user['username'],
            "role": user['role'],
            "message": "Login successful"
        }), 200
    
    return jsonify({"error": "Invalid username or password."}), 401

@app.route('/api/products', methods=['GET'])
def get_products():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)