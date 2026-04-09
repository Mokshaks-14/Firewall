import datetime
import re
import random
from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt # pip install pyjwt

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyber_defense.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Aegis_Shield_2026_Key'
db = SQLAlchemy(app)

# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user') # 'user' or 'admin'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    img_url = db.Column(db.String(300))

class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    attack_type = db.Column(db.String(100))
    payload = db.Column(db.String(500))
    endpoint = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    decision = db.Column(db.String(50)) # Blocked, Trapped
    threat_level = db.Column(db.Integer, default=1) # 1-5 for dash visuals

# --- NEW: PASSWORD VALIDATION HELPER ---
def is_strong_password(password):
    """Enforces: 8+ chars, 1 Uppercase, 1 Number, 1 Special Char"""
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[0-9]", password): return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False
    return True

# --- AI & HONEYPOT DETECTION ENGINE ---
ATTACK_PATTERNS = {
    "SQL Injection": (r"(' OR 1=1|UNION SELECT|DROP TABLE|--|;)", 4),
    "XSS Scripting": (r"(<script>|alert\(|onerror=|javascript:)", 3),
    "Directory Traversal": (r"(\.\./|\.\.\\|/etc/passwd|/boot/)", 5),
    "CSRF/Session Hijacking Attempt": (r"(csrf_token=XSS|admin=true&session=fake)", 4),
    "API Brute Force/Data Scraping": (r"(?s)(/api/products/\d+\.){5,}", 2), 
    "IDOR Privilege Escalation": (r"(user_id=0|admin=true&id=admin)", 5)
}

def analyze_and_respond(req):
    ip = req.remote_addr
    path = req.path
    payload = str(req.args.to_dict()) + str(req.form.to_dict()) + str(req.data)
    
    if path == '/admin-secret' or path == '/internal-db':
        log_attack(ip, "Honeypot Trap Trigger", path, "Trapped", 5)
        return "TRAP"

    for attack_name, (pattern, level) in ATTACK_PATTERNS.items():
        if re.search(pattern, payload, re.IGNORECASE) or re.search(pattern, path, re.IGNORECASE):
            log_attack(ip, attack_name, payload, "Trapped", level)
            return "TRAP" 
            
    return "ALLOW"

def log_attack(ip, type, payload, decision, level):
    new_log = AttackLog(ip=ip, attack_type=type, payload=str(payload)[:500], endpoint=request.path, decision=decision, threat_level=level)
    db.session.add(new_log)
    db.session.commit()

# --- SECURITY MIDDLEWARE ---
@app.before_request
def security_filter():
    if request.path in ['/api/login', '/api/register', '/fake-admin-panel']:
        return

    if request.path.startswith('/api/') or request.path == '/admin-secret':
        result = analyze_and_respond(request)
        if result == "TRAP":
            return redirect('/fake-admin-panel')

# --- USER AUTH ROUTES ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "All fields required"}), 400
    
    # MODIFIED: Check password strength
    if not is_strong_password(data['password']):
        return jsonify({"message": "WEAK_PASSWORD_ERROR"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already exists"}), 409
    
    hashed_pw = generate_password_hash(data['password'])
    new_user = User(username=data['username'], email=data['email'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registration successful"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"token": token, "user": {"id": user.id, "username": user.username, "role": user.role}}), 200
    return jsonify({"message": "Invalid email or password"}), 401

# --- UPDATED: PRODUCT API WITH SEARCH ---
@app.route('/api/products', methods=['GET'])
def get_products():
    category = request.args.get('category')
    search_query = request.args.get('q') 
    
    query = Product.query
    if category:
        query = query.filter_by(category=category)
    if search_query:
        query = query.filter(Product.name.ilike(f'%{search_query}%'))
        
    products = query.all()
    return jsonify([{"id": p.id, "name": p.name, "category": p.category, "price": p.price, "img_url": p.img_url} for p in products])

# --- UPDATED: ADMIN STATS (ACCESS TO MALICIOUS DATA) ---
@app.route('/api/admin/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    total_threats = AttackLog.query.count()
    total_trapped = AttackLog.query.filter_by(decision='Trapped').count()
    total_users = User.query.count()
    
    # FETCH RECENT MALICIOUS ACTIVITY LOGS
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(5).all()
    recent_threats = [{"detection": l.attack_type, "threat_level": l.threat_level, "source_ip": l.ip, "timestamp": l.timestamp.strftime("%H:%M:%S")} for l in logs]
    
    return jsonify({
        "total_threats": total_threats, 
        "total_defended": total_threats - total_trapped, 
        "total_failed": total_trapped, 
        "total_users": total_users,
        "recent_threats": recent_threats,
        "total_integrity": 7869, "critical_integrity": 2573, 
        "suspicious_integrity": 2117, "stable_integrity": 3179
    })

# --- HONEYPOT ROUTES ---
@app.route('/admin-secret', strict_slashes=False)
def admin_secret_trap():
    ip = request.remote_addr
    log_attack(ip, "Honeypot Trap Trigger", "/admin-secret", "Trapped", 5)
    return redirect('/fake-admin-panel')

@app.route('/fake-admin-panel', strict_slashes=False)
def fake_admin():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AEGIS // ADMIN_DASHBOARD_V4</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body { background: #0b1120; color: white; font-family: 'Inter', sans-serif; }
            .glass { background: rgba(255, 255, 255, 0.04); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.08); }
            .matrix-glow { color: #10b981; text-shadow: 0 0 10px #10b981; }
            .btn-fake { background: rgba(59, 130, 246, 0.1); border: 1px solid #3b82f6; transition: 0.3s; }
            .btn-fake:hover { background: #3b82f6; color: white; }
        </style>
    </head>
    <body class="p-8">
        <header class="flex justify-between items-center mb-10">
            <div>
                <h1 class="text-3xl font-bold matrix-glow">AEGIS <span class="text-white">DASHBOARD</span></h1>
                <p class="text-xs text-green-700 font-mono mt-1">SECURE_NODE: PRIMARY-DB-01 // SESSION: AUTH_BYPASS_DETECTED</p>
            </div>
            <div class="flex space-x-4">
                <div class="glass px-4 py-2 rounded-lg text-xs font-mono text-gray-400">SERVER_TIME: 00:42:18</div>
                <button onclick="alert('SYSTEM LOCKDOWN: Terminal Access Only')" class="bg-red-900/30 border border-red-600 text-red-500 px-4 py-2 rounded-lg text-sm font-bold">EMERGENCY SHUTDOWN</button>
            </div>
        </header>
        <div class="grid grid-cols-4 gap-6 mb-8">
            <div class="glass p-6 rounded-3xl border-l-4 border-blue-500"><p class="text-gray-500 text-sm">Total Sales</p><p class="text-3xl font-bold mt-1">₹8,42,190.00</p></div>
            <div class="glass p-6 rounded-3xl border-l-4 border-green-500"><p class="text-gray-500 text-sm">Active Sessions</p><p class="text-3xl font-bold mt-1">1,042</p></div>
            <div class="glass p-6 rounded-3xl border-l-4 border-purple-500"><p class="text-gray-500 text-sm">Database Load</p><p class="text-3xl font-bold mt-1">12%</p></div>
            <div class="glass p-6 rounded-3xl border-l-4 border-yellow-500"><p class="text-gray-500 text-sm">Pending Shipments</p><p class="text-3xl font-bold mt-1">84</p></div>
        </div>
        <div class="grid grid-cols-3 gap-6">
            <div class="glass p-8 rounded-3xl space-y-6">
                <h3 class="text-xl font-semibold border-b border-gray-800 pb-4">User Access Control</h3>
                <div class="space-y-4">
                    <div class="flex justify-between items-center bg-gray-900/50 p-3 rounded-xl border border-gray-800"><span class="text-sm font-mono text-blue-400">admin_root</span><button onclick="alert('Action Logged')" class="text-xs text-gray-500 underline">View Hash</button></div>
                    <div class="flex justify-between items-center bg-gray-900/50 p-3 rounded-xl border border-gray-800"><span class="text-sm font-mono text-blue-400">finance_lead</span><button onclick="alert('Action Logged')" class="text-xs text-gray-500 underline">View Hash</button></div>
                </div>
                <button onclick="alert('ERROR: Quarantine Buffer Full')" class="w-full btn-fake py-3 rounded-xl font-bold text-blue-400">DOWNLOAD USER_DB.SQL</button>
            </div>
            <div class="lg:col-span-2 glass p-8 rounded-3xl">
                <h3 class="text-xl font-semibold mb-6">Internal System Logs</h3>
                <div class="space-y-3 font-mono text-xs text-gray-500">
                    <p class="text-green-500">[00:41:02] Connection established from IP: """ + request.remote_addr + """</p>
                    <p>[00:41:08] Escalating privileges to ROOT... SUCCESS</p>
                    <p class="animate-pulse text-red-500 font-bold">[!] ERROR: BACKDOOR DETECTED. COMMENCING DATA QUARANTINE...</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/elevate-demo-admin')
def elevate_admin():
    user = User.query.first()
    if user:
        user.role = 'admin'
        db.session.commit()
        return f"User {user.username} is now ADMIN."
    return "Register a user first."

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not Product.query.first():
            items_map = {
                "Clothes": ["Cotton T-Shirt", "Denim Jacket", "Formal Trouser", "Hooded Sweatshirt", "Summer Dress"],
                "Electronics": ["Smartphone", "Wireless Earbuds", "Gaming Mouse", "Mechanical Keyboard", "Smart Watch"],
                "Jewellery": ["Silver Ring", "Gold Pendant", "Crystal Earrings", "Luxury Watch", "Pearl Necklace"],
                "Toys": ["Building Blocks", "Remote Control Car", "Action Figure", "Teddy Bear", "Puzzle Set"]
            }
            all_items = []
            for category, names in items_map.items():
                for name in names:
                    search_query = f"{name} product shot white background isolated".replace(' ', ',')
                    img_url = f"https://images.unsplash.com/photo-1?auto=format&fit=crop&w=500&q=80&sig={random.randint(1, 5000)}&{search_query}"
                    all_items.append(Product(name=f"Aegis {name}", category=category, price=round(random.uniform(499, 45000), 2), img_url=img_url))
            db.session.add_all(all_items)
            db.session.commit()
    app.run(debug=True, port=5000)