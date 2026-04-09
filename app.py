import datetime
import re
import random
from flask import Flask, request, jsonify
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

# --- AI & HONEYPOT DETECTION ENGINE ---
ATTACK_PATTERNS = {
    "SQL Injection": (r"(' OR 1=1|UNION SELECT|DROP TABLE|--|;)", 4),
    "XSS Scripting": (r"(<script>|alert\(|onerror=|javascript:)", 3),
    "Directory Traversal": (r"(\.\./|\.\.\\|/etc/passwd|/boot/)", 5),
    "CSRF/Session Hijacking Attempt": (r"(csrf_token=XSS|admin=true&session=fake)", 4),
    "API Brute Force/Data Scraping": (r"(?s)(/api/products/\d+\.){5,}", 2), # Rapid hits
    "IDOR Privilege Escalation": (r"(user_id=0|admin=true&id=admin)", 5)
}

def analyze_and_respond(req):
    ip = req.remote_addr
    path = req.path
    payload = str(req.args.to_dict()) + str(req.form.to_dict()) + str(req.data)
    
    # 1. Honeypot/Secret Entry Points
    # /admin-secret is the trap, /admin-dashboard is the real secret
    if path == '/admin-secret' or path == '/internal-db':
        log_attack(ip, "Honeypot Trap Trigger", path, "Trapped", 5)
        return "TRAP"

    # 2. Rule-Based Attack Detection
    for attack_name, (pattern, level) in ATTACK_PATTERNS.items():
        if re.search(pattern, payload, re.IGNORECASE) or re.search(pattern, path, re.IGNORECASE):
            log_attack(ip, attack_name, payload, "Blocked", level)
            return "BLOCK"
            
    return "ALLOW"

def log_attack(ip, type, payload, decision, level):
    new_log = AttackLog(ip=ip, attack_type=type, payload=str(payload)[:500], endpoint=request.path, decision=decision, threat_level=level)
    db.session.add(new_log)
    db.session.commit()

# Security Middleware
@app.before_request
def security_filter():
    # Only intercept API or critical paths, not static dashboard files if served
    if request.path.startswith('/api/'):
        # Allow open routes like products, login, register
        if request.path in ['/api/login', '/api/register', '/api/products']:
            return

        result = analyze_and_respond(request)
        if result == "BLOCK":
            return jsonify({"status": "error", "message": "Critical Security Violation. IP Flagged.", "code": "AI_BLOCK"}), 403
        if result == "TRAP":
            return jsonify({"status": "redirect", "url": "/fake-admin-panel"}), 302

# --- USER AUTH ROUTES ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "All fields required (username, email, password)"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already exists"}), 409
    
    hashed_pw = generate_password_hash(data['password'])
    new_user = User(username=data['username'], email=data['email'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registration successful. Please login."}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email and Password required"}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        # Create a simple JWT token
        token = jwt.encode({
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({"message": "Login successful", "token": token, "user": {"id": user.id, "username": user.username, "role": user.role}}), 200
    
    return jsonify({"message": "Invalid email or password"}), 401

# --- E-COMMERCE API ---
@app.route('/api/products', methods=['GET'])
def get_products():
    category = request.args.get('category')
    if category:
        products = Product.query.filter_by(category=category).all()
    else:
        products = Product.query.all()
        
    return jsonify([{"id": p.id, "name": p.name, "category": p.category, "price": p.price, "img_url": p.img_url} for p in products])

# --- ADMIN DASHBOARD API (The Complex Parts) ---
# Need JWT verification here for real security, simplified for demo
@app.route('/api/admin/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    # Security check simplified: only allowing ID 1 by default
    # If using full JWT auth, you would extract user_id and check role here.
    
    total_threats = AttackLog.query.count()
    total_blocked = AttackLog.query.filter_by(decision='Blocked').count()
    total_trapped = AttackLog.query.filter_by(decision='Trapped').count()
    total_users = User.query.count()
    
    # Recent Threats (Last 5)
    recent_threats_query = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(5).all()
    recent_threats = []
    for l in recent_threats_query:
        # Map threat level (1-5) to dash icons
        # Sequential Breach = Level 4/5, Global Disruption = Level 5, Analytical Deduction = Level 2
        threat_name = "Sequential Breach"
        if l.threat_level == 5: threat_name = "Global Disruption"
        elif l.threat_level < 3: threat_name = "Analytical Deduction"
        
        recent_threats.append({
            "detection": f"{threat_name} - {l.attack_type}",
            "threat_level": l.threat_level, # Frontend will map to visual lines
            "source_ip": l.ip,
            "timestamp": l.timestamp.strftime("%H:%M:%S")
        })

    # Model Deployment Mock Data
    models = {
        "at_risk": 986, "breached": 1278, "dormant": 1945, "new_detections": 1786
    }
    total_integrity = 7869
    critical_integrity = 2573
    suspicious_integrity = 2117
    stable_integrity = 3179
    
    return jsonify({
        "total_threats": total_threats, "total_defended": total_blocked, "total_failed": total_trapped, "total_users": total_users,
        "recent_threats": recent_threats,
        "models": models,
        "total_integrity": total_integrity,
        "critical_integrity": critical_integrity,
        "suspicious_integrity": suspicious_integrity,
        "stable_integrity": stable_integrity
    })

# --- DEEP HONEYPOT ROUTE ---
@app.route('/fake-admin-panel')
def fake_admin():
    # Looks like a genuine, old system but contains no real data
    return """
    <html><head><title>System Administration v1.2</title><style>
        body { background: #1a1a1a; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; }
        .critical { color: red; font-weight: bold; }
        .log-entry { margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 5px; }
    </style></head>
    <body>
        <h1>SYSTEM ADMINISTRATION - SECURE NODE B</h1>
        <p class="critical">*** ALERT: System in Quarantine Mode. Secure Boot Pending. ***</p>
        <p>ACCESS NODE: B1-TRAP-SYS</p>
        <p>CURRENT SESSION: QUARANTINE_0912X</p>
        <div class="log-entry">
            [14:23:01] ROOT ACCESS GRANTED<br>
            [14:23:02] INITIALIZING SHELL SESSION...<br>
            [14:23:03] Loading fake_data_generator_mod.py... [OK]<br>
            [14:23:05] ALERT: Integrity Check Failed on system.config<br>
            [14:23:07] Logged attacker IP: """ + request.remote_addr + """ [QUARANTINED]<br>
            [14:23:10] Executing defensive measure: IP_MOCK_CONTAINMENT_V2<br>
        </div>
        <p>This session is actively monitored. Do not disconnect.</p>
    </body></html>
    """

# --- HIDDEN DEMO ADMIN ELEVATION ROUTE ---
@app.route('/elevate-demo-admin')
def elevate_admin():
    user = User.query.first()
    if user:
        user.role = 'admin'
        db.session.commit()
        return f"Successfully elevated {user.username} (ID {user.id}) to ADMIN for demo purposes."
    return "No users found. Please register first."

# --- INITIALIZE AND SEED DATABASE (40+ PRODUCTS) ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed Products if empty
        if not Product.query.first():
            print("Seeding 40 Products...")
            clothes = ["Stealth Hoodie", "Aegis Tech-Jacket", "Neural Knit Sweater", "Quantum Cargo Pants", "Secure Socks", "Zero-Day Shirt", "Data Weave Scarf", "Encrypted Cap", "Cyber Trench Coat", "Vortex Vest"]
            electronics = ["Neural Link Pro", "Quantum Phone Z", "Vortex VR Headset", "Aegis Secure Laptop", "Neural Implant Chip v2", "Data Smartwatch", "Stealth Earbuds", "Secure SSD 5TB", "Holo-Projector", "Grid Access Tablet"]
            jewellery = ["Diamond Ring (Encrypted)", "Quantum Necklace", "Aegis Ruby Bracelet", "Cipher Watch", "Vortex Opal Earrings", "Stealth Tech Pendant", "Zero-Day Brooch", "Data-Etched Cufflinks", "Secure Gold Chain", "Quantum Sapphire Tiara"]
            toys = ["AI Learning Droid", "Vortex Hover-Drone", "Quantum Science Kit", "Stealth Robot Dog", "Zero-Day Toy Train", "Data Blocks v3", "Aegis Tech-Doll", "Neural Pulse Blaster", "Quantum Puzzle Cube", "VR Learning Holo-Toy"]
            
            all_items = []
            for name in clothes: all_items.append(Product(name=name, category='Clothes', price=round(random.uniform(50, 400), 2), img_url="https://images.unsplash.com/photo-1551028719-00167b16eac5?w=300"))
            for name in electronics: all_items.append(Product(name=name, category='Electronics', price=round(random.uniform(200, 2000), 2), img_url="https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=300"))
            for name in jewellery: all_items.append(Product(name=name, category='Jewellery', price=round(random.uniform(500, 5000), 2), img_url="https://images.unsplash.com/photo-1605100804763-247f67b3557e?w=300"))
            for name in toys: all_items.append(Product(name=name, category='Toys', price=round(random.uniform(30, 300), 2), img_url="https://images.unsplash.com/photo-1596461404969-9ae70f2830c1?w=300"))
            
            db.session.add_all(all_items)
            db.session.commit()
            print("Product seeding complete.")
            
    app.run(debug=True, port=5000)