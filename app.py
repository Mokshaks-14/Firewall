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
    
    # 1. Honeypot/Secret Entry Points
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

# --- SECURITY MIDDLEWARE ---
@app.before_request
def security_filter():
    # Only allow Login and Register to skip the security check
    # We REMOVE '/api/products' from this list
    if request.path in ['/api/login', '/api/register']:
        return

    # Now, every other /api/ request (including products) gets scanned
    if request.path.startswith('/api/'):
        result = analyze_and_respond(request)
        
        if result == "BLOCK":
            return jsonify({
                "status": "error", 
                "message": "AI Security Violation: Malicious Pattern Detected", 
                "code": "AI_BLOCK"
            }), 403
            
        if result == "TRAP":
            return jsonify({"status": "redirect", "url": "/fake-admin-panel"}), 302
# --- USER AUTH ROUTES ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "All fields required"}), 400
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

# --- E-COMMERCE API ---
@app.route('/api/products', methods=['GET'])
def get_products():
    category = request.args.get('category')
    products = Product.query.filter_by(category=category).all() if category else Product.query.all()
    return jsonify([{"id": p.id, "name": p.name, "category": p.category, "price": p.price, "img_url": p.img_url} for p in products])

# --- ADMIN DASHBOARD API ---
@app.route('/api/admin/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    total_threats = AttackLog.query.count()
    total_blocked = AttackLog.query.filter_by(decision='Blocked').count()
    total_trapped = AttackLog.query.filter_by(decision='Trapped').count()
    total_users = User.query.count()
    
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(5).all()
    recent_threats = []
    for l in logs:
        threat_name = "Sequential Breach"
        if l.threat_level == 5: threat_name = "Global Disruption"
        elif l.threat_level < 3: threat_name = "Analytical Deduction"
        
        recent_threats.append({
            "detection": f"{threat_name} - {l.attack_type}",
            "threat_level": l.threat_level,
            "source_ip": l.ip,
            "timestamp": l.timestamp.strftime("%H:%M:%S")
        })
    
    return jsonify({
        "total_threats": total_threats, "total_defended": total_blocked, 
        "total_failed": total_trapped, "total_users": total_users,
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
    <html><head><title>System Administration v1.2</title><style>
        body { background: #1a1a1a; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; }
        .critical { color: red; font-weight: bold; }
    </style></head>
    <body>
        <h1>SYSTEM ADMINISTRATION - SECURE NODE B</h1>
        <p class="critical">*** ALERT: System in Quarantine Mode. Secure Boot Pending. ***</p>
        <p>ACCESS NODE: B1-TRAP-SYS</p>
        <p>> ROOT ACCESS GRANTED</p>
        <p>> INITIALIZING SHELL SESSION... [OK]</p>
        <p>> Logged attacker IP: """ + request.remote_addr + """ [QUARANTINED]</p>
    </body></html>
    """

@app.route('/elevate-demo-admin')
def elevate_admin():
    user = User.query.first()
    if user:
        user.role = 'admin'
        db.session.commit()
        return f"User {user.username} is now ADMIN."
    return "Register a user first."

# --- SEEDING ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not Product.query.first():
            print("Seeding Professional E-commerce Products...")
            
            # Refined names and categories for "Amazon/Flipkart" style
            items_map = {
                "Clothes": ["Cotton T-Shirt", "Denim Jacket", "Formal Trouser", "Hooded Sweatshirt", "Summer Dress"],
                "Electronics": ["Smartphone", "Wireless Earbuds", "Gaming Mouse", "Mechanical Keyboard", "Smart Watch"],
                "Jewellery": ["Silver Ring", "Gold Pendant", "Crystal Earrings", "Luxury Watch", "Pearl Necklace"],
                "Toys": ["Building Blocks", "Remote Control Car", "Action Figure", "Teddy Bear", "Puzzle Set"]
            }

            all_items = []
            for category, names in items_map.items():
                for name in names:
                    # We add "product shot white background" to the search query
                    # This tells the API to look for clean, professional catalog images
                    search_query = f"{name} product shot white background isolated".replace(' ', ',')
                    
                    # Using Unsplash with specific professional filters
                    img_url = f"https://images.unsplash.com/photo-1?auto=format&fit=crop&w=500&q=80&sig={random.randint(1, 5000)}&{search_query}"
                    
                    all_items.append(Product(
                        name=f"Aegis {name}", 
                        category=category, 
                        price=round(random.uniform(499, 45000), 2), 
                        img_url=img_url
                    ))
            
            db.session.add_all(all_items)
            db.session.commit()
    app.run(debug=True, port=5000)