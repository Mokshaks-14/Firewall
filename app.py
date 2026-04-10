import datetime
import re
import random
from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt 

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
    phone = db.Column(db.String(10), nullable=True) 
    address = db.Column(db.String(300), nullable=True) 
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user') 
    orders = db.relationship('Order', backref='user', lazy=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(20), unique=True)
    total_price = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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
    decision = db.Column(db.String(50)) 
    threat_level = db.Column(db.Integer, default=1)

# --- PASSWORD VALIDATION HELPER ---
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
    if request.path in ['/api/login', '/api/register', '/fake-admin-panel', '/api/user/update']:
        return
    if request.path.startswith('/api/') or request.path == '/admin-secret':
        result = analyze_and_respond(request)
        if result == "TRAP":
            return redirect('/fake-admin-panel')

# --- USER AUTH ROUTES ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('phone') or not data.get('password'):
        return jsonify({"message": "All fields required"}), 400
    if not re.match(r"^[0-9]{10}$", str(data.get('phone', ''))):
        return jsonify({"message": "Invalid Phone (10 digits required)"}), 400
    if not is_strong_password(data['password']):
        return jsonify({"message": "WEAK_PASSWORD_ERROR"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already exists"}), 409
    hashed_pw = generate_password_hash(data['password'])
    new_user = User(username=data['username'], email=data['email'], phone=data['phone'], address=data.get('address', 'Not Set'), password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registration successful"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        if str(user.phone) != str(data.get('phone')): return jsonify({"message": "Phone number mismatch!"}), 401
        token = jwt.encode({'user_id': user.id, 'role': user.role, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"token": token, "user": {"id": user.id, "username": user.username, "role": user.role, "email": user.email, "phone": user.phone, "address": user.address}}), 200
    return jsonify({"message": "Invalid email or password"}), 401

# --- FIXED: UPDATE ACCOUNT ROUTE ---
@app.route('/api/user/update', methods=['POST'])
def update_user():
    data = request.json
    user = User.query.get(data.get('id'))
    if user:
        user.username = data.get('username', user.username)
        user.phone = data.get('phone', user.phone)
        user.address = data.get('address', user.address)
        db.session.commit()
        # Return full user object to frontend so it doesn't lose state/logout
        return jsonify({
            "message": "Profile Updated", 
            "user": {
                "id": user.id, 
                "username": user.username, 
                "email": user.email, 
                "phone": user.phone, 
                "address": user.address, 
                "role": user.role
            }
        }), 200
    return jsonify({"message": "User not found"}), 404

# --- USER PROFILE & ORDERS ---
@app.route('/api/user/orders/<int:user_id>', methods=['GET'])
def get_user_orders(user_id):
    orders = Order.query.filter_by(user_id=user_id).all()
    return jsonify([{"order_id": o.order_id, "total": o.total_price, "date": o.timestamp.strftime("%Y-%m-%d")} for o in orders])

@app.route('/api/place-order', methods=['POST'])
def place_order():
    data = request.json
    new_order = Order(order_id=data['order_id'], total_price=data['total'], user_id=data['user_id'])
    db.session.add(new_order)
    db.session.commit()
    return jsonify({"message": "Order Saved"}), 201

# --- PRODUCT & ADMIN API ---
@app.route('/api/products', methods=['GET'])
def get_products():
    q, cat = request.args.get('q'), request.args.get('category')
    query = Product.query
    if cat: query = query.filter_by(category=cat)
    if q: query = query.filter(Product.name.ilike(f'%{q}%'))
    products = query.all()
    return jsonify([{"id": p.id, "name": p.name, "category": p.category, "price": p.price, "img_url": p.img_url} for p in products])

@app.route('/api/admin/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    total_threats = AttackLog.query.count()
    total_trapped = AttackLog.query.filter_by(decision='Trapped').count()
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(5).all()
    recent_threats = [{"detection": l.attack_type, "threat_level": l.threat_level, "source_ip": l.ip, "timestamp": l.timestamp.strftime("%H:%M:%S")} for l in logs]
    return jsonify({
        "total_threats": total_threats, "total_defended": total_threats - total_trapped, 
        "total_failed": total_trapped, "total_users": User.query.count(),
        "recent_threats": recent_threats,
        "total_integrity": 7869, "critical_integrity": 2573, "suspicious_integrity": 2117, "stable_integrity": 3179
    })

# --- DECEPTION UI ---
@app.route('/fake-admin-panel', strict_slashes=False)
def fake_admin():
    return """<body style='background:#000;color:#0f0;padding:50px;font-family:monospace;'><h1>DECEPTION ACTIVE</h1><p>IP Traced: """ + request.remote_addr + """</p></body>"""

@app.route('/elevate-demo-admin')
def elevate_admin():
    user = User.query.first()
    if user:
        user.role = 'admin'
        db.session.commit()
        return f"User {user.username} is now ADMIN."
    return "Register first."

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not Product.query.first():
            items_map = {"Jewellery": ["Gold Ring"], "Toys": ["Drone"], "Clothes": ["Hoodie"], "Electronics": ["Phone"]}
            for category, names in items_map.items():
                for name in names:
                    img_url = f"https://loremflickr.com/320/240/{name.replace(' ', '')}?random={random.randint(1,5000)}"
                    db.session.add(Product(name=f"Aegis {name}", category=category, price=5000, img_url=img_url))
            db.session.commit()
    app.run(debug=True, port=5000)