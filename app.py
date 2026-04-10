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
# --- BEHAVIORAL ANALYSIS STORAGE ---
user_activity = {} 

def is_behavior_malicious(user_id):
    now = datetime.datetime.utcnow() # Use utcnow to match your DB timestamps
    if user_id not in user_activity:
        user_activity[user_id] = []
    
    # Keep only the timestamps of orders from the last 60 seconds
    user_activity[user_id] = [t for t in user_activity[user_id] if (now - t).total_seconds() < 60]
    
    # If a user tries to place more than 5 orders in 1 minute, it's suspicious
    # (I changed it to 5 for easier testing)
    if len(user_activity[user_id]) > 5:
        return True
    
    user_activity[user_id].append(now)
    return False

def analyze_and_respond(req):
    ip = req.remote_addr
    path = req.path
    # FIX: Scans URL args, Form data, and JSON Body text for malicious payloads
    payload = str(req.args.to_dict()) + str(req.form.to_dict()) + str(req.get_data(as_text=True))
    
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
    # Never trap the honeypots themselves or the admin elevation tool
    if request.path in ['/api/login', '/api/register', '/fake-admin-panel', '/fake-user-profile', '/elevate-demo-admin']:
        return
        
    result = analyze_and_respond(request)
    if result == "TRAP":
        # Redirect based on whether they hit an admin endpoint or a user endpoint
        if 'admin' in request.path or request.path == '/admin-secret':
            return redirect('/fake-admin-panel')
        else:
            return redirect('/fake-user-profile')

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

# --- UPDATE ACCOUNT ROUTE ---
@app.route('/api/user/update', methods=['POST'])
def update_user():
    data = request.json
    user = User.query.get(data.get('id'))
    if user:
        user.username = data.get('username', user.username)
        user.phone = data.get('phone', user.phone)
        user.address = data.get('address', user.address)
        db.session.commit()
        return jsonify({
            "message": "Profile Updated", 
            "user": {
                "id": user.id, "username": user.username, "email": user.email, 
                "phone": user.phone, "address": user.address, "role": user.role
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
    u_id = data.get('user_id')

    # --- NEW BEHAVIORAL CHECK ---
    if is_behavior_malicious(u_id):
        log_attack(request.remote_addr, "Velocity Attack (Bot)", f"User {u_id} spamming orders", "Trapped", 4)
        # We don't redirect here because it's an API call, 
        # but we return a code that tells the frontend to redirect
        return jsonify({"redirect": "/fake-user-profile"}), 302 

    # Original logic continues below...
    new_order = Order(order_id=data['order_id'], total_price=data['total'], user_id=u_id)
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

# --- DECEPTION UI & ROUTES ---
@app.route('/admin-secret', strict_slashes=False)
def admin_secret_trap():
    log_attack(request.remote_addr, "Honeypot Trap Trigger", "/admin-secret", "Trapped", 5)
    return redirect('/fake-admin-panel')

# --- HONEYPOT: THE FAKE ADMIN PANEL (Tricks attacker into thinking they have Root) ---
@app.route('/fake-admin-panel', strict_slashes=False)
def fake_admin_panel():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Monitor | SHOP-X_INTERNAL</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body { background: #0f172a; color: white; font-family: 'Inter', sans-serif; }
            .glass { background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255,255,255,0.06); }
        </style>
    </head>
    <body class="bg-[#0b1120] min-h-screen p-8">
        <header class="flex justify-between items-center mb-10 border-b border-gray-800 pb-4">
            <h1 class="text-3xl font-bold text-white">Security Monitor <span class="text-xs text-green-400 font-mono tracking-widest">[ROOT_ACCESS_GRANTED]</span></h1>
            <div class="flex items-center space-x-4">
                <span class="text-red-400 font-bold border border-red-900 px-3 py-1 rounded animate-pulse">Forensic Trace ACTIVE</span>
            </div>
        </header>
        <div class="grid grid-cols-4 gap-6 mb-8">
            <div class="glass p-6 rounded-3xl"><p class="text-gray-500 text-sm">Total Threats</p><p class="text-4xl font-bold">14,215</p></div>
            <div class="glass p-6 rounded-3xl"><p class="text-gray-500 text-sm">Trapped Intruders</p><p class="text-4xl font-bold text-red-400">3,179</p></div>
            <div class="glass p-6 rounded-3xl"><p class="text-gray-500 text-sm">Authorized Admins</p><p class="text-4xl font-bold">1</p></div>
            <div class="glass p-6 rounded-3xl"><p class="text-gray-500 text-sm">AI Stability</p><p class="text-4xl font-bold text-green-400">99.8%</p></div>
        </div>
        <div class="grid grid-cols-2 gap-8">
            <div class="glass p-8 rounded-3xl min-h-[300px]">
                <h3 class="text-xl font-bold mb-6">Internal Access Logs</h3>
                <div class="space-y-2 font-mono text-xs text-blue-300">
                    <p>> Connection established from 127.0.0.1</p>
                    <p>> Fetching user_hash_table... [SUCCESS]</p>
                    <p>> Root bypass detected... [TRAPPED]</p>
                </div>
            </div>
            <div class="glass p-8 rounded-3xl flex items-center justify-center border-l-4 border-green-500">
                <p class="text-green-500 font-mono animate-pulse">Monitoring stableintegrity... [7,869 Stable]</p>
            </div>
        </div>
    </body>
    </html>
    """

# --- HONEYPOT: THE FAKE USER PROFILE (Identical to Real Dashboard UI) ---
@app.route('/fake-user-profile', strict_slashes=False)
def fake_user_profile():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SHOP-X | Secure Store</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body { background: #0f172a; color: white; font-family: 'Inter', sans-serif; }
            .glass { background: rgba(255, 255, 255, 0.04); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.06); }
            .cyber-dash { background-color: #0b1120; }
            .btn-blue { background-color: #3b82f6; }
        </style>
    </head>
    <body>
        <nav class="flex justify-between items-center px-10 py-6 glass sticky top-0 z-50">
            <h1 class="text-2xl font-bold text-blue-400 cursor-default">SHOP-X</h1>
            <div class="flex-1 max-w-md mx-10">
                <input type="text" placeholder="Search products..." class="w-full bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 outline-none">
            </div>
            <div class="flex items-center space-x-6">
                <span class="text-gray-400 text-sm">Welcome, admin_backup_01</span>
                <button class="relative text-gray-400">🛒 Cart <span class="absolute -top-2 -right-3 bg-red-600 text-xs w-5 h-5 flex items-center justify-center rounded-full font-bold">0</span></button>
                <button class="text-blue-400 font-bold border border-blue-900 px-3 py-1 rounded">🛡 Dashboard</button>
                <button class="text-sm text-gray-400">Logout</button>
            </div>
        </nav>

        <div class="flex">
            <aside class="w-64 p-10 space-y-4 border-r border-gray-800 min-h-screen">
                <h3 class="text-xs uppercase text-gray-600 font-bold tracking-widest">Categories</h3>
                <button class="w-full text-left p-2 hover:bg-gray-800 rounded">All Items</button>
                <button class="w-full text-left p-2 hover:bg-gray-800 rounded">Clothes</button>
                <button class="w-full text-left p-2 hover:bg-gray-800 rounded">Electronics</button>
                <hr class="border-gray-800">
                <button class="w-full text-left p-2 text-green-400 bg-gray-800 rounded">📦 My Orders</button>
                <button class="w-full text-left p-2 text-yellow-400 hover:bg-gray-800 rounded">👤 My Account</button>
            </aside>

            <main class="flex-1 p-10">
                <div class="glass p-10 rounded-3xl min-h-[500px] border-l-4 border-blue-500">
                    <div class="flex justify-between items-center mb-8">
                        <h2 class="text-2xl font-bold">Encrypted Order History</h2>
                        <span class="text-green-400 font-mono text-xs animate-pulse">SSL_ENCRYPTED_TUNNEL_ACTIVE</span>
                    </div>

                    <div class="space-y-6">
                        <div class="glass p-6 rounded-2xl flex justify-between items-center">
                            <div class="flex items-center space-x-4">
                                <div class="w-16 h-16 bg-blue-900/20 rounded-xl flex items-center justify-center text-2xl">💎</div>
                                <div>
                                    <p class="text-xs text-gray-500 font-mono">ID: #ORD-B771-K</p>
                                    <h3 class="font-bold">Aegis Luxury Diamond Watch - Platinum Edition</h3>
                                    <p class="text-xs text-blue-300">Status: Shipped to Private Vault</p>
                                </div>
                            </div>
                            <div class="text-right">
                                <p class="text-2xl font-bold text-blue-400">₹1,85,000.00</p>
                                <p class="text-[10px] text-gray-600 uppercase">Paid via Crypto_Vault</p>
                            </div>
                        </div>

                        <div class="mt-12 p-8 bg-blue-900/10 border border-blue-500/20 rounded-3xl">
                            <div class="flex items-center space-x-3 mb-4">
                                <div class="w-3 h-3 bg-red-500 rounded-full animate-ping"></div>
                                <h3 class="text-sm font-bold text-blue-300 uppercase tracking-widest">Sensitive System Assets Detected</h3>
                            </div>
                            <p class="text-sm text-gray-400 mb-6">User session has elevated read-access to the transaction backup server (Alpha-Node-7).</p>
                            
                            <div class="grid grid-cols-2 gap-4 mb-8">
                                <div class="bg-black/40 p-4 rounded-xl border border-gray-800">
                                    <p class="text-[10px] text-gray-500">INTERNAL_IP</p>
                                    <p class="text-sm font-mono text-green-400">10.0.0.254</p>
                                </div>
                                <div class="bg-black/40 p-4 rounded-xl border border-gray-800">
                                    <p class="text-[10px] text-gray-500">AUTH_TOKEN</p>
                                    <p class="text-sm font-mono text-green-400 text-xs">shx_live_9921_decoy</p>
                                </div>
                            </div>

                            <button onclick="alert('CRITICAL ERROR: Connection to core database timed out. Access logged.')" 
                                    class="w-full py-4 bg-blue-600 hover:bg-blue-700 rounded-2xl font-bold transition shadow-lg shadow-blue-500/20">
                                DOWNLOAD TRANSACTION_DUMP.CSV (2.4 MB)
                            </button>
                        </div>
                    </div>
                </div>
                <p class="text-center text-[10px] text-gray-700 mt-10 font-mono">SHOPX_FORENSIC_TRAP_ENABLED // TRACE_ID: 0x992B</p>
            </main>
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
    return "Register first."

if __name__ == '__main__':
    with app.app_context():
        # Line ~287: Create tables only if they don't exist
        db.create_all()
        
        # Line ~290: Set your specific email to always be Admin
        # Change 'moksha@example.com' to your actual registration email
        my_admin_email = "moksha@gmail.com" 
        
        target_user = User.query.filter_by(email=my_admin_email).first()
        if target_user:
            target_user.role = 'admin'
            db.session.commit()
            print(f"✔️ PERMANENT ADMIN ACTIVE: {target_user.username}")
        else:
            print("ℹ️ Admin email not found in DB yet. Register first!")
        db.create_all()
        if not Product.query.first():
            items_map = {
                "Clothes": ["Leather Jacket", "Denim Jeans", "Silk Saree", "Cotton Hoodie", "Formal Suit", "Running Shoes", "Woolen Sweater", "Cargo Pants", "Polo Shirt", "Summer Dress"],
                "Electronics": ["Gaming Laptop", "Wireless Headphones", "Mechanical Keyboard", "Mirrorless Camera", "Smart Speaker", "Drone Quadcopter", "VR Headset", "Tablet Pro", "OLED Monitor", "Power Bank"],
                "Jewellery": ["Diamond Ring", "Gold Necklace", "Silver Bracelet", "Pearl Earrings", "Luxury Watch", "Gemstone Pendant", "Platinum Bands", "Ruby Studs", "Crystal Brooch", "Antique Locket"],
                "Toys": ["LEGO Castle", "Remote Control Car", "Barbie Dollhouse", "Chess Set", "Plush Bear", "Action Figure Hero", "Rubiks Cube", "Hot Wheels Track", "Telescope for Kids", "Art Supplies Kit"]
            }
            all_products = []
            for category, names in items_map.items():
                for name in names:
                    image_query = name.replace(" ", "+")
                    img_url = f"https://loremflickr.com/400/400/{image_query}?random={random.randint(1,1000)}"
                    all_products.append(Product(name=f"Aegis {name}", category=category, price=round(random.uniform(999, 85000), 2), img_url=img_url))
            db.session.add_all(all_products)
            db.session.commit()
            print("Successfully seeded 40 high-quality items!")

    app.run(debug=True, port=5000)