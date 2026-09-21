"""
Python Web Application (Flask) demonstrating:
1. Session Authentication (Cookie-based with secure headers)
2. JWT Authentication (JSON Web Token for API endpoints)
3. Brute Force Protection (Rate limiting & Account/IP lockout)

How to run:
    pip install flask pyjwt
    python app.py
Then open: http://127.0.0.1:5000
"""

import time
import datetime
# pyrefly: ignore [missing-import]
import jwt
from functools import wraps
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template_string,
    jsonify,
)

app = Flask(__name__)

# ==========================================
# 1. CONFIGURATION & CONSTANTS
# ==========================================

# Secret Keys
app.secret_key = "super-secret-session-key-change-in-production"
JWT_SECRET_KEY = "super-secret-jwt-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DELTA = datetime.timedelta(minutes=30)

# Cookie Security Configs
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevents XSS script access to session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Helps prevent CSRF attacks
app.config["SESSION_COOKIE_SECURE"] = False   # Set to True in production with HTTPS

# Demo Accounts (In real apps, use hashed passwords in a database e.g., bcrypt/argon2)
USERS = {
    "admin": "123456",
    "user": "password"
}

# Brute Force Protection Configuration
MAX_FAILED_ATTEMPTS = 5       # Max failed attempts allowed
LOCKOUT_TIME_SECONDS = 300     # Lockout duration: 5 minutes (300 seconds)

# In-memory storage for tracking failed login attempts
# Format: { "key": {"count": int, "lock_until": float timestamp} }
FAILED_ATTEMPTS = {}


# ==========================================
# 2. BRUTE FORCE PROTECTION HELPERS
# ==========================================

def get_client_identifier(username=""):
    """
    Returns a unique key combining Client IP and target Username.
    Tracking both IP + Username prevents single-user lockouts targeting everyone
    and blocks distributed brute force attacks against a single user.
    """
    client_ip = request.remote_addr or "127.0.0.1"
    return f"{client_ip}:{username.strip().lower()}"


def check_brute_force_lockout(key):
    """
    Checks if an IP/Username identifier is currently locked out.
    Returns (is_locked: bool, seconds_remaining: int)
    """
    record = FAILED_ATTEMPTS.get(key)
    if not record:
        return False, 0

    now = time.time()
    lock_until = record.get("lock_until", 0)

    if lock_until > now:
        return True, int(lock_until - now)
    
    # If lockout time has passed, reset record
    if lock_until > 0 and lock_until <= now:
        FAILED_ATTEMPTS.pop(key, None)

    return False, 0


def record_failed_attempt(key):
    """
    Increments failed attempt counter and sets lock_until timestamp if threshold exceeded.
    Returns (current_attempts: int, is_locked: bool, seconds_remaining: int)
    """
    now = time.time()
    record = FAILED_ATTEMPTS.get(key, {"count": 0, "lock_until": 0})
    
    record["count"] += 1
    
    if record["count"] >= MAX_FAILED_ATTEMPTS:
        record["lock_until"] = now + LOCKOUT_TIME_SECONDS
        FAILED_ATTEMPTS[key] = record
        return record["count"], True, LOCKOUT_TIME_SECONDS

    FAILED_ATTEMPTS[key] = record
    return record["count"], False, 0


def reset_failed_attempts(key):
    """Resets failed attempt count upon successful login."""
    FAILED_ATTEMPTS.pop(key, None)


# ==========================================
# 3. JWT DECORATOR & HELPERS
# ==========================================

def generate_jwt_token(username):
    """Generates a signed JWT access token containing standard claims."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + JWT_EXPIRATION_DELTA
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def jwt_required(f):
    """Decorator to enforce valid JWT Token in HTTP Authorization Header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Unauthorized",
                "message": "Missing or invalid Authorization header. Expected format: 'Bearer <token>'"
            }), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            request.jwt_user = payload.get("sub")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Unauthorized", "message": "JWT token has expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Unauthorized", "message": "Invalid JWT token."}), 401

        return f(*args, **kwargs)
    return decorated


# ==========================================
# 4. HTML TEMPLATES FOR DEMO UI
# ==========================================

BASE_STYLE = """
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 650px; margin: 40px auto; text-align: center; background-color: #f8f9fa; color: #333; }
    input { padding: 10px; margin: 8px 0; width: 85%; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
    button { padding: 10px 20px; margin-top: 10px; cursor: pointer; border: none; border-radius: 6px; background-color: #0d6efd; color: white; font-weight: bold; }
    button:hover { background-color: #0b5ed7; }
    .btn-secondary { background-color: #6c757d; }
    .btn-secondary:hover { background-color: #5c636a; }
    .btn-danger { background-color: #dc3545; }
    .btn-danger:hover { background-color: #bb2d3b; }
    .error { color: #dc3545; font-weight: bold; background: #f8d7da; padding: 10px; border-radius: 6px; border: 1px solid #f5c2c7; }
    .warning { color: #856404; font-weight: bold; background: #fff3cd; padding: 10px; border-radius: 6px; border: 1px solid #ffeeba; }
    .success { color: #0f5132; background: #d1e7dd; padding: 10px; border-radius: 6px; border: 1px solid #badbcc; }
    .box { background: white; border: 1px solid #dee2e6; border-radius: 10px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 20px; text-align: left; }
    pre { background: #212529; color: #00ff66; padding: 12px; border-radius: 6px; text-align: left; overflow-x: auto; font-size: 13px; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; background: #6c757d; }
    .badge-jwt { background: #6f42c1; }
    .badge-session { background: #0d6efd; }
</style>
"""

HOME_PAGE = """
<!DOCTYPE html>
<html><head><title>Authentication & Security Demo</title>{{ style | safe }}</head>
<body>
<div class="box">
    <h2>🛡️ Authentication & Security Dashboard</h2>
    <hr>
    {% if username %}
        <div class="success">
            <h3>Logged in via Session Cookie!</h3>
            <p><strong>Username:</strong> {{ username }}</p>
            <p><strong>Cookie Properties:</strong> HttpOnly=True, SameSite=Lax</p>
        </div>
        <a href="{{ url_for('logout') }}"><button class="btn-danger">Log Out (Clear Session)</button></a>
    {% else %}
        <div class="warning">
            <p>You are currently <strong>Not Logged In</strong> via Web Session.</p>
        </div>
        <a href="{{ url_for('login') }}"><button>Web Session Login Page</button></a>
    {% endif %}
    
    <p><a href="{{ url_for('ping') }}" target="_blank">Healthcheck Endpoint (/ping)</a></p>
</div>

<div class="box">
    <h3>🔑 Interactive JWT Authentication Test</h3>
    <p>Test JWT token login & authorization directly from client-side JS API calls:</p>
    <div>
        <input type="text" id="jwt_user" value="admin" placeholder="Username"><br>
        <input type="password" id="jwt_pass" value="123456" placeholder="Password"><br>
        <button onclick="testJwtLogin()" class="btn-secondary">1. POST /api/login (Get JWT)</button>
        <button onclick="testJwtProtected()" class="btn-secondary">2. GET /api/protected (Use JWT)</button>
    </div>
    <h4>API Response Output:</h4>
    <pre id="jwt_output">// Click a button above to test JWT API...</pre>
</div>

<script>
let currentJwtToken = "";

async function testJwtLogin() {
    const u = document.getElementById("jwt_user").value;
    const p = document.getElementById("jwt_pass").value;
    const out = document.getElementById("jwt_output");
    out.textContent = "Requesting /api/login...";
    
    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();
        out.textContent = `HTTP ${res.status}\n` + JSON.stringify(data, null, 2);
        if (res.ok && data.access_token) {
            currentJwtToken = data.access_token;
        }
    } catch (err) {
        out.textContent = "Error: " + err;
    }
}

async function testJwtProtected() {
    const out = document.getElementById("jwt_output");
    if (!currentJwtToken) {
        out.textContent = "⚠️ Please obtain a JWT token first using Step 1 (POST /api/login)!";
        return;
    }
    out.textContent = "Requesting /api/protected with Bearer Token...";
    
    try {
        const res = await fetch("/api/protected", {
            method: "GET",
            headers: { 
                "Authorization": "Bearer " + currentJwtToken,
                "Content-Type": "application/json" 
            }
        });
        const data = await res.json();
        out.textContent = `HTTP ${res.status}\n` + JSON.stringify(data, null, 2);
    } catch (err) {
        out.textContent = "Error: " + err;
    }
}
</script>
</body></html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html><head><title>Web Session Login</title>{{ style | safe }}</head>
<body>
<div class="box" style="text-align:center;">
    <h2>🔐 Session Cookie Login</h2>
    
    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}
    
    <form method="POST" action="{{ url_for('login') }}">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit">Log In</button>
    </form>
    
    <p style="margin-top: 20px;"><a href="{{ url_for('home') }}">← Back to Dashboard</a></p>
</div>
</body></html>
"""


# ==========================================
# 5. ROUTES & ENDPOINTS
# ==========================================

@app.route("/ping")
def ping():
    """Health check endpoint."""
    return jsonify({"status": "ok", "message": "pong"})


@app.route("/")
def home():
    """Main dashboard displaying session state and JWT interactive demo."""
    return render_template_string(
        HOME_PAGE, style=BASE_STYLE, username=session.get("username")
    )


# --- 5.1 SESSION AUTHENTICATION ROUTES ---

@app.route("/login", methods=["GET", "POST"])
def login():
    """Cookie-based Session Login with Brute-Force Rate Limiting & Lockout."""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        identifier = get_client_identifier(username)

        # 1. Check Brute-Force Lockout Status
        is_locked, remaining_seconds = check_brute_force_lockout(identifier)
        if is_locked:
            error = f"⛔ Account/IP locked due to too many failed login attempts. Please try again in {remaining_seconds} seconds."
            return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error), 429

        # 2. Verify Credentials
        if username in USERS and USERS[username] == password:
            # Login successful: reset failed attempt counter
            reset_failed_attempts(identifier)

            # Establish Session
            session.permanent = True
            session["username"] = username
            return redirect(url_for("home"))
        else:
            # Login failed: record attempt
            attempts, is_now_locked, lock_seconds = record_failed_attempt(identifier)
            if is_now_locked:
                error = f"⛔ Too many failed attempts ({attempts}/{MAX_FAILED_ATTEMPTS}). Your account/IP is locked for {lock_seconds // 60} minutes."
                return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error), 429
            else:
                remaining_tries = MAX_FAILED_ATTEMPTS - attempts
                error = f"Invalid username or password! ({attempts}/{MAX_FAILED_ATTEMPTS} failed attempts. {remaining_tries} tries left before lockout)."

    return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error)


@app.route("/logout")
def logout():
    """Clears web session cookie."""
    session.pop("username", None)
    return redirect(url_for("home"))


# --- 5.2 JWT AUTHENTICATION API ROUTES ---

@app.route("/api/login", methods=["POST"])
def api_login():
    """
    JSON API Login Endpoint for JWT authentication.
    Accepts JSON: { "username": "...", "password": "..." }
    Enforces Brute-Force Rate Limiting.
    Returns: JSON containing JWT access token.
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "Bad Request", "message": "Username and password are required."}), 400

    identifier = get_client_identifier(username)

    # 1. Check Brute-Force Lockout Status
    is_locked, remaining_seconds = check_brute_force_lockout(identifier)
    if is_locked:
        return jsonify({
            "error": "Too Many Requests",
            "message": f"Account or IP is locked due to brute force protection. Try again in {remaining_seconds} seconds.",
            "retry_after_seconds": remaining_seconds
        }), 429

    # 2. Verify Credentials
    if username in USERS and USERS[username] == password:
        reset_failed_attempts(identifier)
        token = generate_jwt_token(username)
        return jsonify({
            "status": "success",
            "message": "Authentication successful",
            "access_token": token,
            "token_type": "Bearer",
            "expires_in_seconds": int(JWT_EXPIRATION_DELTA.total_seconds())
        }), 200
    else:
        attempts, is_now_locked, lock_seconds = record_failed_attempt(identifier)
        if is_now_locked:
            return jsonify({
                "error": "Too Many Requests",
                "message": f"Too many failed attempts ({attempts}/{MAX_FAILED_ATTEMPTS}). Account locked for {lock_seconds} seconds.",
                "retry_after_seconds": lock_seconds
            }), 429
        else:
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid username or password.",
                "failed_attempts": attempts,
                "remaining_attempts": MAX_FAILED_ATTEMPTS - attempts
            }), 401


@app.route("/api/protected", methods=["GET"])
@jwt_required
def api_protected():
    """
    Protected REST API Endpoint requiring JWT Authentication.
    Header required: Authorization: Bearer <token>
    """
    return jsonify({
        "status": "success",
        "message": f"Welcome to the protected API endpoint, {request.jwt_user}!",
        "authenticated_user": request.jwt_user,
        "server_timestamp": time.time()
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
