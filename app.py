"""
Python Web Application (Flask) demonstrating:
1. Explicit Login Flow (Username 404, Lockout 429, Password 401/200)
2. Account-based Brute Force Lockout (Prevents IP rotation / spraying attacks)
3. Password Complexity Enforcement (Min 8 chars, UPPER/lower/number/special, no username, no DOB)
4. Session & JWT Authentication
"""

import time
import datetime
import re
from functools import wraps
# pyrefly: ignore [missing-import]
import jwt
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
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevents XSS script access
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Prevents CSRF attacks
app.config["SESSION_COOKIE_SECURE"] = False   # Set True in production with HTTPS

# Demo Accounts with compliant complex passwords
# Minimum 8 chars, uppercase, lowercase, number, special char, no username, no DOB
USERS = {
    "admin": "Admin@2026!",
    "user": "User@2026!"
}

# Brute Force Protection Configuration
MAX_FAILED_ATTEMPTS = 5       # Threshold: 5 failed attempts
LOCKOUT_TIME_SECONDS = 300     # Lockout duration: 5 minutes (300 seconds)

# Storage for tracking failed login attempts per USERNAME (Account Lockout)
# Format: { "username": {"count": int, "lock_until": float timestamp} }
FAILED_ATTEMPTS = {}


# ==========================================
# 2. SECURITY HELPERS & PASSWORD VALIDATION
# ==========================================

def get_account_identifier(username=""):
    """
    Returns the account identifier (username).
    Tracking failed login count per USERNAME (Account-level Lockout) prevents 
    IP Rotation / IP Spraying attacks from bypassing rate limits.
    """
    return username.strip().lower()


def check_brute_force_lockout(key):
    """
    Checks if an account (username key) is currently locked out.
    Returns (is_locked: bool, seconds_remaining: int)
    """
    record = FAILED_ATTEMPTS.get(key)
    if not record:
        return False, 0

    now = time.time()
    lock_until = record.get("lock_until", 0)

    if lock_until > now:
        return True, int(lock_until - now)
    
    # Reset record if lockout period has expired
    if lock_until > 0 and lock_until <= now:
        FAILED_ATTEMPTS.pop(key, None)

    return False, 0


def record_failed_attempt(key):
    """
    Increments failed attempt count for the account and locks if threshold reached.
    Returns (current_count: int, is_locked: bool, seconds_remaining: int)
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
    """Resets failed attempt counter upon successful authentication."""
    FAILED_ATTEMPTS.pop(key, None)


def validate_password_complexity(password, username="", dob=None):
    """
    Validates password complexity requirements:
    1. Minimum 8 characters
    2. Must contain uppercase letter (A-Z)
    3. Must contain lowercase letter (a-z)
    4. Must contain digit (0-9)
    5. Must contain special character (!@#$%^&*...)
    6. Must not match or contain username
    7. Must not contain date of birth (DOB) or common birth year formats
    
    Returns (is_valid: bool, errors: list[str])
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
        
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least 1 uppercase letter (A-Z).")
        
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least 1 lowercase letter (a-z).")
        
    if not re.search(r"\d", password):
        errors.append("Password must contain at least 1 digit (0-9).")
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+\=]", password):
        errors.append("Password must contain at least 1 special character (!@#$%^&*...).")
        
    if username and username.strip().lower() in password.lower():
        errors.append("Password must not match or contain the username.")
        
    if dob:
        clean_dob = re.sub(r"\D", "", dob)
        if clean_dob and len(clean_dob) >= 4 and clean_dob in password:
            errors.append("Password must not contain date of birth.")
            
    # Check for common birth year patterns (1950 - 2026)
    found_years = re.findall(r"(19[5-9]\d|20[0-2]\d)", password)
    if found_years and dob:
        errors.append(f"Password contains a suspected birth year ({', '.join(found_years)}).")

    return (len(errors) == 0, errors)


# ==========================================
# 3. JWT DECORATOR & HELPERS
# ==========================================

def generate_jwt_token(username):
    """Generates a signed JWT access token."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + JWT_EXPIRATION_DELTA
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def jwt_required(f):
    """Decorator to enforce valid JWT Token in Authorization Header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Unauthorized",
                "message": "Missing or invalid Authorization header. Format: 'Bearer <token>'"
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
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 700px; margin: 30px auto; text-align: center; background-color: #f4f6f9; color: #333; }
    input { padding: 10px; margin: 8px 0; width: 85%; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
    button { padding: 10px 20px; margin-top: 8px; cursor: pointer; border: none; border-radius: 6px; background-color: #0d6efd; color: white; font-weight: bold; }
    button:hover { background-color: #0b5ed7; }
    .btn-secondary { background-color: #6c757d; }
    .btn-secondary:hover { background-color: #5c636a; }
    .btn-danger { background-color: #dc3545; }
    .btn-danger:hover { background-color: #bb2d3b; }
    .error { color: #842029; font-weight: bold; background: #f8d7da; padding: 12px; border-radius: 6px; border: 1px solid #f5c2c7; text-align: left; }
    .warning { color: #664d03; font-weight: bold; background: #fff3cd; padding: 12px; border-radius: 6px; border: 1px solid #ffeeba; }
    .success { color: #0f5132; background: #d1e7dd; padding: 12px; border-radius: 6px; border: 1px solid #badbcc; }
    .box { background: white; border: 1px solid #dee2e6; border-radius: 10px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 20px; text-align: left; }
    pre { background: #212529; color: #00ff66; padding: 12px; border-radius: 6px; text-align: left; overflow-x: auto; font-size: 13px; }
    ul { margin: 5px 0; padding-left: 20px; }
</style>
"""

HOME_PAGE = """
<!DOCTYPE html>
<html><head><title>Authentication & Security Demo</title>{{ style | safe }}</head>
<body>
<div class="box">
    <h2>🛡️ Security & Authentication Dashboard</h2>
    <hr>
    {% if username %}
        <div class="success">
            <h3>Logged in via Session Cookie!</h3>
            <p><strong>Username:</strong> {{ username }}</p>
        </div>
        <a href="{{ url_for('logout') }}"><button class="btn-danger">Log Out</button></a>
    {% else %}
        <div class="warning">
            <p>You are currently <strong>Not Logged In</strong> via Web Session.</p>
        </div>
        <a href="{{ url_for('login') }}"><button>Web Session Login Page</button></a>
    {% endif %}
</div>

<div class="box">
    <h3>📋 Security Rules & Specifications</h3>
    <ul>
        <li><strong>Account Lockout:</strong> Tracks failed login attempts by <code>username</code> (Max: 5 attempts). Prevents IP rotation (IP spraying) attacks.</li>
        <li><strong>Explicit Response Flow:</strong>
            <ul>
                <li>Username check: Return <code>404 Not Found</code> if username does not exist.</li>
                <li>Lockout check: Return <code>429 Too Many Requests</code> if failed count >= 5.</li>
                <li>Password check (<code>==</code> operator): Return <code>200 OK</code> if match, <code>401 Unauthorized</code> if incorrect.</li>
            </ul>
        </li>
        <li><strong>Password Policy:</strong> Min 8 chars, UPPER, lower, number, special char, no username, no DOB.</li>
    </ul>
    <p><em>Demo Accounts:</em> <code>admin / Admin@2026!</code>, <code>user / User@2026!</code></p>
</div>

<div class="box">
    <h3>🔑 Test API Login & Lockout Flow (POST /api/login)</h3>
    <input type="text" id="jwt_user" value="admin" placeholder="Username"><br>
    <input type="password" id="jwt_pass" value="Admin@2026!" placeholder="Password"><br>
    <button onclick="testApiLogin()" class="btn-secondary">POST /api/login</button>
    <button onclick="testJwtProtected()" class="btn-secondary">GET /api/protected</button>
    <pre id="api_output">// Click POST /api/login to test API response...</pre>
</div>

<div class="box">
    <h3>🔒 Test Password Complexity Checker (POST /api/validate-password)</h3>
    <input type="text" id="val_user" value="admin" placeholder="Username"><br>
    <input type="password" id="val_pass" value="123456" placeholder="Password to test"><br>
    <input type="text" id="val_dob" value="1998-10-25" placeholder="Date of birth (YYYY-MM-DD)"><br>
    <button onclick="testPasswordVal()">Validate Password Complexity</button>
    <pre id="val_output">// Click button above to check password requirements...</pre>
</div>

<script>
let currentJwtToken = "";

async function testApiLogin() {
    const u = document.getElementById("jwt_user").value;
    const p = document.getElementById("jwt_pass").value;
    const out = document.getElementById("api_output");
    out.textContent = "Sending request to /api/login...";
    
    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();
        out.textContent = `HTTP Status: ${res.status}\n` + JSON.stringify(data, null, 2);
        if (res.ok && data.access_token) {
            currentJwtToken = data.access_token;
        }
    } catch (err) {
        out.textContent = "Error: " + err;
    }
}

async function testJwtProtected() {
    const out = document.getElementById("api_output");
    if (!currentJwtToken) {
        out.textContent = "⚠️ Obtain a JWT token first using POST /api/login!";
        return;
    }
    
    try {
        const res = await fetch("/api/protected", {
            method: "GET",
            headers: { 
                "Authorization": "Bearer " + currentJwtToken,
                "Content-Type": "application/json" 
            }
        });
        const data = await res.json();
        out.textContent = `HTTP Status: ${res.status}\n` + JSON.stringify(data, null, 2);
    } catch (err) {
        out.textContent = "Error: " + err;
    }
}

async function testPasswordVal() {
    const u = document.getElementById("val_user").value;
    const p = document.getElementById("val_pass").value;
    const dob = document.getElementById("val_dob").value;
    const out = document.getElementById("val_output");
    
    try {
        const res = await fetch("/api/validate-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: u, password: p, dob: dob })
        });
        const data = await res.json();
        out.textContent = `HTTP Status: ${res.status}\n` + JSON.stringify(data, null, 2);
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
    <h2>🔐 Web Session Login</h2>
    
    {% if error %}
        <div class="error">{{ error }}</div>
        <br>
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
    """Main dashboard displaying session state, rules, and interactive tests."""
    return render_template_string(
        HOME_PAGE, style=BASE_STYLE, username=session.get("username")
    )


# --- 5.1 SESSION AUTHENTICATION ROUTE ---

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Session Login with explicit 404/429/401/200 status codes.
    1. Check username existence -> 404 Not Found
    2. Check account brute force lockout -> 429 Too Many Requests
    3. Check password match via == -> 200 OK (or 401 Unauthorized)
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        identifier = get_account_identifier(username)

        # Step 1: Check Username Existence (404 Not Found)
        if username not in USERS:
            error = f"❌ 404 Not Found: Username '{username}' does not exist!"
            return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error), 404

        # Step 2: Check Brute Force Account Lockout (429 Too Many Requests)
        is_locked, remaining_seconds = check_brute_force_lockout(identifier)
        if is_locked:
            error = f"⛔ 429 Too Many Requests: Account '{username}' is locked due to too many failed attempts ({MAX_FAILED_ATTEMPTS}). Try again in {remaining_seconds} seconds."
            return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error), 429

        # Step 3: Check Password Match using ==
        if USERS[username] == password:
            # Match: Reset fail count & establish session
            reset_failed_attempts(identifier)
            session.permanent = True
            session["username"] = username
            return redirect(url_for("home"))
        else:
            # Mismatch: Increment fail count
            attempts, is_now_locked, lock_seconds = record_failed_attempt(identifier)
            if is_now_locked:
                error = f"⛔ 429 Too Many Requests: Failed password attempt ({attempts}/{MAX_FAILED_ATTEMPTS}). Account '{username}' is locked for {lock_seconds // 60} minutes."
                return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error), 429
            else:
                remaining_tries = MAX_FAILED_ATTEMPTS - attempts
                error = f"❌ 401 Unauthorized: Incorrect password! ({attempts}/{MAX_FAILED_ATTEMPTS} failed attempts. {remaining_tries} attempts remaining)."
                return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error), 401

    return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error)


@app.route("/logout")
def logout():
    """Clears web session cookie."""
    session.pop("username", None)
    return redirect(url_for("home"))


# --- 5.2 JSON API AUTHENTICATION ROUTES ---

@app.route("/api/login", methods=["POST"])
def api_login():
    """
    JSON API Login Endpoint with explicit, honest HTTP status codes:
    - Step 1: Check username existence -> 404 Not Found
    - Step 2: Check account brute force lockout -> 429 Too Many Requests
    - Step 3: Check password match via == -> 200 OK + JWT (or 401 Unauthorized)
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({
            "error": "Bad Request",
            "status_code": 400,
            "message": "Both username and password are required."
        }), 400

    identifier = get_account_identifier(username)

    # Step 1: Check Username Existence (404 Not Found)
    if username not in USERS:
        return jsonify({
            "error": "Not Found",
            "status_code": 404,
            "message": f"Username '{username}' does not exist."
        }), 404

    # Step 2: Check Account Lockout Status (429 Too Many Requests)
    is_locked, remaining_seconds = check_brute_force_lockout(identifier)
    if is_locked:
        return jsonify({
            "error": "Too Many Requests",
            "status_code": 429,
            "message": f"Account '{username}' is locked due to too many failed attempts ({MAX_FAILED_ATTEMPTS}). Try again in {remaining_seconds} seconds.",
            "retry_after_seconds": remaining_seconds
        }), 429

    # Step 3: Check Password Match using ==
    if USERS[username] == password:
        reset_failed_attempts(identifier)
        token = generate_jwt_token(username)
        return jsonify({
            "status": "success",
            "status_code": 200,
            "message": "Login successful!",
            "access_token": token,
            "token_type": "Bearer",
            "expires_in_seconds": int(JWT_EXPIRATION_DELTA.total_seconds())
        }), 200
    else:
        attempts, is_now_locked, lock_seconds = record_failed_attempt(identifier)
        if is_now_locked:
            return jsonify({
                "error": "Too Many Requests",
                "status_code": 429,
                "message": f"Incorrect password. You exceeded {MAX_FAILED_ATTEMPTS} failed attempts. Account '{username}' is locked for {lock_seconds} seconds.",
                "retry_after_seconds": lock_seconds
            }), 429
        else:
            return jsonify({
                "error": "Unauthorized",
                "status_code": 401,
                "message": "Incorrect password.",
                "failed_attempts": attempts,
                "remaining_attempts": MAX_FAILED_ATTEMPTS - attempts
            }), 401


@app.route("/api/validate-password", methods=["POST"])
def api_validate_password():
    """
    API Endpoint to test password complexity compliance.
    JSON: { "password": "...", "username": "...", "dob": "YYYY-MM-DD" }
    """
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    username = str(data.get("username", ""))
    dob = data.get("dob")

    is_valid, errors = validate_password_complexity(password, username, dob)

    if is_valid:
        return jsonify({
            "status": "success",
            "status_code": 200,
            "message": "Password is valid and meets all security requirements!"
        }), 200
    else:
        return jsonify({
            "status": "error",
            "status_code": 400,
            "message": "Password does not meet security requirements!",
            "errors": errors
        }), 400


@app.route("/api/protected", methods=["GET"])
@jwt_required
def api_protected():
    """Protected REST API Endpoint requiring JWT Authentication."""
    return jsonify({
        "status": "success",
        "message": f"Welcome to the protected API endpoint, {request.jwt_user}!",
        "authenticated_user": request.jwt_user,
        "server_timestamp": time.time()
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
