"""
Python Web Application (Flask) demonstrating Security & Rate Limiting Mechanisms:
1. Explicit Login Flow (Username 404, Lockout 429, Password 401/200)
2. Account-based Brute Force Lockout (Prevents IP rotation / spraying attacks)
3. Password Complexity Enforcement (Min 8 chars, UPPER/lower/number/special, no username, no DOB)
4. Session & JWT Authentication
5. Rate Limiting via Leaky Bucket Algorithm (Capacity & Leak Rate)
6. Dynamic CAPTCHA Verification System (Arithmetic Challenges)
7. Exponential Backoff Cooldown (Delay doubles after failed attempts: 2s, 4s, 8s, 16s...)
8. UI UX Blocking (Form & Submit button disabled with live visual countdown timer)
"""

import time
import datetime
import re
import random
import uuid
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
USERS = {
    "admin": "Admin@2026!",
    "user": "User@2026!"
}

# Brute Force Protection Configuration
MAX_FAILED_ATTEMPTS = 5       # Threshold: 5 failed attempts before account lockout
LOCKOUT_TIME_SECONDS = 300     # Lockout duration: 5 minutes (300 seconds)
CAPTCHA_REQUIRE_THRESHOLD = 2  # Require CAPTCHA after 2 failed attempts

# Tracking storage for failed attempts, lockout, and backoff timestamps
# Format: { "username": {"count": int, "lock_until": float, "last_failed": float} }
FAILED_ATTEMPTS = {}

# In-memory storage for active CAPTCHAs
# Format: { "captcha_id": {"answer": str, "expires_at": float} }
CAPTCHA_STORE = {}


# ==========================================
# 2. LEAKY BUCKET RATE LIMITER CLASS
# ==========================================

class LeakyBucketRateLimiter:
    """
    Leaky Bucket Algorithm for Rate Limiting:
    - Capacity: Maximum water (request tokens) the bucket can hold.
    - Leak Rate: Units leaked per second (drains continuously).
    - If incoming request water + current water > capacity, bucket overflows -> 429 Too Many Requests.
    """
    def __init__(self, capacity=5.0, leak_rate=0.5):
        self.capacity = float(capacity)
        self.leak_rate = float(leak_rate)  # 0.5 units/sec = 1 leak every 2 seconds
        self.buckets = {}  # key -> {"water": float, "last_leak": float}

    def add_request(self, key, cost=1.0):
        now = time.time()
        bucket = self.buckets.get(key, {"water": 0.0, "last_leak": now})
        
        # Calculate water leaked since last interaction
        elapsed = now - bucket["last_leak"]
        leaked = elapsed * self.leak_rate
        bucket["water"] = max(0.0, bucket["water"] - leaked)
        bucket["last_leak"] = now
        
        if bucket["water"] + cost <= self.capacity:
            bucket["water"] += cost
            self.buckets[key] = bucket
            remaining_capacity = self.capacity - bucket["water"]
            return {
                "allowed": True,
                "current_water": round(bucket["water"], 2),
                "remaining_capacity": round(remaining_capacity, 2),
                "capacity": self.capacity,
                "leak_rate": self.leak_rate,
                "wait_seconds": 0.0
            }
        else:
            needed_leak = (bucket["water"] + cost) - self.capacity
            wait_seconds = round(needed_leak / self.leak_rate, 2)
            self.buckets[key] = bucket
            return {
                "allowed": False,
                "current_water": round(bucket["water"], 2),
                "remaining_capacity": 0.0,
                "capacity": self.capacity,
                "leak_rate": self.leak_rate,
                "wait_seconds": max(wait_seconds, 1.0)
            }

    def get_status(self, key):
        now = time.time()
        bucket = self.buckets.get(key, {"water": 0.0, "last_leak": now})
        elapsed = now - bucket["last_leak"]
        leaked = elapsed * self.leak_rate
        current_water = max(0.0, bucket["water"] - leaked)
        return {
            "current_water": round(current_water, 2),
            "capacity": self.capacity,
            "leak_rate": self.leak_rate,
            "remaining_capacity": round(self.capacity - current_water, 2)
        }

# Global Leaky Bucket Instance: Capacity = 5 requests, Leak Rate = 0.5 requests/sec (1 leak per 2s)
GLOBAL_LEAKY_BUCKET = LeakyBucketRateLimiter(capacity=5.0, leak_rate=0.5)


# ==========================================
# 3. EXPONENTIAL BACKOFF & CAPTCHA HELPERS
# ==========================================

def get_exponential_backoff_delay(failed_count, base=2, max_delay=64):
    """
    Calculates exponential backoff delay in seconds:
    - 1st fail: 2^1 = 2 seconds
    - 2nd fail: 2^2 = 4 seconds
    - 3rd fail: 2^3 = 8 seconds
    - 4th fail: 2^4 = 16 seconds
    - Capped at max_delay (64s)
    """
    if failed_count <= 0:
        return 0
    delay = base ** failed_count
    return min(delay, max_delay)


def check_exponential_backoff_cooldown(key):
    """
    Checks if account/IP is currently in an exponential backoff cooldown period.
    Returns (is_in_cooldown: bool, seconds_remaining: int)
    """
    record = FAILED_ATTEMPTS.get(key)
    if not record or record.get("count", 0) == 0:
        return False, 0

    count = record.get("count", 0)
    last_failed = record.get("last_failed", 0)
    backoff_delay = get_exponential_backoff_delay(count)
    
    now = time.time()
    cooldown_until = last_failed + backoff_delay
    if now < cooldown_until:
        return True, int(cooldown_until - now)
    
    return False, 0


def generate_captcha_challenge():
    """Generates a random arithmetic CAPTCHA challenge valid for 3 minutes."""
    op = random.choice(["+", "-", "*"])
    if op == "+":
        n1, n2 = random.randint(1, 20), random.randint(1, 20)
        ans = n1 + n2
    elif op == "-":
        n1 = random.randint(10, 30)
        n2 = random.randint(1, n1)
        ans = n1 - n2
    else:
        n1, n2 = random.randint(2, 9), random.randint(2, 9)
        ans = n1 * n2

    captcha_id = str(uuid.uuid4())
    question = f"{n1} {op} {n2} = ?"
    expires_at = time.time() + 180

    CAPTCHA_STORE[captcha_id] = {
        "answer": str(ans),
        "expires_at": expires_at
    }

    # Clean expired captchas
    now = time.time()
    expired = [k for k, v in CAPTCHA_STORE.items() if v["expires_at"] < now]
    for k in expired:
        CAPTCHA_STORE.pop(k, None)

    return captcha_id, question


def verify_captcha_answer(captcha_id, user_answer):
    """Verifies user answer for a given captcha_id. Single-use only."""
    if not captcha_id or not user_answer:
        return False, "CAPTCHA ID and answer are required."

    record = CAPTCHA_STORE.pop(captcha_id, None)
    if not record:
        return False, "CAPTCHA expired or invalid. Please generate a new CAPTCHA."

    if time.time() > record["expires_at"]:
        return False, "CAPTCHA has expired. Please try again."

    if str(user_answer).strip() == record["answer"]:
        return True, "CAPTCHA verified successfully."
    else:
        return False, "Incorrect CAPTCHA answer."


# ==========================================
# 4. BRUTE FORCE & PASSWORD HELPERS
# ==========================================

def get_account_identifier(username=""):
    return username.strip().lower()


def check_brute_force_lockout(key):
    """Checks account lockout status (5 failed attempts -> 5 min lock)."""
    record = FAILED_ATTEMPTS.get(key)
    if not record:
        return False, 0

    now = time.time()
    lock_until = record.get("lock_until", 0)

    if lock_until > now:
        return True, int(lock_until - now)

    if lock_until > 0 and lock_until <= now:
        FAILED_ATTEMPTS.pop(key, None)

    return False, 0


def record_failed_attempt(key):
    """Increments failed attempt count and calculates backoff & lockout."""
    now = time.time()
    record = FAILED_ATTEMPTS.get(key, {"count": 0, "lock_until": 0, "last_failed": 0})

    record["count"] += 1
    record["last_failed"] = now

    if record["count"] >= MAX_FAILED_ATTEMPTS:
        record["lock_until"] = now + LOCKOUT_TIME_SECONDS
        FAILED_ATTEMPTS[key] = record
        return record["count"], True, LOCKOUT_TIME_SECONDS, get_exponential_backoff_delay(record["count"])

    FAILED_ATTEMPTS[key] = record
    return record["count"], False, 0, get_exponential_backoff_delay(record["count"])


def reset_failed_attempts(key):
    FAILED_ATTEMPTS.pop(key, None)


def validate_password_complexity(password, username="", dob=None):
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

    found_years = re.findall(r"(19[5-9]\d|20[0-2]\d)", password)
    if found_years and dob:
        errors.append(f"Password contains a suspected birth year ({', '.join(found_years)}).")

    return (len(errors) == 0, errors)


# ==========================================
# 5. JWT DECORATOR & HELPERS
# ==========================================

def generate_jwt_token(username):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + JWT_EXPIRATION_DELTA
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def jwt_required(f):
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
# 6. HTML TEMPLATES WITH UI BLOCKING & UX
# ==========================================

BASE_STYLE = """
<style>
    :root {
        --primary: #0d6efd;
        --danger: #dc3545;
        --warning: #ffc107;
        --success: #198754;
        --dark: #212529;
    }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 800px; margin: 30px auto; background-color: #f4f6f9; color: #333; padding: 0 15px; }
    input, button, select { font-family: inherit; font-size: 14px; }
    input[type="text"], input[type="password"] { padding: 10px 14px; margin: 8px 0; width: 100%; border: 1.5px solid #ced4da; border-radius: 6px; box-sizing: border-box; transition: border-color 0.2s, box-shadow 0.2s; }
    input:focus { border-color: #86b7fe; outline: 0; box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
    button { padding: 10px 20px; margin-top: 8px; cursor: pointer; border: none; border-radius: 6px; background-color: var(--primary); color: white; font-weight: 600; transition: background-color 0.2s, opacity 0.2s; }
    button:hover:not(:disabled) { background-color: #0b5ed7; }
    button:disabled { background-color: #6c757d !important; opacity: 0.65; cursor: not-allowed !important; }
    .btn-secondary { background-color: #6c757d; }
    .btn-secondary:hover:not(:disabled) { background-color: #5c636a; }
    .btn-danger { background-color: var(--danger); }
    .btn-danger:hover:not(:disabled) { background-color: #bb2d3b; }
    .btn-warning { background-color: #fd7e14; color: white; }
    .btn-warning:hover:not(:disabled) { background-color: #e8590c; }
    
    .error { color: #842029; font-weight: bold; background: #f8d7da; padding: 12px 16px; border-radius: 8px; border: 1px solid #f5c2c7; margin-bottom: 12px; }
    .warning { color: #664d03; font-weight: bold; background: #fff3cd; padding: 12px 16px; border-radius: 8px; border: 1px solid #ffeeba; margin-bottom: 12px; }
    .success { color: #0f5132; background: #d1e7dd; padding: 12px 16px; border-radius: 8px; border: 1px solid #badbcc; margin-bottom: 12px; }
    
    .box { background: white; border: 1px solid #dee2e6; border-radius: 12px; padding: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); margin-bottom: 24px; text-align: left; }
    pre { background: #212529; color: #00ff66; padding: 14px; border-radius: 8px; text-align: left; overflow-x: auto; font-size: 13px; line-height: 1.4; }
    ul { margin: 5px 0; padding-left: 20px; }
    
    /* UX Countdown & Lock Banner */
    .ux-lock-banner { background: #fff3cd; border: 2px dashed #ffc107; border-radius: 8px; padding: 12px 16px; margin: 12px 0; color: #664d03; font-weight: bold; display: flex; align-items: center; justify-content: space-between; }
    .ux-lock-banner.active { background: #f8d7da; border-color: #dc3545; color: #842029; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.85; } 100% { opacity: 1; } }
    
    /* Leaky Bucket Visualizer */
    .bucket-container { background: #e9ecef; border-radius: 10px; padding: 16px; margin-top: 12px; }
    .bucket-bar-bg { width: 100%; height: 28px; background-color: #ced4da; border-radius: 14px; overflow: hidden; position: relative; }
    .bucket-bar-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #0d6efd, #0dcaf0); transition: width 0.3s ease; }
    .bucket-bar-text { position: absolute; width: 100%; text-align: center; top: 0; line-height: 28px; font-weight: bold; color: #212529; font-size: 13px; text-shadow: 0 0 2px rgba(255,255,255,0.8); }
    
    /* CAPTCHA Widget */
    .captcha-box { background: #eef2f7; border: 1.5px solid #b6c4d0; border-radius: 8px; padding: 14px; margin: 12px 0; }
    .captcha-badge { background: #495057; color: white; padding: 6px 12px; border-radius: 6px; font-family: monospace; font-size: 18px; letter-spacing: 2px; display: inline-block; margin-right: 10px; }
</style>
"""

HOME_PAGE = """
<!DOCTYPE html>
<html><head><title>Security & Rate Limiting Dashboard</title>{{ style | safe }}</head>
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
        <a href="{{ url_for('login') }}"><button>Web Session Login Page (With Rate Limit & CAPTCHA)</button></a>
    {% endif %}
</div>

<div class="box">
    <h3>📋 Security Specifications & Active Mechanisms</h3>
    <ul>
        <li><strong>Account Lockout:</strong> Tracks failed login attempts by <code>username</code> (Max: 5 attempts, 5 min lock).</li>
        <li><strong>Rate Limit (Leaky Bucket):</strong> Bucket Capacity = 5 tokens, Leak Rate = 0.5/sec (1 leak per 2s). Prevents request flooding.</li>
        <li><strong>Exponential Backoff:</strong> Delay doubles after each failed attempt ($2^n$ seconds: 2s, 4s, 8s, 16s... max 64s).</li>
        <li><strong>Dynamic CAPTCHA:</strong> Required after 2 failed attempts or on high-frequency requests.</li>
        <li><strong>UI UX Blocking:</strong> Submit buttons automatically lock & display live countdown timers during backoff/lockout.</li>
    </ul>
    <p><em>Demo Accounts:</em> <code>admin / Admin@2026!</code>, <code>user / User@2026!</code></p>
</div>

<!-- LEAKY BUCKET LIVE DEMO WIDGET -->
<div class="box">
    <h3>🪣 1. Rate Limit Simulation (Leaky Bucket Algorithm)</h3>
    <p>Capacity: <strong>5.0 tokens</strong> | Leak Rate: <strong>0.5 tokens/sec (1 request leaks every 2s)</strong></p>
    
    <div class="bucket-container">
        <div class="bucket-bar-bg">
            <div id="bucket_fill" class="bucket-bar-fill"></div>
            <div id="bucket_text" class="bucket-bar-text">Water Level: 0 / 5.0 (0%)</div>
        </div>
    </div>
    
    <div style="margin-top: 15px;">
        <button onclick="pourWater()" id="btn_pour">🚰 Send Request (Pour +1 Water)</button>
        <button onclick="pourBurst()" class="btn-warning" id="btn_burst">⚡ Burst 6 Rapid Requests (Test Overflow)</button>
        <button onclick="fetchBucketStatus()" class="btn-secondary">🔄 Refresh Status</button>
    </div>
    <pre id="bucket_output">// Click "Send Request" to test Leaky Bucket rate limiting...</pre>
</div>

<!-- API LOGIN WITH BACKOFF & CAPTCHA -->
<div class="box">
    <h3>🔑 2. Test API Login Flow (POST /api/login)</h3>
    <p>Supports Exponential Backoff countdown & CAPTCHA verification.</p>
    
    <div id="api_ux_banner" class="ux-lock-banner" style="display:none;">
        <span id="api_ux_msg">⏳ Cooldown active...</span>
        <span id="api_ux_timer">0s</span>
    </div>
    
    <input type="text" id="jwt_user" value="admin" placeholder="Username"><br>
    <input type="password" id="jwt_pass" value="wrong_pass" placeholder="Password"><br>
    
    <!-- Dynamic CAPTCHA Container -->
    <div id="api_captcha_container" class="captcha-box" style="display:none;">
        <label>🤖 <strong>CAPTCHA Verification Required:</strong></label><br>
        <span id="api_captcha_question" class="captcha-badge">? + ? = ?</span>
        <button type="button" onclick="loadApiCaptcha()" class="btn-secondary" style="padding: 4px 10px; font-size:12px;">Refresh</button>
        <input type="hidden" id="api_captcha_id">
        <input type="text" id="api_captcha_answer" placeholder="Enter answer here..." style="margin-top:8px;"><br>
    </div>
    
    <button onclick="testApiLogin()" id="btn_api_login">POST /api/login</button>
    <button onclick="testJwtProtected()" class="btn-secondary">GET /api/protected</button>
    <pre id="api_output">// Output logs will appear here...</pre>
</div>

<!-- PASSWORD COMPLEXITY CHECKER -->
<div class="box">
    <h3>🔒 3. Password Complexity Checker (POST /api/validate-password)</h3>
    <input type="text" id="val_user" value="admin" placeholder="Username"><br>
    <input type="password" id="val_pass" value="123456" placeholder="Password to test"><br>
    <input type="text" id="val_dob" value="1998-10-25" placeholder="Date of birth (YYYY-MM-DD)"><br>
    <button onclick="testPasswordVal()">Validate Password Complexity</button>
    <pre id="val_output">// Click button above to check password requirements...</pre>
</div>

<script>
let currentJwtToken = "";
let apiCooldownTimer = null;

// --- LEAKY BUCKET WIDGET LOGIC ---
async function fetchBucketStatus() {
    try {
        const res = await fetch("/api/leaky-bucket/status");
        const data = await res.json();
        updateBucketUI(data.current_water, data.capacity);
    } catch (err) { console.error(err); }
}

function updateBucketUI(water, capacity) {
    const pct = Math.min(100, Math.max(0, (water / capacity) * 100));
    const fillEl = document.getElementById("bucket_fill");
    const textEl = document.getElementById("bucket_text");
    
    fillEl.style.width = pct + "%";
    textEl.textContent = `Water Level: ${water.toFixed(1)} / ${capacity} (${pct.toFixed(0)}%)`;
    
    if (pct > 80) fillEl.style.background = "linear-gradient(90deg, #fd7e14, #dc3545)";
    else fillEl.style.background = "linear-gradient(90deg, #0d6efd, #0dcaf0)";
}

async function pourWater() {
    const out = document.getElementById("bucket_output");
    try {
        const res = await fetch("/api/leaky-bucket/request", { method: "POST" });
        const data = await res.json();
        updateBucketUI(data.current_water, data.capacity);
        out.textContent = `HTTP ${res.status}: ` + JSON.stringify(data, null, 2);
    } catch (err) { out.textContent = "Error: " + err; }
}

async function pourBurst() {
    const out = document.getElementById("bucket_output");
    out.textContent = "Sending burst of 6 rapid requests...";
    for (let i = 1; i <= 6; i++) {
        await pourWater();
        await new Promise(r => setTimeout(r, 100));
    }
}

// Auto poll bucket status every 2 seconds to reflect continuous leakage
setInterval(fetchBucketStatus, 2000);
fetchBucketStatus();


// --- CAPTCHA & BACKOFF API LOGIC ---
async function loadApiCaptcha() {
    try {
        const res = await fetch("/api/captcha/new");
        const data = await res.json();
        document.getElementById("api_captcha_id").value = data.captcha_id;
        document.getElementById("api_captcha_question").textContent = data.captcha_question;
        document.getElementById("api_captcha_container").style.display = "block";
    } catch (err) { console.error(err); }
}

function triggerUiLockout(seconds, message) {
    const btn = document.getElementById("btn_api_login");
    const banner = document.getElementById("api_ux_banner");
    const msgEl = document.getElementById("api_ux_msg");
    const timerEl = document.getElementById("api_ux_timer");
    
    btn.disabled = true;
    banner.style.display = "flex";
    banner.classList.add("active");
    msgEl.textContent = message || "⏳ UI Locked (Exponential Backoff active):";
    
    let remaining = seconds;
    timerEl.textContent = remaining + "s";
    
    if (apiCooldownTimer) clearInterval(apiCooldownTimer);
    
    apiCooldownTimer = setInterval(() => {
        remaining--;
        if (remaining <= 0) {
            clearInterval(apiCooldownTimer);
            btn.disabled = false;
            banner.style.display = "none";
            banner.classList.remove("active");
        } else {
            timerEl.textContent = remaining + "s";
        }
    }, 1000);
}

async function testApiLogin() {
    const u = document.getElementById("jwt_user").value;
    const p = document.getElementById("jwt_pass").value;
    const captchaId = document.getElementById("api_captcha_id").value;
    const captchaAns = document.getElementById("api_captcha_answer").value;
    const out = document.getElementById("api_output");
    
    out.textContent = "Sending request to /api/login...";
    
    const payload = { username: u, password: p };
    if (captchaId) {
        payload.captcha_id = captchaId;
        payload.captcha_answer = captchaAns;
    }

    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        out.textContent = `HTTP Status: ${res.status}\n` + JSON.stringify(data, null, 2);
        
        if (res.ok && data.access_token) {
            currentJwtToken = data.access_token;
            document.getElementById("api_captcha_container").style.display = "none";
        }

        // Handle CAPTCHA Requirement
        if (data.captcha_required) {
            document.getElementById("api_captcha_id").value = data.captcha_id;
            document.getElementById("api_captcha_question").textContent = data.captcha_question;
            document.getElementById("api_captcha_container").style.display = "block";
        }

        // Handle Exponential Backoff or Rate Limit UI Lockout
        if (data.backoff_seconds && data.backoff_seconds > 0) {
            triggerUiLockout(data.backoff_seconds, "⏳ Backoff Delay Active (UI Disabled):");
        } else if (data.retry_after_seconds && data.retry_after_seconds > 0) {
            triggerUiLockout(data.retry_after_seconds, "⛔ Account Locked (UI Disabled):");
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
<div class="box" style="max-width: 450px; margin: 40px auto;">
    <h2 style="text-align:center;">🔐 Web Session Login</h2>
    <p style="font-size:13px; color:#666; text-align:center;">Includes Rate Limiting, Exponential Backoff, CAPTCHA, & UI Blocking</p>
    <hr>
    
    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}
    
    <div id="ux_lock_banner" class="ux-lock-banner" style="{% if not lock_seconds %}display:none;{% endif %}">
        <span id="ux_msg">⏳ Cooldown / Lockout Active:</span>
        <span id="ux_timer">{{ lock_seconds or 0 }}s</span>
    </div>
    
    <form id="login_form" method="POST" action="{{ url_for('login') }}">
        <label>Username:</label>
        <input type="text" id="username_input" name="username" value="{{ last_username or '' }}" placeholder="Username" required><br>
        
        <label>Password:</label>
        <input type="password" id="password_input" name="password" placeholder="Password" required><br>
        
        {% if captcha_required %}
        <div class="captcha-box">
            <label>🤖 <strong>Solve CAPTCHA:</strong></label><br>
            <span class="captcha-badge">{{ captcha_question }}</span>
            <input type="hidden" name="captcha_id" value="{{ captcha_id }}">
            <input type="text" name="captcha_answer" placeholder="Enter answer..." required style="margin-top:8px;">
        </div>
        {% endif %}
        
        <button type="submit" id="submit_btn" style="width:100%; padding:12px; margin-top:12px;">Log In</button>
    </form>
    
    <p style="margin-top: 20px; text-align:center;"><a href="{{ url_for('home') }}">← Back to Dashboard</a></p>
</div>

<script>
let lockSeconds = {{ lock_seconds or 0 }};
if (lockSeconds > 0) {
    const btn = document.getElementById("submit_btn");
    const uInput = document.getElementById("username_input");
    const pInput = document.getElementById("password_input");
    const banner = document.getElementById("ux_lock_banner");
    const timerEl = document.getElementById("ux_timer");
    
    // UI Blocking: Disable submit button and inputs
    btn.disabled = true;
    uInput.disabled = true;
    pInput.disabled = true;
    
    let remaining = lockSeconds;
    const timer = setInterval(() => {
        remaining--;
        if (remaining <= 0) {
            clearInterval(timer);
            btn.disabled = false;
            uInput.disabled = false;
            pInput.disabled = false;
            banner.style.display = "none";
            btn.textContent = "Log In";
        } else {
            timerEl.textContent = remaining + "s";
            btn.textContent = `Locked (${remaining}s)`;
        }
    }, 1000);
}
</script>
</body></html>
"""


# ==========================================
# 7. ROUTES & ENDPOINTS
# ==========================================

@app.route("/ping")
def ping():
    return jsonify({"status": "ok", "message": "pong"})


@app.route("/")
def home():
    return render_template_string(
        HOME_PAGE, style=BASE_STYLE, username=session.get("username")
    )


# --- 7.1 LEAKY BUCKET DEMO ENDPOINTS ---

@app.route("/api/leaky-bucket/status", methods=["GET"])
def leaky_bucket_status():
    client_ip = request.remote_addr or "127.0.0.1"
    status = GLOBAL_LEAKY_BUCKET.get_status(client_ip)
    return jsonify(status), 200


@app.route("/api/leaky-bucket/request", methods=["POST"])
def leaky_bucket_request():
    client_ip = request.remote_addr or "127.0.0.1"
    result = GLOBAL_LEAKY_BUCKET.add_request(client_ip, cost=1.0)
    
    if result["allowed"]:
        return jsonify({
            "status": "success",
            "message": "Request processed through Leaky Bucket.",
            **result
        }), 200
    else:
        return jsonify({
            "error": "Too Many Requests",
            "message": f"Leaky Bucket capacity overflowed! Please wait {result['wait_seconds']} seconds for water to leak.",
            "retry_after_seconds": result["wait_seconds"],
            **result
        }), 429


# --- 7.2 CAPTCHA ENDPOINTS ---

@app.route("/api/captcha/new", methods=["GET"])
def get_new_captcha():
    captcha_id, question = generate_captcha_challenge()
    return jsonify({
        "status": "success",
        "captcha_id": captcha_id,
        "captcha_question": question
    }), 200


# --- 7.3 SESSION LOGIN ROUTE ---

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Session Login with explicit 404/429/401/200 status codes,
    Leaky Bucket Rate Limiting, Exponential Backoff, and CAPTCHA.
    """
    error = None
    captcha_required = False
    captcha_id = None
    captcha_question = None
    lock_seconds = 0
    client_ip = request.remote_addr or "127.0.0.1"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user_captcha_id = request.form.get("captcha_id")
        user_captcha_ans = request.form.get("captcha_answer")

        identifier = get_account_identifier(username)

        # Step 0: Check Leaky Bucket Rate Limiting
        lb_res = GLOBAL_LEAKY_BUCKET.add_request(client_ip)
        if not lb_res["allowed"]:
            error = f"⛔ 429 Too Many Requests: Rate limit exceeded (Leaky Bucket). Wait {lb_res['wait_seconds']}s."
            return render_template_string(
                LOGIN_PAGE, style=BASE_STYLE, error=error, lock_seconds=lb_res["wait_seconds"], last_username=username
            ), 429

        # Step 1: Check Username Existence (404 Not Found)
        if username not in USERS:
            error = f"❌ 404 Not Found: Username '{username}' does not exist!"
            return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error), 404

        # Step 2: Check Brute Force Lockout (429 Too Many Requests)
        is_locked, remaining_seconds = check_brute_force_lockout(identifier)
        if is_locked:
            error = f"⛔ 429 Too Many Requests: Account '{username}' is locked due to too many failed attempts ({MAX_FAILED_ATTEMPTS}). Try again in {remaining_seconds} seconds."
            return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error, lock_seconds=remaining_seconds, last_username=username), 429

        # Step 3: Check Exponential Backoff Cooldown
        in_backoff, backoff_remaining = check_exponential_backoff_cooldown(identifier)
        if in_backoff:
            error = f"⏳ Exponential Backoff Cooldown: Please wait {backoff_remaining} seconds before trying again."
            return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error, lock_seconds=backoff_remaining, last_username=username), 429

        # Step 4: Check CAPTCHA if required for this account
        record = FAILED_ATTEMPTS.get(identifier, {})
        fail_count = record.get("count", 0)
        
        if fail_count >= CAPTCHA_REQUIRE_THRESHOLD:
            if not user_captcha_id or not user_captcha_ans:
                captcha_id, captcha_question = generate_captcha_challenge()
                error = "🤖 Security Check: Please solve the CAPTCHA before submitting."
                return render_template_string(
                    LOGIN_PAGE, style=BASE_STYLE, error=error,
                    captcha_required=True, captcha_id=captcha_id, captcha_question=captcha_question,
                    last_username=username
                ), 400

            valid_captcha, captcha_msg = verify_captcha_answer(user_captcha_id, user_captcha_ans)
            if not valid_captcha:
                attempts, is_now_locked, lock_sec, backoff_sec = record_failed_attempt(identifier)
                captcha_id, captcha_question = generate_captcha_challenge()
                error = f"❌ CAPTCHA Error: {captcha_msg}"
                return render_template_string(
                    LOGIN_PAGE, style=BASE_STYLE, error=error,
                    captcha_required=True, captcha_id=captcha_id, captcha_question=captcha_question,
                    lock_seconds=backoff_sec, last_username=username
                ), 400

        # Step 5: Check Password Match using ==
        if USERS[username] == password:
            reset_failed_attempts(identifier)
            session.permanent = True
            session["username"] = username
            return redirect(url_for("home"))
        else:
            attempts, is_now_locked, lock_sec, backoff_sec = record_failed_attempt(identifier)
            if is_now_locked:
                error = f"⛔ 429 Too Many Requests: Failed password attempt ({attempts}/{MAX_FAILED_ATTEMPTS}). Account '{username}' is locked for {lock_sec} seconds."
                return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error, lock_seconds=lock_sec, last_username=username), 429
            else:
                remaining_tries = MAX_FAILED_ATTEMPTS - attempts
                error = f"❌ 401 Unauthorized: Incorrect password! ({attempts}/{MAX_FAILED_ATTEMPTS} failed attempts). Exponential Backoff: {backoff_sec}s delay enforced."
                
                # Check if CAPTCHA will be required for next attempt
                if attempts >= CAPTCHA_REQUIRE_THRESHOLD:
                    captcha_required = True
                    captcha_id, captcha_question = generate_captcha_challenge()

                return render_template_string(
                    LOGIN_PAGE, style=BASE_STYLE, error=error,
                    lock_seconds=backoff_sec, captcha_required=captcha_required,
                    captcha_id=captcha_id, captcha_question=captcha_question,
                    last_username=username
                ), 401

    return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))


# --- 7.4 JSON API AUTHENTICATION ROUTE ---

@app.route("/api/login", methods=["POST"])
def api_login():
    """
    JSON API Login Endpoint with Leaky Bucket, Backoff, Lockout & CAPTCHA:
    - Step 0: Check Leaky Bucket rate limit -> 429
    - Step 1: Check username existence -> 404
    - Step 2: Check account lockout status -> 429
    - Step 3: Check Exponential Backoff cooldown -> 429
    - Step 4: Check CAPTCHA (if required) -> 400
    - Step 5: Check password match -> 200 + JWT (or 401)
    """
    client_ip = request.remote_addr or "127.0.0.1"

    # Step 0: Check Leaky Bucket Rate Limiting
    lb_res = GLOBAL_LEAKY_BUCKET.add_request(client_ip)
    if not lb_res["allowed"]:
        return jsonify({
            "error": "Too Many Requests",
            "status_code": 429,
            "message": f"Rate limit exceeded (Leaky Bucket). Please wait {lb_res['wait_seconds']} seconds.",
            "retry_after_seconds": lb_res["wait_seconds"]
        }), 429

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    user_captcha_id = data.get("captcha_id")
    user_captcha_ans = data.get("captcha_answer")

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

    # Step 3: Check Exponential Backoff Cooldown
    in_backoff, backoff_remaining = check_exponential_backoff_cooldown(identifier)
    if in_backoff:
        return jsonify({
            "error": "Too Many Requests",
            "status_code": 429,
            "message": f"Exponential Backoff active. Please wait {backoff_remaining} seconds before retrying.",
            "backoff_seconds": backoff_remaining
        }), 429

    # Step 4: Check CAPTCHA if required
    record = FAILED_ATTEMPTS.get(identifier, {})
    fail_count = record.get("count", 0)

    if fail_count >= CAPTCHA_REQUIRE_THRESHOLD:
        if not user_captcha_id or not user_captcha_ans:
            c_id, c_quest = generate_captcha_challenge()
            return jsonify({
                "error": "Bad Request",
                "status_code": 400,
                "message": "CAPTCHA required due to multiple failed login attempts.",
                "captcha_required": True,
                "captcha_id": c_id,
                "captcha_question": c_quest
            }), 400

        valid_captcha, captcha_msg = verify_captcha_answer(user_captcha_id, user_captcha_ans)
        if not valid_captcha:
            attempts, is_now_locked, lock_sec, backoff_sec = record_failed_attempt(identifier)
            c_id, c_quest = generate_captcha_challenge()
            return jsonify({
                "error": "Bad Request",
                "status_code": 400,
                "message": f"CAPTCHA failed: {captcha_msg}",
                "captcha_required": True,
                "captcha_id": c_id,
                "captcha_question": c_quest,
                "backoff_seconds": backoff_sec
            }), 400

    # Step 5: Check Password Match using ==
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
        attempts, is_now_locked, lock_sec, backoff_sec = record_failed_attempt(identifier)
        c_id, c_quest = (None, None)
        captcha_req = attempts >= CAPTCHA_REQUIRE_THRESHOLD
        if captcha_req:
            c_id, c_quest = generate_captcha_challenge()

        if is_now_locked:
            return jsonify({
                "error": "Too Many Requests",
                "status_code": 429,
                "message": f"Incorrect password. Exceeded {MAX_FAILED_ATTEMPTS} failed attempts. Account '{username}' locked for {lock_sec} seconds.",
                "retry_after_seconds": lock_sec,
                "backoff_seconds": backoff_sec
            }), 429
        else:
            return jsonify({
                "error": "Unauthorized",
                "status_code": 401,
                "message": f"Incorrect password. ({attempts}/{MAX_FAILED_ATTEMPTS} failed attempts).",
                "failed_attempts": attempts,
                "remaining_attempts": MAX_FAILED_ATTEMPTS - attempts,
                "backoff_seconds": backoff_sec,
                "captcha_required": captcha_req,
                "captcha_id": c_id,
                "captcha_question": c_quest
            }), 401


@app.route("/api/validate-password", methods=["POST"])
def api_validate_password():
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
    return jsonify({
        "status": "success",
        "message": f"Welcome to the protected API endpoint, {request.jwt_user}!",
        "authenticated_user": request.jwt_user,
        "server_timestamp": time.time()
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
