"""
Simple Python web app (Flask) with:
- /ping    : health check endpoint
- /login   : login form (GET) + login handling (POST)
- /        : home page, shows login status
- /logout  : log out

How to run:
    pip install flask
    python app.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, request, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # used to sign the session cookie

# Demo accounts (in a real app, store these in a database with hashed passwords)
USERS = {
    "admin": "123456",
    "user": "password"
}

BASE_STYLE = """
<style>
    body { font-family: Arial, sans-serif; max-width: 400px; margin: 60px auto; text-align: center; }
    input { padding: 8px; margin: 6px 0; width: 90%; }
    button { padding: 8px 20px; margin-top: 10px; cursor: pointer; }
    .error { color: red; }
    .success { color: green; }
    .box { border: 1px solid #ccc; border-radius: 8px; padding: 20px; }
</style>
"""

HOME_PAGE = """
<html><head><title>Home</title>{{ style }}</head>
<body>
<div class="box">
    {% if username %}
        <h2 class="success">Hello, {{ username }}! You are logged in.</h2>
        <a href="{{ url_for('logout') }}"><button>Log out</button></a>
    {% else %}
        <h2>You are not logged in.</h2>
        <a href="{{ url_for('login') }}"><button>Log in</button></a>
    {% endif %}
    <p><a href="{{ url_for('ping') }}">Check /ping</a></p>
</div>
</body></html>
"""

LOGIN_PAGE = """
<html><head><title>Login</title>{{ style }}</head>
<body>
<div class="box">
    <h2>Login</h2>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit">Log in</button>
    </form>
    <p><a href="{{ url_for('home') }}">Back to home</a></p>
</div>
</body></html>
"""


@app.route("/ping")
def ping():
    return {"status": "ok", "message": "pong"}


@app.route("/")
def home():
    return render_template_string(
        HOME_PAGE, style=BASE_STYLE, username=session.get("username")
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            session["username"] = username
            return redirect(url_for("home"))
        else:
            error = "Invalid username or password!"
    return render_template_string(LOGIN_PAGE, style=BASE_STYLE, error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
