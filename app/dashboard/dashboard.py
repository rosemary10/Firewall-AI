from flask import Flask, render_template, request, redirect, url_for, session, Response
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from collections import Counter
import datetime
import re
import os

app = Flask(__name__)
app.secret_key = "SUPER_SECURE_SENTINELAI_SECRET_KEY_2026"

# ================= DB =================
def get_db_connection():
    conn = sqlite3.connect(
        "firewall.db",
        timeout=10
    )

    conn.row_factory = sqlite3.Row
    return conn

# ================= AUTH =================
def is_admin():
    return session.get("role") == "admin"

def is_analyst():
    return session.get("role") == "analyst"

def is_user():
    return session.get("role") == "user"

def check_authentication():
    return session.get("logged_in")

# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():

    error = None
    success = None

    if request.method == "POST":

        email = request.form.get("email").strip()
        mobile = request.form.get("mobile").strip()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # PASSWORD RULE
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$"

        # PASSWORD MATCH
        if password != confirm_password:

            error = "Passwords do not match"

        # PASSWORD VALIDATION
        elif not re.match(pattern, password):

            error = """
Password must contain:
- Minimum 8 characters
- Uppercase letter
- Lowercase letter
- Number
- Special character
"""

        else:

            conn = get_db_connection()

            # CHECK EMAIL
            existing_email = conn.execute(
                "SELECT * FROM users WHERE email=?",
                (email,)
            ).fetchone()

            # CHECK MOBILE
            existing_mobile = conn.execute(
                "SELECT * FROM users WHERE mobile=?",
                (mobile,)
            ).fetchone()

            if existing_email:

                error = "Email already registered"

            elif existing_mobile:

                error = "Mobile number already registered"

            else:

                hashed_password = generate_password_hash(password)

                conn.execute("""
INSERT INTO users (
    email,
    mobile,
    password,
    role
)
VALUES (?, ?, ?, ?)
""", (
    email,
    mobile,
    hashed_password,
    "user"
))

                conn.commit()

                success = "Registration successful. Please login."

            conn.close()

    return render_template(
        "register.html",
        error=error,
        success=success
    )

# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        login_input = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()

        user = conn.execute("""
SELECT *
FROM users
WHERE email=? OR mobile=?
""", (
    login_input,
    login_input
)).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            session["logged_in"] = True
            session["user_email"] = user["email"]
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            elif user["role"] == "analyst":
                return redirect(url_for("analyst_dashboard"))

            else:
                return redirect(url_for("user_dashboard"))

        else:
            error = "Invalid credentials"

    return render_template(
        "login.html",
        error=error
    )

# ================= LOGOUT =================
@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))

# ================= ROOT =================
@app.route("/")
def root():

    if not check_authentication():
        return redirect(url_for("login"))

    role = session.get("role")

    if role == "admin":
        return redirect(url_for("admin_dashboard"))

    elif role == "analyst":
        return redirect(url_for("analyst_dashboard"))

    else:
        return redirect(url_for("user_dashboard"))

# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin_dashboard():

    if not is_admin():
        return "ACCESS DENIED", 403

    logs, stats = load_logs()

    return render_template(
        "admin_dashboard.html",
        role="admin",
        **stats,
        logs=logs
    )

# ================= ANALYST DASHBOARD =================
@app.route("/analyst")
def analyst_dashboard():

    if not is_analyst():
        return "ACCESS DENIED", 403

    logs, stats = load_logs()

    ANALYST_TIPS = [

        "Investigate repeated login failures immediately",

        "Monitor unusual outbound traffic patterns",

        "Always validate firewall critical alerts",

        "Check logs for brute-force attack indicators",

        "Review suspicious IP addresses daily",

        "Monitor failed admin login attempts",

        "Investigate unknown open ports quickly",

        "Analyze phishing email indicators carefully",

        "Correlate alerts with network activity",

        "Keep SIEM and IDS signatures updated"
    ]

    today_index = datetime.date.today().toordinal()

    analyst_tip = ANALYST_TIPS[
        today_index % len(ANALYST_TIPS)
    ]

    return render_template(
        "analyst_dashboard.html",
        role="analyst",
        **stats,
        logs=logs,
        analyst_tip=analyst_tip
    )

# ================= USER DASHBOARD =================
@app.route("/user")
def user_dashboard():

    if not is_user():
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE email=?",
        (session.get("user_email"),)
    ).fetchone()

    conn.close()

    if user is None:
        return "User not found", 404

    TIPS = [

        "Use strong passwords with symbols & numbers",

        "Enable Two-Factor Authentication (2FA)",

        "Never click unknown email links",

        "Keep your system and antivirus updated",

        "Avoid using public Wi-Fi for banking",

        "Always verify website URLs before login",

        "Do not reuse passwords across sites"
    ]

    today_index = datetime.date.today().toordinal()

    daily_tip = TIPS[
        today_index % len(TIPS)
    ]

    return render_template(
        "user_dashboard.html",

        role="user",

        awareness_training_enabled=
            user["awareness_training_enabled"],

        safe_link_checker_enabled=
            user["safe_link_checker_enabled"],

        tips_enabled=
            user["tips_enabled"],

        daily_tip=daily_tip
    )

# ================= LOAD LOGS =================
def load_logs():

    conn = get_db_connection()

    rows = conn.execute("""
SELECT timestamp, source_ip, destination_port,
threat_level, message
FROM logs
ORDER BY id DESC
""").fetchall()

    conn.close()

    logs = [dict(row) for row in rows]

    total_alerts = len(logs)

    blocked_ips = len(
        set(l["source_ip"] for l in logs)
    )

    critical_count = sum(
        1 for l in logs
        if l["threat_level"] == "CRITICAL"
    )

    high_count = sum(
        1 for l in logs
        if l["threat_level"] == "HIGH"
    )

    medium_count = sum(
        1 for l in logs
        if l["threat_level"] == "MEDIUM"
    )

    ip_counter = Counter(
        l["source_ip"] for l in logs
    )

    return logs, {

        "total_alerts": total_alerts,

        "blocked_ips": blocked_ips,

        "critical_count": critical_count,

        "high_count": high_count,

        "medium_count": medium_count,

        "top_ips": list(ip_counter.keys())[:10],

        "top_counts": list(ip_counter.values())[:10]
    }

# ================= BLOCKED IPS =================
@app.route("/blocked")
def blocked():

    if not is_admin():
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    ips = conn.execute("""
SELECT DISTINCT source_ip
FROM logs
""").fetchall()

    conn.close()

    return render_template(
        "blocked.html",
        ips=ips
    )

# ================= CRITICAL =================
@app.route("/critical")
def critical():

    if not (is_admin() or is_analyst()):
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    logs = conn.execute("""
SELECT *
FROM logs
WHERE threat_level='CRITICAL'
""").fetchall()

    conn.close()

    return render_template(
        "critical.html",
        logs=logs
    )

# ================= HIGH =================
@app.route("/high")
def high():

    if not (is_admin() or is_analyst()):
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    logs = conn.execute("""
SELECT *
FROM logs
WHERE threat_level='HIGH'
""").fetchall()

    conn.close()

    return render_template(
        "high.html",
        logs=logs
    )

# ================= MEDIUM =================
@app.route("/medium")
def medium():

    if not (is_admin() or is_analyst()):
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    logs = conn.execute("""
SELECT *
FROM logs
WHERE threat_level='MEDIUM'
""").fetchall()

    conn.close()

    return render_template(
        "medium.html",
        logs=logs
    )

# ================= USERS =================
@app.route("/users")
def users():

    if not is_admin():
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    users = conn.execute("""
SELECT id, email, mobile, role
FROM users
""").fetchall()

    conn.close()

    return render_template(
        "users.html",
        users=users
    )

# ================= DOWNLOAD REPORT =================
@app.route("/download_report")
def download_report():

    if not is_admin():
        return "ACCESS DENIED", 403

    logs, stats = load_logs()

    def generate():

        yield "SENTINELAI REPORT\n\n"

        yield f"Total Alerts: {stats['total_alerts']}\n"

        yield f"Critical: {stats['critical_count']}\n"

        yield f"High: {stats['high_count']}\n"

        yield f"Medium: {stats['medium_count']}\n\n"

        for log in logs[:20]:

            yield f"""
{log['timestamp']} |
{log['source_ip']} |
{log['threat_level']} |
{log['message']}
"""

    return Response(
        generate(),
        mimetype="text/plain",
        headers={
            "Content-Disposition":
            "attachment;filename=report.txt"
        }
    )

# ================= AWARENESS =================
@app.route("/awareness")
def awareness():

    if not is_user():
        return "ACCESS DENIED", 403

    return render_template("awareness.html")

# ================= CATEGORY PAGES =================
@app.route("/malware")
def malware():
    return render_template("malware.html")

@app.route("/social")
def social():
    return render_template("social.html")

@app.route("/network")
def network():
    return render_template("network.html")

@app.route("/webattacks")
def webattacks():
    return render_template("webattacks.html")

@app.route("/password")
def password():
    return render_template("password.html")

@app.route("/advanced")
def advanced():
    return render_template("advanced.html")

# ================= SAFE LINK CHECKER =================
@app.route("/safe_link_checker")
def safe_link_checker():

    if not check_authentication():
        return redirect(url_for("login"))

    return render_template("safe_link_checker.html")

# ================= CHATBOT =================
@app.route("/chatbot")
def chatbot():

    if not check_authentication():
        return redirect(url_for("login"))

    return render_template("chatbot.html")

# ================= CHAT API =================
@app.route("/chat", methods=["POST"])
def chat():

    if not check_authentication():
        return {"error": "unauthorized"}

    user_msg = request.json.get("message")

    role = session.get("role")

    response = ""

    if "phishing" in user_msg.lower():

        response = """
Phishing is a cyber attack where
attackers trick users into revealing
sensitive information.
"""

    elif "sql injection" in user_msg.lower():

        response = """
SQL Injection is a web attack where
malicious SQL code is inserted
into database queries.
"""

    elif role == "analyst":

        response = """
Analyst mode:
Check logs, anomaly patterns,
and threat indicators carefully.
"""

    elif role == "user":

        response = """
User tip:
Never click unknown links
and always enable MFA.
"""

    else:

        response = """
I can help you with
cybersecurity questions.
"""

    return {
        "reply": response
    }

# ================= DEBUG =================
@app.route("/test")
def test():
    return "WORKING"

# ================= RUN =================
if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 5000)
    )

    app.run(
        host="0.0.0.0",
        port=port
    )