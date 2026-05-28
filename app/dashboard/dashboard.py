from flask import Flask, render_template, request, redirect, url_for, session, Response
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from collections import Counter
import datetime

app = Flask(__name__)
app.secret_key = "SUPER_SECURE_FIREWALL_SECRET_KEY_2026"

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

# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["logged_in"] = True
            session["username"] = username
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user["role"] == "analyst":
                return redirect(url_for("analyst_dashboard"))
            else:
                return redirect(url_for("user_dashboard"))
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)

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

# ================= DASHBOARDS =================
@app.route("/admin")
def admin_dashboard():
    if not is_admin():
        return "ACCESS DENIED", 403

    logs, stats = load_logs()
    return render_template("admin_dashboard.html", role="admin", **stats, logs=logs)

@app.route("/analyst")
def analyst_dashboard():
    if not is_analyst():
        return "ACCESS DENIED", 403

    logs, stats = load_logs()
     # ================= ANALYST DAILY TIPS =================

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

@app.route("/user")
def user_dashboard():
    if not is_user():
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (session.get("username"),)
    ).fetchone()

    conn.close()

    if user is None:
        return "User not found", 404

    # ================= DAILY TIP (LEVEL 2) =================
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
    daily_tip = TIPS[today_index % len(TIPS)]

    return render_template(
    "user_dashboard.html",
    role="user",

    awareness_training_enabled=
        user["awareness_training_enabled"]
        if "awareness_training_enabled" in user.keys()
        else 1,

    safe_link_checker_enabled=
        user["safe_link_checker_enabled"]
        if "safe_link_checker_enabled" in user.keys()
        else 1,

    tips_enabled=
        user["tips_enabled"]
        if "tips_enabled" in user.keys()
        else 1,

    daily_tip=daily_tip
)

# ================= LOGS =================
def load_logs():
    conn = get_db_connection()

    rows = conn.execute("""
        SELECT timestamp, source_ip, destination_port, threat_level, message
        FROM logs ORDER BY id DESC
    """).fetchall()

    conn.close()

    logs = [dict(row) for row in rows]

    total_alerts = len(logs)
    blocked_ips = len(set(l["source_ip"] for l in logs))
    critical_count = sum(1 for l in logs if l["threat_level"] == "CRITICAL")
    high_count = sum(1 for l in logs if l["threat_level"] == "HIGH")
    medium_count = sum(1 for l in logs if l["threat_level"] == "MEDIUM")

    ip_counter = Counter(l["source_ip"] for l in logs)

    return logs, {
        "total_alerts": total_alerts,
        "blocked_ips": blocked_ips,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "top_ips": list(ip_counter.keys())[:10],
        "top_counts": list(ip_counter.values())[:10]
    }

# ================= 🔥 FIXED MISSING ROUTES =================

@app.route("/blocked")
def blocked():
    if not is_admin():
        return "ACCESS DENIED", 403

    conn = get_db_connection()
    ips = conn.execute("SELECT DISTINCT source_ip FROM logs").fetchall()
    conn.close()

    return render_template("blocked.html", ips=ips)

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

# ================= USER MANAGEMENT =================
@app.route("/users")
def users():
    if not is_admin():
        return "ACCESS DENIED", 403

    conn = get_db_connection()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()

    return render_template("users.html", users=users)

@app.route("/add_user", methods=["POST"])
def add_user():
    if not is_admin():
        return "ACCESS DENIED", 403

    username = request.form["username"]
    password = request.form["password"]
    role = request.form["role"]

    conn = get_db_connection()

    # 🔥 CHECK IF USER EXISTS
    existing = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if existing:
        conn.close()
        return "User already exists!", 400

    hashed = generate_password_hash(password)

    conn.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, hashed, role)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("users"))

@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    if not is_admin():
        return "ACCESS DENIED", 403

    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("users"))

# ================= REPORT =================
@app.route("/download_report")
def download_report():
    if not is_admin():
        return "ACCESS DENIED", 403

    logs, stats = load_logs()

    def generate():
        yield "FIREWALL AI REPORT\n\n"
        yield f"Total Alerts: {stats['total_alerts']}\n"
        yield f"Critical: {stats['critical_count']}\n"
        yield f"High: {stats['high_count']}\n"
        yield f"Medium: {stats['medium_count']}\n\n"

        for log in logs[:20]:
            yield f"{log['timestamp']} | {log['source_ip']} | {log['threat_level']} | {log['message']}\n"

    return Response(generate(),
                    mimetype="text/plain",
                    headers={"Content-Disposition": "attachment;filename=report.txt"})
# ================= AWARENESS =================

@app.route("/awareness")
def awareness():

    if not is_user():
        return "ACCESS DENIED", 403

    return render_template("awareness.html")

# ================= RUN =================

# =========================
# AWARENESS CATEGORY PAGES
# =========================

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

# =========================
# SAFE LINK CHECKER (ADD HERE)
# =========================
@app.route("/safe_link_checker")
def safe_link_checker():
    if not check_authentication():
        return redirect(url_for("login"))

    return render_template("safe_link_checker.html")

# =========================
# CHATBOT PAGE
# =========================
@app.route("/chatbot")
def chatbot():
    if not check_authentication():
        return redirect(url_for("login"))

    return render_template("chatbot.html")

@app.route("/chat", methods=["POST"])
def chat():
    if not check_authentication():
        return {"error": "unauthorized"}

    user_msg = request.json.get("message")
    role = session.get("role")

    response = ""

    if "phishing" in user_msg.lower():
        response = "Phishing is a cyber attack where attackers trick users into revealing sensitive data."

    elif "sql injection" in user_msg.lower():
        response = "SQL Injection is a web attack where malicious SQL is inserted into queries."

    elif role == "analyst":
        response = "Analyst mode: Always check logs, anomaly patterns, and threat levels."

    elif role == "user":
        response = "User tip: Never click unknown links and enable MFA."

    else:
        response = "I can help you with cybersecurity doubts."

    return {"reply": response}

# =========================
# QUIZ ROUTE
# =========================
@app.route("/quiz", methods=["GET", "POST"])
def quiz():

    if not is_user():
        return "ACCESS DENIED", 403

    questions = [
        {
            "q": "What is phishing?",
            "options": [
                "A type of firewall",
                "A fake attempt to steal information",
                "A password manager",
                "A secure network protocol"
            ],
            "answer": 1
        },
        {
            "q": "What does 2FA mean?",
            "options": [
                "Two Firewall Access",
                "Two Factor Authentication",
                "Fast Access Login",
                "File Authorization"
            ],
            "answer": 1
        },
        {
            "q": "Which is a strong password?",
            "options": [
                "12345678",
                "password",
                "Raj123",
                "R@j#9xL!2026"
            ],
            "answer": 3
        },
        {
            "q": "What should you do before clicking a website link?",
            "options": [
                "Share it with friends",
                "Check if the URL is trusted",
                "Disable antivirus",
                "Download unknown files"
            ],
            "answer": 2
        },
        {
            "q": "Which attack tricks users into revealing passwords?",
            "options": [
                "Phishing",
                "Firewall",
                "Encryption",
                "Backup"
            ],
            "answer": 1
        },
        {
            "q": "What is malware?",
            "options": [
                "A security update",
                "A harmful software",
                "A firewall device",
                "A password"
            ],
            "answer": 2
        },
        {
            "q": "Why is antivirus software important?",
            "options": [
                "It speeds up games",
                "It creates Wi-Fi",
                "It changes passwords",
                "It blocks malware threats"
            ],
            "answer": 4
        },
        {
            "q": "Which password is weakest?",
            "options": [
                "Strong@2026",
                "Qw#45!pl",
                "123456",
                "R@nd0mPass!"
            ],
            "answer": 3
        },
        {
            "q": "What does HTTPS mean on a website?",
            "options": [
                "Secure encrypted connection",
                "Unsafe connection",
                "Virus detected",
                "Public Wi-Fi"
            ],
            "answer": 1
        },
        {
            "q": "Which one is an example of social engineering?",
            "options": [
                "Phishing email",
                "Firewall configuration",
                "Data backup",
                "System update"
            ],
            "answer": 1
        },
        {
            "q": "What is ransomware?",
            "options": [
                "A backup software",
                "A malware that locks files",
                "A firewall",
                "A browser"
            ],
            "answer": 2
        },
        {
            "q": "Which is safest for online banking?",
            "options": [
                "Public Wi-Fi",
                "Unknown hotspot",
                "Secure private network",
                "Free café Wi-Fi"
            ],
            "answer": 3
        },
        {
            "q": "Why should software be updated regularly?",
            "options": [
                "To waste storage",
                "To remove security vulnerabilities",
                "To slow down the PC",
                "To delete files"
            ],
            "answer": 2
        },
        {
            "q": "What is a firewall used for?",
            "options": [
                "Cooking food",
                "Deleting passwords",
                "Blocking unauthorized access",
                "Creating viruses"
            ],  
            "answer": 3
        },
        {
            "q": "What should you do if you receive a suspicious email?",
            "options": [
                "Open all attachments",
                "Reply with passwords",
                "Delete or report it",
                "Forward to everyone"
            ],
            "answer": 3
        },
        {
            "q": "Which of these is a safe cybersecurity habit?",
            "options": [
                "Using the same password everywhere",
                "Sharing OTP codes",
                "Enabling 2FA",
                "Ignoring updates"
            ],
            "answer": 3
        },
        {
            "q": "What does VPN stand for?",
            "options": [
                "Virtual Private Network",
                "Verified Public Network",
                "Virtual Password Node",
                "Virus Protection Network"
            ],
            "answer": 1
        },
        {
            "q": "Which file type is commonly risky in emails?",
            "options": [
                ".txt",
                ".jpg",
                ".png",
                ".exe"
            ],
            "answer": 4
        },
        {
            "q": "What is the purpose of data backup?",
            "options": [
                "To recover lost files",
                "To create malware",
                "To slow systems",
                "To block websites"
            ],
            "answer": 1
        },
        {
            "q": "Which action improves account security the most?",
            "options": [
                "Using weak passwords",
                "Sharing passwords",
                "Enabling multi-factor authentication",
                "Ignoring alerts"
            ],
            "answer": 3
        }
    ]

    score = None

    if request.method == "POST":

        score = 0

        for i, q in enumerate(questions):

            selected = request.form.get(f"question{i+1}")

            if selected is not None and int(selected) == q["answer"]:
                score += 1

    return render_template(
        "quiz.html",
        questions=questions,
        score=score
    )

# =========================
# PASSWORD CHECKER
# =========================
@app.route("/password_checker", methods=["GET", "POST"])
def password_checker():

    if not is_user():
        return "ACCESS DENIED", 403

    strength = None

    if request.method == "POST":

        password = request.form.get("password")

        score = 0

        if len(password) >= 8:
            score += 1

        if any(char.isdigit() for char in password):
            score += 1

        if any(char.isupper() for char in password):
            score += 1

        if any(char in "!@#$%^&*" for char in password):
            score += 1

        if score <= 1:
            strength = "Weak Password ❌"

        elif score <= 3:
            strength = "Medium Password ⚠️"

        else:
            strength = "Strong Password ✅"

    return render_template(
        "password_checker.html",
        strength=strength
    )

# =========================
# LOGS PAGE
# =========================
@app.route("/logs")
def logs_page():

    if not (is_admin() or is_analyst()):
        return "ACCESS DENIED", 403

    conn = get_db_connection()

    logs = conn.execute("""
        SELECT *
        FROM logs
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "logs.html",
        logs=logs
    )
# =========================
# DEBUG ROUTE
# =========================
@app.route("/test")
def test():
    return "WORKING"

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)  