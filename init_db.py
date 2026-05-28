import sqlite3

conn = sqlite3.connect("firewall.db")
cursor = conn.cursor()

# ================= USERS TABLE =================
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT UNIQUE,
    password TEXT,
    role TEXT,

    awareness_training_enabled INTEGER DEFAULT 1,
    safe_link_checker_enabled INTEGER DEFAULT 1,
    tips_enabled INTEGER DEFAULT 1
)
""")

# ================= LOGS TABLE =================
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    destination_port TEXT,
    threat_level TEXT,
    message TEXT
)
""")

# ================= SAMPLE USERS =================
from werkzeug.security import generate_password_hash

cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
               ("admin", generate_password_hash("admin123"), "admin"))

cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
               ("analyst1", generate_password_hash("analyst123"), "analyst"))

cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
               ("user1", generate_password_hash("user123"), "user"))

conn.commit()
conn.close()

print("Database created successfully")