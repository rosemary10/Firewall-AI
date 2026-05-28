import sqlite3

conn = sqlite3.connect("firewall.db")
cursor = conn.cursor()

# ================= USERS TABLE =================
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    email TEXT UNIQUE,
    mobile TEXT UNIQUE,

    password TEXT,

    role TEXT DEFAULT 'user',

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

conn.commit()
conn.close()

print("Database created successfully")