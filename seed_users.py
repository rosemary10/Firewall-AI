import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("firewall.db")
cursor = conn.cursor()

# Analyst User
cursor.execute("""
INSERT OR IGNORE INTO users (username, password, role)
VALUES (?, ?, ?)
""", ("analyst1", generate_password_hash("Analyst@123"), "analyst"))

# Normal User
cursor.execute("""
INSERT OR IGNORE INTO users (username, password, role)
VALUES (?, ?, ?)
""", ("user1", generate_password_hash("User@123"), "user"))

conn.commit()
conn.close()

print("Users created successfully")