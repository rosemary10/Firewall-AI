import sqlite3

conn = sqlite3.connect("firewall.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

print("\n=== USERS IN DATABASE ===\n")

for row in rows:
    print(row)

conn.close()