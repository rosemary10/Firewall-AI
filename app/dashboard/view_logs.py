import sqlite3

connection = sqlite3.connect("firewall.db")

cursor = connection.cursor()

cursor.execute("SELECT * FROM logs")

rows = cursor.fetchall()

print("\n===== DATABASE LOGS =====\n")

for row in rows:
    print(row)

connection.close()