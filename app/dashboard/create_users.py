import sqlite3

from werkzeug.security import generate_password_hash

# =====================================
# CONNECT DATABASE
# =====================================

connection = sqlite3.connect("firewall.db")

cursor = connection.cursor()

# =====================================
# CREATE USERS TABLE
# =====================================

cursor.execute("""

CREATE TABLE IF NOT EXISTS users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT UNIQUE NOT NULL,

    password TEXT NOT NULL,

    role TEXT NOT NULL

)

""")

# =====================================
# CREATE DEFAULT ADMIN
# =====================================

admin_username = "admin"

admin_password = generate_password_hash("Cyber@123")

admin_role = "admin"

# Check if admin already exists

cursor.execute(

    "SELECT * FROM users WHERE username=?",

    (admin_username,)

)

existing_admin = cursor.fetchone()

# =====================================
# INSERT ADMIN
# =====================================

if not existing_admin:

    cursor.execute("""

    INSERT INTO users (

        username,
        password,
        role

    )

    VALUES (?, ?, ?)

    """, (

        admin_username,
        admin_password,
        admin_role

    ))

    print("✅ Admin account created successfully!")

else:

    print("⚠️ Admin already exists.")

# =====================================
# SAVE DATABASE
# =====================================

connection.commit()

connection.close()

print("✅ Users table ready.")