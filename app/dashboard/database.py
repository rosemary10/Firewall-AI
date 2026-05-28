import sqlite3


def create_database():

    connection = sqlite3.connect("firewall.db")

    cursor = connection.cursor()

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

    connection.commit()

    connection.close()

    print("Database and table created successfully!")


# Run directly
if __name__ == "__main__":
    create_database()