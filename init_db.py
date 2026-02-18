import sqlite3

# Connect to SQLite database (creates file if not exists)
conn = sqlite3.connect("smartcart.db")

# Execute schema.sql file
with open("schema.sql", "r") as f:
    conn.executescript(f.read())

# Commit changes and close connection
conn.commit()
conn.close()

print("Database initialized successfully.")
