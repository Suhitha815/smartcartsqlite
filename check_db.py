import sqlite3

conn = sqlite3.connect('smartcart.db')
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("Tables in DB:", tables)

# Optionally, see users table content
cursor.execute("SELECT * FROM users;")
users = cursor.fetchall()
print("Users table rows:", users)

conn.close()
