
import sqlite3
from werkzeug.security import generate_password_hash
from database import get_db_connection

username = input("Enter username: ").strip()
password = input("Enter password: ")

print("Choose role:")
print("1. Owner")
print("2. Viewer")

choice = input("Enter 1 or 2: ").strip()

roles = {
    "1": "owner",
    "2": "viewer",
}

role = roles.get(choice)

if not username or not password:
    print("Username and password cannot be empty.")
elif role is None:
    print("Invalid role. Choose 1 or 2.")
else:
    connection = get_db_connection()

    try:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, generate_password_hash(password), role),
        )
        connection.commit()
        print(f"{role.capitalize()} user created successfully!")

    except sqlite3.IntegrityError:
        print("Username already exists. Choose another username.")

    finally:
        connection.close()
