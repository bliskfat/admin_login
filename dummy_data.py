import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import datetime

from login_2 import hash_password


def add_dummy_users():
    dummy_users = [
        ("john_doe", "password123", "What is your pet's name?", "Fluffy", "User"),
        ("jane_smith", "securepass", "What is your favorite color?", "Blue", "Manager"),
        ("admin_user", "adminpass", "What city were you born in?", "New York", "Admin"),
        ("manager1", "manageme", "What was the name of your first school?", "Greenwood", "Manager"),
        ("user123", "userpass", "What is your favorite movie?", "Inception", "User"),
        ("developer", "devpass", "What is your first car model?", "Toyota", "User"),
        ("tester", "test123", "What is your favorite food?", "Pizza", "User"),
        ("owner", "ownit", "What is your mother's maiden name?", "Brown", "Admin"),
        ("guest", "guest123", "What is your best friend's name?", "Chris", "User"),
        ("ceo_user", "ceopass", "What was the name of your childhood hero?", "Superman", "Admin")
    ]

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    for username, password, question, answer, role in dummy_users:
        try:
            cursor.execute('''
                INSERT INTO users (username, password, recovery_question, recovery_answer, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hash_password(password), question, hash_password(answer), role))
        except sqlite3.IntegrityError:
            print(f"User {username} already exists, skipping.")
    conn.commit()
    conn.close()
    print("Dummy users added successfully!")


add_dummy_users()