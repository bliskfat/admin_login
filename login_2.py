import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import datetime

# Database setup
def setup_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            recovery_question TEXT NOT NULL,
            recovery_answer TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Hashing function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Log user activity
def log_user_activity(username, action):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO user_activity (username, action, timestamp)
        VALUES (?, ?, ?)
    ''', (username, action, timestamp))
    conn.commit()
    conn.close()

# Fetch all users
def fetch_all_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, role FROM users')
    users = cursor.fetchall()
    conn.close()
    return users

# Update user role
def update_user_role(username, new_role, admin_username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    if result:
        old_role = result[0]
        if old_role != new_role:
            cursor.execute('UPDATE users SET role = ? WHERE username = ?', (new_role, username))
            conn.commit()
            log_user_activity(admin_username, f"Changed role of {username} from {old_role} to {new_role}")
            messagebox.showinfo("Success", f"User {username}'s role updated to {new_role}!")
        else:
            messagebox.showinfo("No Change", f"User {username} is already {new_role}.")
    else:
        messagebox.showerror("Error", "User not found.")
    conn.close()


def reset_user_password(username, admin_username):
    """
    Resets the password for a specified user.

    Args:
        username (str): The username whose password will be reset.
        admin_username (str): The admin performing the reset.

    Returns:
        None
    """
    reset_window = tk.Toplevel(root)
    reset_window.title(f"Reset Password for {username}")

    tk.Label(reset_window, text=f"New Password for {username}:").grid(row=0, column=0, padx=10, pady=10)
    new_password_entry = tk.Entry(reset_window, show="*")
    new_password_entry.grid(row=0, column=1, padx=10, pady=10)

    def submit_reset_password():
        new_password = new_password_entry.get()
        if len(new_password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hash_password(new_password), username))
        conn.commit()
        conn.close()

        log_user_activity(admin_username, f"Reset password for {username}")
        messagebox.showinfo("Success", f"Password for {username} has been reset.")
        reset_window.destroy()

    tk.Button(reset_window, text="Reset Password", command=submit_reset_password).grid(row=1, column=0, columnspan=2, pady=10)


# Delete user
def delete_user(username, admin_username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    log_user_activity(admin_username, f"Deleted user {username}")
    conn.close()
    messagebox.showinfo("Success", f"User {username} has been deleted.")

# Admin: View logs
def open_logs_view():
    logs_window = tk.Toplevel(root)
    logs_window.title("User Activity Logs")

    # Treeview for logs
    tree = ttk.Treeview(logs_window, columns=("Username", "Action", "Timestamp"), show="headings", height=15)
    tree.heading("Username", text="Username")
    tree.heading("Action", text="Action")
    tree.heading("Timestamp", text="Timestamp")
    tree.pack(pady=10)

    # Fetch logs from the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, action, timestamp FROM user_activity ORDER BY timestamp DESC')
    logs = cursor.fetchall()
    conn.close()

    # Populate Treeview
    for log in logs:
        tree.insert("", "end", values=log)

# Admin: Manage users
def open_admin_dashboard(admin_username):
    dashboard_window = tk.Toplevel(root)
    dashboard_window.title("Admin Dashboard")

    tk.Label(dashboard_window, text=f"Welcome, {admin_username}!", font=("Arial", 16)).pack(pady=10)

    # Treeview for users
    tree = ttk.Treeview(dashboard_window, columns=("Username", "Role"), show="headings", height=10)
    tree.heading("Username", text="Username")
    tree.heading("Role", text="Role")
    tree.pack(pady=10)

    # Populate Treeview
    users = fetch_all_users()
    for user in users:
        tree.insert("", "end", values=user)

    # Manage selected user
    def manage_selected_user():
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No user selected.")
            return

        username = tree.item(selected_item, "values")[0]

        role_window = tk.Toplevel(dashboard_window)
        role_window.title(f"Manage User: {username}")

        tk.Label(role_window, text="New Role:").grid(row=0, column=0, padx=10, pady=10)
        new_role_var = tk.StringVar()
        roles = ["User", "Manager", "Admin"]
        new_role_menu = ttk.Combobox(role_window, textvariable=new_role_var, values=roles, state="readonly")
        new_role_menu.grid(row=0, column=1, padx=10, pady=10)
        new_role_menu.current(0)

        def submit_role_change():
            new_role = new_role_var.get()
            update_user_role(username, new_role, admin_username)
            tree.item(selected_item, values=(username, new_role))  # Update Treeview
            role_window.destroy()

        def submit_delete_user():
            confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user {username}?")
            if confirm:
                delete_user(username, admin_username)
                tree.delete(selected_item)  # Remove from Treeview
                role_window.destroy()

        tk.Button(role_window, text="Update Role", command=submit_role_change).grid(row=1, column=0, pady=10)
        tk.Button(role_window, text="Delete User", command=submit_delete_user).grid(row=1, column=1, pady=10)
        tk.Button(role_window, text="Reset Password", command=lambda: reset_user_password(username, admin_username)).grid(row=2, column=0, columnspan=2, pady=10)

    tk.Button(dashboard_window, text="Manage Selected User", command=manage_selected_user).pack(pady=10)
    tk.Button(dashboard_window, text="View Logs", command=open_logs_view).pack(pady=10)


# General dashboard
def open_dashboard(username, role):
    log_user_activity(username, "Login")
    dashboard_window = tk.Toplevel(root)
    dashboard_window.title(f"{role} Dashboard")

    tk.Label(dashboard_window, text=f"Welcome, {username}!", font=("Arial", 16)).pack(pady=10)
    tk.Label(dashboard_window, text=f"Role: {role}", font=("Arial", 12)).pack(pady=5)

    if role == "Admin":
        tk.Button(dashboard_window, text="Admin Dashboard", command=lambda: open_admin_dashboard(username)).pack(pady=10)
    elif role == "Manager":
        tk.Button(dashboard_window, text="Manager Feature 1").pack(pady=10)
    elif role == "User":
        tk.Button(dashboard_window, text="User Feature 1").pack(pady=10)

    def logout():
        log_user_activity(username, "Logout")
        dashboard_window.destroy()

    tk.Button(dashboard_window, text="Logout", command=logout).pack(pady=10)

# Login
def login():
    username = username_entry.get()
    password = password_entry.get()

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password, role FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_password, role = result
        if hash_password(password) == stored_password:
            open_dashboard(username, role)
        else:
            messagebox.showerror("Login Failed", "Invalid password!")
    else:
        messagebox.showerror("Login Failed", "Username not found!")

# GUI Setup
setup_database()
root = tk.Tk()
root.title("Login System with Tracking")

# Login Screen
tk.Label(root, text="Username:").grid(row=0, column=0, padx=10, pady=10)
username_entry = tk.Entry(root)
username_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Button(root, text="Login", command=login).grid(row=2, column=0, columnspan=2, pady=10)

# Run Application
root.mainloop()
