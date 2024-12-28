# File: login_ui.py
import tkinter as tk
from tkinter import messagebox


# Function to handle login
def login():
    username = username_entry.get()
    password = password_entry.get()

    # Placeholder for real authentication logic
    if username == "admin" and password == "password":
        messagebox.showinfo("Login Successful", "Welcome to the App!")
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")


# Initialize the main window
root = tk.Tk()
root.title("Login Interface")
root.geometry("300x200")  # Set the window size

# Username Label and Entry
username_label = tk.Label(root, text="Username:")
username_label.pack(pady=(20, 5))  # Add some vertical padding
username_entry = tk.Entry(root, width=30)
username_entry.pack()

# Password Label and Entry
password_label = tk.Label(root, text="Password:")
password_label.pack(pady=(10, 5))
password_entry = tk.Entry(root, width=30, show="*")  # Hide password characters
password_entry.pack()

# Login Button
login_button = tk.Button(root, text="Login", command=login)
login_button.pack(pady=20)

# Run the Tkinter event loop
root.mainloop()
