import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

authenticated = False  # Track authentication state

def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def init_db():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            master_password BLOB
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            website TEXT,
            username TEXT,
            password BLOB
        )
    """)
    conn.commit()
    conn.close()

def store_password(website, username, password):
    key = load_key()
    cipher = Fernet(key)
    encrypted_password = cipher.encrypt(password.encode())
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                   (website, username, encrypted_password))
    conn.commit()
    conn.close()
    root.after(0, lambda: messagebox.showinfo("Success", "Password Stored Successfully!"))

def retrieve_passwords():
    key = load_key()
    cipher = Fernet(key)
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, website, username, password FROM passwords")
    data = cursor.fetchall()
    conn.close()
    decrypted_data = [(id_, site, user, cipher.decrypt(pwd).decode()) for id_, site, user, pwd in data]
    return decrypted_data

def delete_password(password_id):
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
    conn.commit()
    conn.close()
    root.after(0, lambda: messagebox.showinfo("Success", "Password Deleted Successfully!"))

def register():
    master_password = simpledialog.askstring("Register", "Set Master Password:", show='*')
    hashed_password = hash_password(master_password)
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (master_password) VALUES (?)", (hashed_password,))
    conn.commit()
    conn.close()
    root.after(0, lambda: messagebox.showinfo("Success", "Registration Complete!"))

def login():
    global authenticated
    master_password = simpledialog.askstring("Login", "Enter Master Password:", show='*')
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT master_password FROM users LIMIT 1")
    user = cursor.fetchone()
    conn.close()
    if user and verify_password(master_password, user[0]):
        authenticated = True
        root.after(0, lambda: messagebox.showinfo("Success", "Login Successful!"))
    else:
        authenticated = False
        root.after(0, lambda: messagebox.showerror("Error", "Invalid Credentials"))

def add_password():
    if not authenticated:
        root.after(0, lambda: messagebox.showerror("Error", "You must log in first!"))
        return
    website = simpledialog.askstring("New Entry", "Website:")
    username = simpledialog.askstring("New Entry", "Username:")
    password = simpledialog.askstring("New Entry", "Password:", show='*')
    store_password(website, username, password)

def show_passwords():
    if not authenticated:
        root.after(0, lambda: messagebox.showerror("Error", "You must log in first!"))
        return
    passwords = retrieve_passwords()
    display_window = tk.Toplevel(root)
    display_window.title("Stored Passwords")
    display_window.geometry("500x400")
    display_window.configure(bg="#f0e68c")
    
    tk.Label(display_window, text="Stored Passwords", font=("Arial", 14, "bold"), bg="#f0e68c", fg="#4b0082").pack(pady=10)
    
    tree = ttk.Treeview(display_window, columns=("ID", "Website", "Username", "Password"), show="headings")
    tree.heading("ID", text="ID")
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    for id_, site, user, pwd in passwords:
        tree.insert("", tk.END, values=(id_, site, user, pwd))
    
    def on_delete():
        selected_item = tree.selection()
        if selected_item:
            item = tree.item(selected_item)
            password_id = item['values'][0]
            delete_password(password_id)
            tree.delete(selected_item)
        else:
            messagebox.showerror("Error", "Please select an entry to delete.")
    
    def on_copy():
        selected_item = tree.selection()
        if selected_item:
            item = tree.item(selected_item)
            password_to_copy = item['values'][3]  # Password is the fourth column
            display_window.clipboard_clear()
            display_window.clipboard_append(password_to_copy)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showerror("Error", "Please select an entry to copy.")

    # Buttons for delete and copy actions
    button_frame = tk.Frame(display_window, bg="#f0e68c")
    button_frame.pack(pady=5)
    
    delete_button = ttk.Button(button_frame, text="Delete Selected", command=on_delete)
    delete_button.pack(side=tk.LEFT, padx=5)
    
    copy_button = ttk.Button(button_frame, text="Copy Selected", command=on_copy)
    copy_button.pack(side=tk.LEFT, padx=5)

def main():
    global root
    root = tk.Tk()
    root.title("Secure Password Vault")
    root.geometry("400x350")
    root.configure(bg="#add8e6")
    
    frame = tk.Frame(root, bg="#ffffff", padx=10, pady=10, relief=tk.RIDGE, bd=2)
    frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
    
    tk.Label(frame, text="Secure Password Vault", font=("Arial", 16, "bold"), bg="#ffffff", fg="#0073e6").pack(pady=10)
    
    style = ttk.Style()
    style.configure("TButton", font=("Arial", 12), padding=5, background="#0073e6", foreground="black")
    
    ttk.Button(frame, text="Register", command=register, style="TButton").pack(pady=5, fill=tk.X)
    ttk.Button(frame, text="Login", command=login, style="TButton").pack(pady=5, fill=tk.X)
    ttk.Button(frame, text="Add Password", command=add_password, style="TButton").pack(pady=5, fill=tk.X)
    ttk.Button(frame, text="Show Passwords", command=show_passwords, style="TButton").pack(pady=5, fill=tk.X)
    
    root.mainloop()

if __name__ == "__main__":
    init_db()
    generate_key()  
    main()
