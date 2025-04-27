# 🔒 Secure Password Vault

[![Python](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)

A **simple and secure password manager** built with Python, using:
- **SQLite** for storage
- **bcrypt** for master password hashing
- **Fernet encryption** to protect saved passwords
- **Tkinter** for a clean and minimal GUI

> Your passwords are encrypted, locally stored, and protected by a master password.

---

## ✨ Features

- 🔑 Master password authentication (bcrypt-hashed)
- 🔒 Password encryption (Fernet AES encryption)
- 🗂️ Save website, username, and password securely
- 👀 View stored passwords in a user-friendly table
- 📋 Copy password to clipboard
- 🗑️ Delete stored passwords easily
- 🎨 Simple and responsive GUI (Tkinter)

---

## 📦 Installation

1. **Clone this repository**:

bash

git clone https://github.com/your-username/secure-password-vault.git

cd secure-password-vault

---

🚀 Usage
- First Run:

	- A new encryption key (key.key) and database (vault.db) will be generated.

	- Register your master password.

- Main Actions:

	- Register: Set up a new master password.

	- Login: Authenticate using your master password.

	- Add Password: Save website credentials securely.

	- Show Passwords: View, copy, or delete stored credentials.

---

Project Structure

	Password Logger/
	
	├── pass.py
	
	├── key.key   (auto-created)
	
	├── vault.db  (auto-created)
	
	└── README.md   

---

🛡️ Security Notes
- The master password is securely hashed using bcrypt (with salt).

- All stored passwords are encrypted using a unique Fernet key.

- IMPORTANT: Do not delete the key.key file! Without it, your passwords cannot be decrypted.

