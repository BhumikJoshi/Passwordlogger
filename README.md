# Passwordlogger
Secure Password Vault
1. A Python-based password manager that securely stores and manages your website credentials using:

2. SQLite for database storage

3. bcrypt for master password hashing

4. Fernet encryption for password security

5. Tkinter for a graphical user interface



🔒 Your passwords are stored encrypted and protected by a master password.



Features
1. User Registration: Set a master password (hashed with bcrypt).

2. User Login: Authenticate securely before accessing your vault.

3. Password Storage: Encrypt and store website credentials.

4. Password Retrieval: View stored credentials in a secure table.

5. Password Deletion: Remove credentials securely.

6. Copy Password: Copy a selected password directly to clipboard.



Installation
1. Clone the repository or download the pass.py file.

2. Install dependencies (if not already installed):

	pip install bcrypt cryptography

Tkinter usually comes pre-installed with Python. If not, install it manually based on your OS.

4. Run the Application:

	python pass.py



Usage
1. First Time Setup:

	When you run the program for the first time, a database (vault.db) and an encryption key (key.key) are created.

	Register a Master Password to secure access.

2. Main Functionalities:

	Register: Create a master password.

	Login: Enter your master password to unlock features.

	Add Password: Save a new website username-password pair.

	Show Passwords: View, copy, or delete saved passwords.



Project Structure

File		|	Purpose

pass.py		|	Main application code

vault.db	|	SQLite database (auto-created)

key.key		|	Encryption key for passwords



Security
1. Master Password: Hashed using bcrypt (with salting).

2. Saved Passwords: Encrypted with a symmetric Fernet key.

3. Database: Local SQLite database (vault.db).

⚠️ Important:

1. Do not delete key.key file after storing passwords.

2. Losing key.key will make your stored passwords unrecoverable.



Requirements
1. Python 3.7+

2. Packages:

	1. bcrypt

	2. cryptography

	3. tkinter (usually pre-installed)

License
This project is open-source. Feel free to modify and enhance it for your personal use! ✨
