# The Vault v1.1
**Developed by Coleton B.**

The Vault is a secure password management tool that allows you to store, encrypt, and manage your passwords and usernames safely. This application uses `customtkinter` for the graphical user interface and `cryptography.fernet` for encryption, ensuring that your sensitive information is protected. 

## Features
- **Secure Password Storage:** Store your usernames and passwords with strong encryption.
- **Password Strength Analysis:** Analyze the strength of your stored passwords to ensure security.
- **Credential Management:** Add, view, and delete credentials easily from the GUI.
- **Master Password Protection:** Access to the vault is protected by a master password, hashed securely using bcrypt.
- **Information Window:** View details about the protocols and algorithms used in the program.

## Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/the-vault.git

2. **install dependences:**
   ```bash
   pip install -r requirements.txt


![Desktop Screenshot 2024 09 13 - 14 06 54 16](https://github.com/user-attachments/assets/da5493f4-a39c-44a3-bcc6-ee06ab183357)


--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

How It Works

    Encryption and Decryption: The Vault uses cryptography.fernet to encrypt usernames and passwords before storing them in a file named passwords.enc.
    Master Password: The vault is protected by a master password. The provided password is hashed using bcrypt and compared with the stored hash to verify access.
    Password Strength Analysis: Analyze your passwords for common weaknesses such as length, missing character types, or common patterns.

Code Structure

    vault_gui(): The main GUI function that sets up the password management interface.
    login_gui(): The login interface for entering the master password.
    info_gui(): A placeholder window for displaying additional information about the application.
    encrypt_data() and decrypt_data(): Functions to handle the encryption and decryption of stored credentials.
    add_password(), load_passwords(), delete_password(): Functions to manage the storage of credentials.
    analyze_password_strength(): A function to provide feedback on password strength.

Key Functionalities

    Focus Navigation: The application supports seamless navigation between input fields using the up and down arrow keys.
    Password Management: Easily add, view, and delete credentials through a user-friendly interface.
    Password Strength Feedback: Receive immediate feedback on the strength of your passwords to enhance security.


