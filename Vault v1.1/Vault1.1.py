"""The Vault v1.1 Made by Coleton B."""
import customtkinter as ctk
from cryptography.fernet import Fernet
import os
import getpass
import bcrypt
from PIL import Image
import time
from tkinter import font
import re

# file that stores encrypted passwords/usernames
PASSWORD_FILE = "passwords.enc"
# file that it is the vault key 
KEY_FILE = "vault.key"
# MP hash
MASTER_PASSWORD_HASH = "$2b$12$QJi0TkSpjnxxTo.SjF46Z.ckuSDs8IYV/4FW6ojvASjuw6a7a.9m2"

def load_key():
    #loads up vault key from directory 
    try:
        return open(KEY_FILE, "rb").read()
    except Exception as e:
        print("Access Denied: Unable to load the encryption key.")
        exit()

def focus_next_widget(event):
    # This is for when you are on an entry you can click up arrow to move you to the next
    event.widget.tk_focusNext().focus()
    return "break"

def focus_previous_widget(event):
    #same as above function but down instead of up
    event.widget.tk_focusPrev().focus()
    return "break"

def hash_password(password):
    #hashes MP using bcrypt 
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash)

def encrypt_data(data, key):
    #using the key it encrypts username and password data"
    try:
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data
    except ValueError as e:
        print("Access Denied: Invalid encryption key.")
        exit()

def decrypt_data(encrypted_data, key):
    #decrypts data using same key 
    try:
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data
    except (ValueError, Exception) as e:
        print("Access Denied: Invalid encryption key or corrupted data.")
        exit()

def add_password(website, username, password, key):
    # Add new credentials
    encrypted_username = encrypt_data(username, key)
    encrypted_password = encrypt_data(password, key)
    with open(PASSWORD_FILE, "ab") as file:
        file.write(f"{website}:{encrypted_username.decode()}:{encrypted_password.decode()}\n".encode())

def load_passwords(key):
    # Load and decrypt passwords/usernames
    if not os.path.exists(PASSWORD_FILE):
        return []

    credentials = []
    with open(PASSWORD_FILE, "rb") as file:
        lines = file.readlines()
        for line in lines:
            parts = line.decode().strip().split(":")
            if len(parts) == 3:
                website, encrypted_username, encrypted_password = parts
                decrypted_username = decrypt_data(encrypted_username.encode(), key)
                decrypted_password = decrypt_data(encrypted_password.encode(), key)
                credentials.append((website, decrypted_username, decrypted_password))
    return credentials

def delete_password(website, key):

    #delete credentials from the vault
    if not os.path.exists(PASSWORD_FILE):
        return

    credentials = load_passwords(key)
    updated_credentials = [(site, usr, pwd) for site, usr, pwd in credentials if site != website]

    if len(updated_credentials) == len(credentials):
        return

    #overwrite the file with updated credentials
    with open(PASSWORD_FILE, "wb") as file:
        for site, usr, pwd in updated_credentials:
            encrypted_username = encrypt_data(usr, key)
            encrypted_password = encrypt_data(pwd, key)
            file.write(f"{site}:{encrypted_username.decode()}:{encrypted_password.decode()}\n".encode())

def clear_status_label(message, status_label):
    #this function is just used to clear status label after 5 seconds 
    status_label.configure(text=message)
    status_label.after(5000, lambda: status_label.configure(text=""))

def analyze_password_strength(password):
    feedback = []
    #Check pw length
    if len(password) < 12:
        feedback.append("Password is too short. Consider using at least 12 characters.")
    #Check for uppercase, lowercase, digits, and special characters
    if not re.search(r'[A-Z]', password):
        feedback.append("Add uppercase letters for better security.")
    if not re.search(r'[a-z]', password):
        feedback.append("Add lowercase letters for better security.")
    if not re.search(r'[0-9]', password):
        feedback.append("Add numbers for better security.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        feedback.append("Add special characters (e.g., !, @, #) for stronger security.")
    #Check for common passwords or patterns
    common_passwords = ["123456", "password", "12345678", "qwerty", "abc123"]
    if password.lower() in common_passwords:
        feedback.append("This password is too common and easily guessed.")

    #If no issues were found, password is strong
    if not feedback:
        feedback.append("Password is strong!")

    return feedback

def analyze_gui(credentials):
    #Create a new window for password analysis
    analysis_window = ctk.CTk()
    analysis_window.title("Password Strength Analysis")
    analysis_window.geometry("600x400")
    analysis_window.resizable(False,False)

    analysis_textbox = ctk.CTkTextbox(analysis_window, height=350, width=580)
    analysis_textbox.place(y=25,x=10)

    # Analyze each password and display results
    for website, username, password in credentials:
        feedback = analyze_password_strength(password)
        analysis_textbox.insert(ctk.END, f"Website: {website}\nUsername: {username}\nPassword: {password}\n")
        for comment in feedback:
            analysis_textbox.insert(ctk.END, f"  - {comment}\n", ("weak" if "too" in comment or "add" in comment.lower() else "strong"))

        analysis_textbox.insert(ctk.END, "\n")

    #weak feedback in red
    analysis_textbox.tag_config("weak", foreground="red")
    #strong feedback in green
    analysis_textbox.tag_config("strong", foreground="green")

    analysis_window.mainloop()

def vault_gui():
    # Set up the GUI using customtkinter
    ctk.set_appearance_mode("dark")  
    ctk.set_default_color_theme("green")  

    app = ctk.CTk()  
    app.title("The Vault")  
    app.geometry("500x600") 
    app.resizable(False,False) 
    

    image_path = "vaultimage2.png"  
    vault_image = ctk.CTkImage(Image.open(image_path), size=(125, 125))  
    
    
    image_label = ctk.CTkLabel(app, image=vault_image, text="")
    image_label.place(y=155,x=190)

    def add_credentials():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if website and username and password:
            add_password(website, username, password, key)
            clear_status_label("Credentials added successfully!", status_label)
            website_entry.delete(0, ctk.END)
            username_entry.delete(0, ctk.END)
            password_entry.delete(0, ctk.END)
        else:
            clear_status_label("Please fill in all fields.", status_label)

    def show_credentials():
        credentials = load_passwords(key)
        credentials_textbox.configure(state="normal")
        credentials_textbox.delete("1.0", ctk.END)  
        for website, username, password in credentials:
            credentials_textbox.insert(ctk.END, f"Website: {website}\nUsername: {username}\nPassword: {password}\n\n")
        credentials_textbox.configure(state="disabled")

    def delete_credentials():
        website = delete_entry.get()
        if website:
            delete_password(website, key)
            show_credentials()
            clear_status_label(f"Credentials for {website} deleted successfully!", status_label)
            delete_entry.delete(0, ctk.END)
        else:
            clear_status_label("Please enter the website name to delete.", status_label)

    # GUI layout
    
    ctk.CTkLabel(app, text="The Vault", font=("Roboto", 28,"bold")).place(y=30,x=185)
    ctk.CTkLabel(app,text="V1.1",text_color="#90ee90",font=("Arial",10)).place(y=40,x=315)

    # Add credentials section
    ctk.CTkLabel(app, text="Add New Credentials").place(y=122,x=25)
    website_entry = ctk.CTkEntry(app, placeholder_text="Website")
    website_entry.place(y=154,x=15)
    username_entry = ctk.CTkEntry(app, placeholder_text="Username")
    username_entry.place(y=186,x=15)
    password_entry = ctk.CTkEntry(app, placeholder_text="Password", show="*")
    password_entry.place(y=218,x=15)
    ctk.CTkButton(app, text="Add", command=lambda: [add_credentials(),show_credentials()]).place(y=250,x=15)
    
    # seemless entry transisitioning!!!!!!!!!! 
    website_entry.bind("<Down>",focus_next_widget)
    website_entry.bind("<Up>",focus_previous_widget)
    username_entry.bind("<Down>",focus_next_widget)
    username_entry.bind("<Up>",focus_previous_widget)
    password_entry.bind("<Down>",focus_next_widget)
    password_entry.bind("<Up>",focus_previous_widget)

    # Show credentials 
    ctk.CTkLabel(app, text="Saved Credentials").place(y=300,x=200)
    credentials_textbox = ctk.CTkTextbox(app, height=225,width=425)
    credentials_textbox.place(y=330,x=37)
    ctk.CTkButton(app, text="Show", command=show_credentials).place(y=560,x=185)

    # Delete credentials
    ctk.CTkLabel(app, text="Delete Credentials").place(y=122,x=360)
    delete_entry = ctk.CTkEntry(app, placeholder_text="Website to delete")
    delete_entry.place(y=154,x=345)
    ctk.CTkButton(app, text="Delete", command=delete_credentials).place(y=186,x=344)
    # Example: Placing the button and passing status_label
    analyze_button = ctk.CTkButton(app, text="Analyze Passwords", command=lambda: analyze_gui(load_passwords(key)))
    analyze_button.place(y=218, x=344)
    ctk.CTkButton(app,text="Information",command=info_gui).place(y=250,x=344)

    # Status label
    status_label = ctk.CTkLabel(app, text="")
    status_label.pack(pady=70)

    app.mainloop()

def login_gui():
    login_window = ctk.CTk()
    login_window.title("Enter Master Password")
    login_window.geometry("300x175")
    login_window.resizable(False,False)
    ctk.set_appearance_mode("dark")  
    ctk.set_default_color_theme("green")
    image_path = "vaultimage2.png"  
    vault_image = ctk.CTkImage(Image.open(image_path), size=(60, 60))
    image_label = ctk.CTkLabel(login_window, image=vault_image, text="")
    image_label.pack()
    
    def check_password():

        entered_password = password_entry.get()
        # Correctly verify using the embedded MASTER_PASSWORD_HASH
        if verify_password(MASTER_PASSWORD_HASH.encode(), entered_password):
            login_window.destroy()  # Close the login window
            vault_gui()  # Open the main vault GUI
        else:
            error_label.configure(text="Incorrect password, Exiting application.")
            login_window.after(2000, lambda: login_window.destroy())

    # Layout for the login window
    ctk.CTkLabel(login_window, text="Enter Master Password:", font=("Roboto", 14,"bold")).pack(pady=10)
    password_entry = ctk.CTkEntry(login_window, show="*", placeholder_text="Master Password")
    password_entry.pack(pady=5)

    error_label = ctk.CTkLabel(login_window, text="")
    error_label.pack()

    login_window.bind('<Return>', lambda event: check_password())
    password_entry.focus()

    login_window.mainloop()

def info_gui():
    info_window = ctk.CTk()
    info_window.geometry("500x600")
    info_window.title("Security Information")
    info_window.resizable(False, False)
    
    protocol_info = """
    The Vault v1.1 Security Protocols:

    1. **Encryption Protocol: Fernet**
       - Symmetric encryption using AES (128-bit CBC mode).
       - Integrity and authenticity via HMAC with SHA256.
       - Used for encrypting stored credentials.

    2. **Hashing Protocol: Bcrypt**
       - Secure password hashing with Blowfish cipher.
       - Incorporates a salt and a configurable cost factor.
       - Used for hashing the master password.

    3. **Secure Storage: File-Based Encryption**
       - Encrypted credentials stored in 'passwords.enc'.
       - Only decrypted when correct master password is entered.

    4. **User Input Security**
       - Password fields are masked in the GUI.
       - Application access is protected by a master password.

    Together, these protocols protect your data from unauthorized access and 
    ensure that your credentials are safely stored.
    





    Made By Coleton B 
    """

    info_textbox = ctk.CTkTextbox(info_window, width=480, height=560, wrap="word")
    info_textbox.pack(padx=10, pady=10)

    info_textbox.insert(ctk.END, protocol_info)
    info_textbox.configure(state="disabled")  # Disable editing

    info_window.mainloop()

if __name__ == "__main__":
    key = load_key()

    login_gui()


