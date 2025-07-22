import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import os
import json
import base64
import hashlib
import secrets

# Constants
KEY_FILE = 'key.key'  # Not used anymore, but kept for reference
DATA_FILE = 'vault.dat'
CONFIG_FILE = 'config.json'
PBKDF2_ITERATIONS = 200_000

# --- Master Password Logic ---
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt, PBKDF2_ITERATIONS
    )

def set_master_password(password):
    salt = secrets.token_bytes(16)
    pwd_hash = hash_password(password, salt)
    config = {
        'salt': base64.b64encode(salt).decode(),
        'pwd_hash': base64.b64encode(pwd_hash).decode(),
        'iterations': PBKDF2_ITERATIONS
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def verify_master_password(password):
    if not os.path.exists(CONFIG_FILE):
        return False
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
    salt = base64.b64decode(config['salt'])
    stored_hash = base64.b64decode(config['pwd_hash'])
    test_hash = hash_password(password, salt)
    return secrets.compare_digest(stored_hash, test_hash)

def derive_key(password):
    if not os.path.exists(CONFIG_FILE):
        raise Exception('Config file missing!')
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
    salt = base64.b64decode(config['salt'])
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(key)

# --- GUI Logic ---
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Password Manager')
        self.root.geometry('500x400')
        self.master_password = None
        self.key = None
        self.vault = []
        self.setup_ui()

    def setup_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        if not os.path.exists(CONFIG_FILE):
            # First run: set master password
            tk.Label(self.root, text='Set Master Password:').pack(pady=10)
            self.master_entry = tk.Entry(self.root, show='*')
            self.master_entry.pack(pady=5)
            tk.Label(self.root, text='Confirm Password:').pack(pady=10)
            self.confirm_entry = tk.Entry(self.root, show='*')
            self.confirm_entry.pack(pady=5)
            tk.Button(self.root, text='Set Password', command=self.set_password).pack(pady=10)
        else:
            # Subsequent runs: verify master password
            tk.Label(self.root, text='Enter Master Password:').pack(pady=10)
            self.master_entry = tk.Entry(self.root, show='*')
            self.master_entry.pack(pady=5)
            tk.Button(self.root, text='Unlock', command=self.unlock).pack(pady=10)

    def set_password(self):
        pwd = self.master_entry.get()
        confirm = self.confirm_entry.get()
        if not pwd or not confirm:
            messagebox.showerror('Error', 'Please fill both fields.')
            return
        if pwd != confirm:
            messagebox.showerror('Error', 'Passwords do not match.')
            return
        set_master_password(pwd)
        messagebox.showinfo('Success', 'Master password set! Please log in.')
        self.setup_ui()

    def unlock(self):
        pwd = self.master_entry.get()
        if not pwd:
            messagebox.showerror('Error', 'Please enter your master password.')
            return
        if verify_master_password(pwd):
            self.master_password = pwd
            self.key = derive_key(pwd)
            self.load_vault()
            self.show_vault_ui()
        else:
            messagebox.showerror('Error', 'Incorrect master password.')

    # --- Vault Encryption/Decryption ---
    def load_vault(self):
        if not os.path.exists(DATA_FILE):
            self.vault = []
            return
        with open(DATA_FILE, 'rb') as f:
            encrypted = f.read()
        try:
            fernet = Fernet(self.key)
            decrypted = fernet.decrypt(encrypted)
            self.vault = json.loads(decrypted.decode())
        except Exception as e:
            messagebox.showerror('Error', 'Failed to decrypt vault. Wrong password or corrupted file.')
            self.vault = []

    def save_vault(self):
        fernet = Fernet(self.key)
        data = json.dumps(self.vault).encode()
        encrypted = fernet.encrypt(data)
        with open(DATA_FILE, 'wb') as f:
            f.write(encrypted)

    # --- Main Vault UI ---
    def show_vault_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text='Password Vault', font=('Arial', 16)).pack(pady=10)
        self.entries_listbox = tk.Listbox(self.root, width=60)
        self.entries_listbox.pack(pady=10)
        self.refresh_entries()
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text='Add Entry', command=self.add_entry_dialog).pack(side='left', padx=5)
        tk.Button(btn_frame, text='View Entry', command=self.view_entry_dialog).pack(side='left', padx=5)
        tk.Button(btn_frame, text='Delete Entry', command=self.delete_entry).pack(side='left', padx=5)
        tk.Button(btn_frame, text='Lock', command=self.lock).pack(side='left', padx=5)

    def refresh_entries(self):
        self.entries_listbox.delete(0, tk.END)
        for idx, entry in enumerate(self.vault):
            display = f"{entry.get('site','')} | {entry.get('username','')}"
            self.entries_listbox.insert(tk.END, display)

    def add_entry_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title('Add Entry')
        tk.Label(dialog, text='Site:').grid(row=0, column=0, sticky='e')
        tk.Label(dialog, text='Username:').grid(row=1, column=0, sticky='e')
        tk.Label(dialog, text='Password:').grid(row=2, column=0, sticky='e')
        tk.Label(dialog, text='Notes:').grid(row=3, column=0, sticky='e')
        site_entry = tk.Entry(dialog)
        user_entry = tk.Entry(dialog)
        pwd_entry = tk.Entry(dialog)
        notes_entry = tk.Entry(dialog)
        site_entry.grid(row=0, column=1)
        user_entry.grid(row=1, column=1)
        pwd_entry.grid(row=2, column=1)
        notes_entry.grid(row=3, column=1)
        def save():
            entry = {
                'site': site_entry.get(),
                'username': user_entry.get(),
                'password': pwd_entry.get(),
                'notes': notes_entry.get()
            }
            self.vault.append(entry)
            self.save_vault()
            self.refresh_entries()
            dialog.destroy()
        tk.Button(dialog, text='Save', command=save).grid(row=4, column=0, columnspan=2, pady=5)

    def view_entry_dialog(self):
        sel = self.entries_listbox.curselection()
        if not sel:
            messagebox.showerror('Error', 'Select an entry to view.')
            return
        idx = sel[0]
        entry = self.vault[idx]
        dialog = tk.Toplevel(self.root)
        dialog.title('View Entry')
        tk.Label(dialog, text=f"Site: {entry.get('site','')}").pack(anchor='w')
        tk.Label(dialog, text=f"Username: {entry.get('username','')}").pack(anchor='w')
        tk.Label(dialog, text=f"Password: {entry.get('password','')}").pack(anchor='w')
        tk.Label(dialog, text=f"Notes: {entry.get('notes','')}").pack(anchor='w')
        tk.Button(dialog, text='Close', command=dialog.destroy).pack(pady=5)

    def delete_entry(self):
        sel = self.entries_listbox.curselection()
        if not sel:
            messagebox.showerror('Error', 'Select an entry to delete.')
            return
        idx = sel[0]
        if messagebox.askyesno('Confirm', 'Delete this entry?'):
            del self.vault[idx]
            self.save_vault()
            self.refresh_entries()

    def lock(self):
        self.master_password = None
        self.key = None
        self.vault = []
        self.setup_ui()

def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == '__main__':
    main() 