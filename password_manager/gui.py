import tkinter as tk
from tkinter import messagebox
from vault import VaultManager
from auth import AuthManager
from utils import copy_to_clipboard, generate_password
import threading
import time

# Main GUI launcher

def launch_app():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

class PasswordManagerApp:
    AUTOLOCK_SECONDS = 120

    def __init__(self, root):
        self.root = root
        self.root.title('Password Manager')
        self.root.geometry('500x400')
        self.auth = AuthManager()
        self.vault = VaultManager()
        self.master_password = None
        self.key = None
        self.search_var = tk.StringVar()
        self.filtered_indices = []
        self.last_activity = time.time()
        self.autolock_timer = None
        self.setup_ui()
        self.start_autolock_timer()
        self.root.bind_all('<Any-KeyPress>', self.reset_autolock)
        self.root.bind_all('<Any-Button>', self.reset_autolock)

    def start_autolock_timer(self):
        if self.autolock_timer:
            self.root.after_cancel(self.autolock_timer)
        self.check_autolock()

    def check_autolock(self):
        if self.master_password and (time.time() - self.last_activity > self.AUTOLOCK_SECONDS):
            self.lock()
        else:
            self.autolock_timer = self.root.after(1000, self.check_autolock)

    def reset_autolock(self, event=None):
        self.last_activity = time.time()

    def setup_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        if not self.auth_config_exists():
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

    def auth_config_exists(self):
        import os
        return os.path.exists('config.json')

    def set_password(self):
        pwd = self.master_entry.get()
        confirm = self.confirm_entry.get()
        if not pwd or not confirm:
            messagebox.showerror('Error', 'Please fill both fields.')
            return
        if pwd != confirm:
            messagebox.showerror('Error', 'Passwords do not match.')
            return
        self.auth.set_master_password(pwd)
        messagebox.showinfo('Success', 'Master password set! Please log in.')
        self.setup_ui()

    def unlock(self):
        pwd = self.master_entry.get()
        if not pwd:
            messagebox.showerror('Error', 'Please enter your master password.')
            return
        if self.auth.verify_master_password(pwd):
            self.master_password = pwd
            self.key = self.auth.derive_key(pwd)
            self.vault.set_key(self.key)
            try:
                self.vault.load()
            except Exception as e:
                messagebox.showerror('Error', f'Failed to decrypt vault: {e}')
                self.vault.entries = []
            self.show_vault_ui()
        else:
            messagebox.showerror('Error', 'Incorrect master password.')

    def show_vault_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text='Password Vault', font=('Arial', 16)).pack(pady=10)
        # Search bar
        search_frame = tk.Frame(self.root)
        search_frame.pack(pady=5)
        tk.Label(search_frame, text='Search:').pack(side='left')
        search_entry = tk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side='left', padx=5)
        search_entry.bind('<KeyRelease>', lambda e: self.refresh_entries())
        # Entries list
        self.entries_listbox = tk.Listbox(self.root, width=60)
        self.entries_listbox.pack(pady=10)
        self.refresh_entries()
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text='Add Entry', command=self.add_entry_dialog).pack(side='left', padx=5)
        tk.Button(btn_frame, text='Edit Entry', command=self.edit_entry_dialog).pack(side='left', padx=5)
        tk.Button(btn_frame, text='View Entry', command=self.view_entry_dialog).pack(side='left', padx=5)
        tk.Button(btn_frame, text='Delete Entry', command=self.delete_entry).pack(side='left', padx=5)
        tk.Button(btn_frame, text='Copy Password', command=self.copy_password).pack(side='left', padx=5)
        tk.Button(btn_frame, text='Lock', command=self.lock).pack(side='left', padx=5)

    def refresh_entries(self):
        self.entries_listbox.delete(0, tk.END)
        query = self.search_var.get().lower()
        self.filtered_indices = []
        for idx, entry in enumerate(self.vault.entries):
            display = f"{entry.get('site','')} | {entry.get('username','')}"
            if not query or query in display.lower():
                self.entries_listbox.insert(tk.END, display)
                self.filtered_indices.append(idx)

    def get_selected_entry_index(self):
        sel = self.entries_listbox.curselection()
        if not sel:
            return None
        listbox_idx = sel[0]
        if listbox_idx >= len(self.filtered_indices):
            return None
        return self.filtered_indices[listbox_idx]

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
        def generate():
            pwd_entry.delete(0, tk.END)
            pwd_entry.insert(0, generate_password())
        tk.Button(dialog, text='Generate Password', command=generate).grid(row=2, column=2, padx=5)
        def save():
            entry = {
                'site': site_entry.get(),
                'username': user_entry.get(),
                'password': pwd_entry.get(),
                'notes': notes_entry.get()
            }
            self.vault.add_entry(entry)
            self.refresh_entries()
            dialog.destroy()
        tk.Button(dialog, text='Save', command=save).grid(row=4, column=0, columnspan=3, pady=5)

    def edit_entry_dialog(self):
        idx = self.get_selected_entry_index()
        if idx is None:
            messagebox.showerror('Error', 'Select an entry to edit.')
            return
        entry = self.vault.entries[idx]
        dialog = tk.Toplevel(self.root)
        dialog.title('Edit Entry')
        tk.Label(dialog, text='Site:').grid(row=0, column=0, sticky='e')
        tk.Label(dialog, text='Username:').grid(row=1, column=0, sticky='e')
        tk.Label(dialog, text='Password:').grid(row=2, column=0, sticky='e')
        tk.Label(dialog, text='Notes:').grid(row=3, column=0, sticky='e')
        site_entry = tk.Entry(dialog)
        user_entry = tk.Entry(dialog)
        pwd_entry = tk.Entry(dialog)
        notes_entry = tk.Entry(dialog)
        site_entry.insert(0, entry.get('site',''))
        user_entry.insert(0, entry.get('username',''))
        pwd_entry.insert(0, entry.get('password',''))
        notes_entry.insert(0, entry.get('notes',''))
        site_entry.grid(row=0, column=1)
        user_entry.grid(row=1, column=1)
        pwd_entry.grid(row=2, column=1)
        notes_entry.grid(row=3, column=1)
        def generate():
            pwd_entry.delete(0, tk.END)
            pwd_entry.insert(0, generate_password())
        tk.Button(dialog, text='Generate Password', command=generate).grid(row=2, column=2, padx=5)
        def save():
            new_entry = {
                'site': site_entry.get(),
                'username': user_entry.get(),
                'password': pwd_entry.get(),
                'notes': notes_entry.get()
            }
            self.vault.update_entry(idx, new_entry)
            self.refresh_entries()
            dialog.destroy()
        tk.Button(dialog, text='Save', command=save).grid(row=4, column=0, columnspan=3, pady=5)

    def view_entry_dialog(self):
        idx = self.get_selected_entry_index()
        if idx is None:
            messagebox.showerror('Error', 'Select an entry to view.')
            return
        entry = self.vault.entries[idx]
        dialog = tk.Toplevel(self.root)
        dialog.title('View Entry')
        tk.Label(dialog, text=f"Site: {entry.get('site','')}").pack(anchor='w')
        tk.Label(dialog, text=f"Username: {entry.get('username','')}").pack(anchor='w')
        tk.Label(dialog, text=f"Password: {entry.get('password','')}").pack(anchor='w')
        tk.Button(dialog, text='Copy Password', command=lambda: [copy_to_clipboard(entry.get('password','')), messagebox.showinfo('Copied', 'Password copied to clipboard. It will be cleared in 15 seconds.'), dialog.after(15000, self.clear_clipboard)]).pack(pady=2)
        tk.Label(dialog, text=f"Notes: {entry.get('notes','')}").pack(anchor='w')
        tk.Button(dialog, text='Close', command=dialog.destroy).pack(pady=5)

    def delete_entry(self):
        idx = self.get_selected_entry_index()
        if idx is None:
            messagebox.showerror('Error', 'Select an entry to delete.')
            return
        if messagebox.askyesno('Confirm', 'Delete this entry?'):
            self.vault.delete_entry(idx)
            self.refresh_entries()

    def lock(self):
        self.master_password = None
        self.key = None
        self.vault.entries = []
        self.setup_ui()

    def copy_password(self):
        idx = self.get_selected_entry_index()
        if idx is None:
            messagebox.showerror('Error', 'Select an entry to copy password.')
            return
        entry = self.vault.entries[idx]
        password = entry.get('password', '')
        if not password:
            messagebox.showerror('Error', 'No password to copy.')
            return
        copy_to_clipboard(password)
        messagebox.showinfo('Copied', 'Password copied to clipboard. It will be cleared in 15 seconds.')
        self.root.after(15000, self.clear_clipboard)

    def clear_clipboard(self):
        self.root.clipboard_clear() 