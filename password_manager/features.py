import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import re

def export_vault(vault_entries):
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON Files', '*.json')])
    if not file_path:
        return
    try:
        with open(file_path, 'w') as f:
            json.dump(vault_entries, f, indent=2)
        messagebox.showinfo('Export', f'Vault exported to {file_path}')
    except Exception as e:
        messagebox.showerror('Export Error', str(e))

def import_vault():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(filetypes=[('JSON Files', '*.json')])
    if not file_path:
        return None
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        messagebox.showinfo('Import', f'Vault imported from {file_path}')
        return data
    except Exception as e:
        messagebox.showerror('Import Error', str(e))
        return None

def password_strength(password):
    score = 0
    length = len(password)
    if length >= 8:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^A-Za-z0-9]', password):
        score += 1
    return score  # 0 (faible) à 5 (très fort) 