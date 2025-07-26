import os
import json
from cryptography.fernet import Fernet

DATA_FILE = 'vault.dat'

class VaultManager:
    def __init__(self):
        self.entries = []
        self.key = None

    def set_key(self, key):
        self.key = key

    def load(self):
        if not os.path.exists(DATA_FILE):
            self.entries = []
            return
        with open(DATA_FILE, 'rb') as f:
            encrypted = f.read()
        fernet = Fernet(self.key)
        decrypted = fernet.decrypt(encrypted)
        self.entries = json.loads(decrypted.decode())

    def save(self):
        fernet = Fernet(self.key)
        data = json.dumps(self.entries).encode()
        encrypted = fernet.encrypt(data)
        with open(DATA_FILE, 'wb') as f:
            f.write(encrypted)

    def add_entry(self, entry):
        self.entries.append(entry)
        self.save()

    def delete_entry(self, idx):
        del self.entries[idx]
        self.save()

    def update_entry(self, idx, entry):
        self.entries[idx] = entry
        self.save() 

#the user can update the entries
"""
six functionnalities in total, updating entries, delete, save,load,set the key 
"""

def list_entries(vault):
    """
    Display all entries stored in the vault.
    """
    if not vault.entries:
        print("The vault is empty.")
    else:
        for i, entry in enumerate(vault.entries):
            print(f"{i}: {entry}")

def search_entries(vault, keyword):
    """
    Search for entries containing a keyword.
    """
    results = [entry for entry in vault.entries if keyword.lower() in str(entry).lower()]
    if results:
        print("Search results:")
        for i, entry in enumerate(results):
            print(f"{i}: {entry}")
    else:
        print("No results found.")

def export_entries(vault, export_file='exported_vault.json'):
    """
    Export vault entries to a plaintext JSON file.
    """
    with open(export_file, 'w', encoding='utf-8') as f:
        json.dump(vault.entries, f, ensure_ascii=False, indent=4)
    print(f"Entries exported to '{export_file}'.")

def import_entries(vault, import_file='exported_vault.json'):
    """
    Import entries from an external JSON file.
    """
    if not os.path.exists(import_file):
        print(f"File '{import_file}' not found.")
        return
    with open(import_file, 'r', encoding='utf-8') as f:
        imported = json.load(f)
    if isinstance(imported, list):
        vault.entries.extend(imported)
        vault.save()
        print(f"{len(imported)} entries successfully imported.")
    else:
        print("Invalid format: the file must contain a list of entries.")

def clear_vault(vault):
    """
    Delete all entries from the vault.
    """
    vault.entries.clear()
    vault.save()
    print("All entries have been deleted.")

def backup_vault(filename='vault_backup.dat'):
    """
    Create a backup of the encrypted data file.
    """
    if os.path.exists(DATA_FILE):
        import shutil
        shutil.copy(DATA_FILE, filename)
        print(f"Backup created at '{filename}'.")
    else:
        print("No data file found to back up.")
