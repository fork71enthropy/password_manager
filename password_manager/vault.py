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
    Affiche les entrées actuelles du coffre.
    """
    if not vault.entries:
        print("Le coffre est vide.")
    else:
        for i, entry in enumerate(vault.entries):
            print(f"{i}: {entry}")

def search_entries(vault, keyword):
    """
    Recherche et affiche les entrées contenant un mot-clé.
    """
    results = [entry for entry in vault.entries if keyword.lower() in str(entry).lower()]
    if results:
        print("Résultats de recherche :")
        for i, entry in enumerate(results):
            print(f"{i}: {entry}")
    else:
        print("Aucun résultat trouvé.")

def export_entries(vault, export_file='exported_vault.json'):
    """
    Exporte les entrées en clair dans un fichier JSON.
    """
    with open(export_file, 'w', encoding='utf-8') as f:
        json.dump(vault.entries, f, ensure_ascii=False, indent=4)
    print(f"Entrées exportées dans {export_file}")

def import_entries(vault, import_file='exported_vault.json'):
    """
    Importe des entrées depuis un fichier JSON externe.
    """
    if not os.path.exists(import_file):
        print(f"Fichier {import_file} introuvable.")
        return
    with open(import_file, 'r', encoding='utf-8') as f_
