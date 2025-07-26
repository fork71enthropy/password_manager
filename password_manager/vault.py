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