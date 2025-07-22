import os
import json
import base64
import hashlib
import secrets

CONFIG_FILE = 'config.json'
PBKDF2_ITERATIONS = 200_000

class AuthManager:
    def __init__(self):
        pass

    def hash_password(self, password, salt):
        return hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt, PBKDF2_ITERATIONS
        )

    def set_master_password(self, password):
        salt = secrets.token_bytes(16)
        pwd_hash = self.hash_password(password, salt)
        config = {
            'salt': base64.b64encode(salt).decode(),
            'pwd_hash': base64.b64encode(pwd_hash).decode(),
            'iterations': PBKDF2_ITERATIONS
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    def verify_master_password(self, password):
        if not os.path.exists(CONFIG_FILE):
            return False
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        salt = base64.b64decode(config['salt'])
        stored_hash = base64.b64decode(config['pwd_hash'])
        test_hash = self.hash_password(password, salt)
        return secrets.compare_digest(stored_hash, test_hash)

    def derive_key(self, password):
        if not os.path.exists(CONFIG_FILE):
            raise Exception('Config file missing!')
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        salt = base64.b64decode(config['salt'])
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=32)
        return base64.urlsafe_b64encode(key) 