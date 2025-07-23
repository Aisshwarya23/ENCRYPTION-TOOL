from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64, os

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + encrypted_data)

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        content = f.read()
    salt = content[:16]
    encrypted_data = content[16:]
    key = generate_key(password, salt)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path.replace('.enc', '.dec'), 'wb') as f:
        f.write(decrypted_data)
