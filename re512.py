from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os


def encrypt(message, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    encoded_data = base64.b64encode(salt + iv + tag + ciphertext).decode('utf-8')
    return encoded_data


def decrypt(ciphertext, password):
    decoded_data = base64.b64decode(ciphertext)
    salt = decoded_data[:16]
    iv = decoded_data[16:28]
    tag = decoded_data[28:44]
    ciphertext = decoded_data[44:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')
