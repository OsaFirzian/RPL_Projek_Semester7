# hybrid_crypto.py (BACKEND UNTUK VERSION WEB, TIDAK ADA TKINTER)

import os
import struct
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# -------------------------
# PEMBANGKITAN DAN LOAD / SAVE KEY
# -------------------------
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key_to_file(private_key, filename, password: bytes = None):
    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo
    )
    with open(filename, "wb") as f:
        f.write(pem)


def save_public_key_to_file(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(pem)


def load_private_key_from_file(filename, password: bytes = None):
    with open(filename, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())


def load_public_key_from_file(filename):
    with open(filename, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())


# -------------------------
# HYBRID AES + RSA
# Format file terenkripsi:
# [4 byte len encrypted_key][4 byte len nonce][encrypted_key][nonce][ciphertext]
# -------------------------
def encrypt_file_with_rsa_aes(public_key, in_path, out_path):
    aes_key = secrets.token_bytes(32)              # AES-256
    nonce = secrets.token_bytes(12)               # 96-bit nonce for GCM
    aesgcm = AESGCM(aes_key)

    with open(in_path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext + tag

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(out_path, "wb") as f:
        f.write(struct.pack(">I", len(encrypted_key)))
        f.write(struct.pack(">I", len(nonce)))
        f.write(encrypted_key)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file_with_rsa_aes(private_key, in_path, out_path):
    with open(in_path, "rb") as f:
        header = f.read(8)
        if len(header) < 8:
            raise ValueError("File corrupted / header tidak lengkap")

        len_encrypted_key, len_nonce = struct.unpack(">II", header)
        encrypted_key = f.read(len_encrypted_key)
        nonce = f.read(len_nonce)
        ciphertext = f.read()

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(out_path, "wb") as f:
        f.write(plaintext)
