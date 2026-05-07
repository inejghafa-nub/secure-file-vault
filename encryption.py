import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SECRET_KEY = b'ThisIsA16ByteKey'  # 16 bytes = AES-128

def encrypt_file(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # store IV + ciphertext together

def decrypt_file(data: bytes) -> bytes:
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)