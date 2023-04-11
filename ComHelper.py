import json
import socket
import pyscrypt
import random
import hashlib
from Crypto.Cipher import AES


def generate_salt(passwd: str) -> bytes:
    return hashlib.sha256(passwd.encode()).digest()


def create_key_from_passwd(passwd: str) -> bytes:
    salt = generate_salt(passwd)
    key = pyscrypt.hash(passwd.encode(), salt, 128, 8, 1, 32)
    return key


def encrypt_AES(key: bytes, text: str) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted = cipher.encrypt(text.encode()).hex()
    e = json.dumps({"nonce": cipher.nonce.hex(), "msg": encrypted}).encode()
    return e


def decrypt_AES(nonce: bytes, key: bytes, text: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt(text)


def receive_msg(soc: socket) -> bytes:
    length = soc.recv(4)
    return soc.recv(int.from_bytes(length, 'little'))


def send_msg(soc: socket, msg):
    soc.send(len(msg).to_bytes(4, 'little'))
    soc.send(msg)


if __name__ == '__main__':
    p = create_key_from_passwd("password")
    print(p)
    nonce, enc = encrypt_AES(p, "hello")
    print(enc)
    text = decrypt_AES(nonce, p, enc)
    print(text)
