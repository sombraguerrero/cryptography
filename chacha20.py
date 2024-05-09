#pip install cryptography
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode
from uuid import uuid4
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pickle import dump, load
from sys import argv
    
def encrypt(msg):
    crypto = {'authData': uuid4().bytes, 'nonce': urandom(12), 'key': ChaCha20Poly1305.generate_key()}
    with open('crypto.pickle', 'wb') as file: dump(crypto, file)
    aad = crypto['authData']
    # keyfile = open('chacha_key.dat','rb')
    key = crypto['key']
    chacha = ChaCha20Poly1305(key)
    nonce = crypto['nonce']
    ct = chacha.encrypt(nonce, msg, aad)
    return ct
    
def decrypt_text(msg):
    with open('crypto.pickle', 'rb') as file: crypto = load(file)
    aad = crypto['authData']
    # keyfile = open('chacha_key.dat','rb')
    key = crypto['key']
    chacha = ChaCha20Poly1305(key)
    nonce = crypto['nonce']
    ct = chacha.decrypt(nonce, urlsafe_b64decode(msg), aad)
    return ct.decode()
    
def decrypt_file(msg):
    with open('crypto.pickle', 'rb') as file: crypto = load(file)
    aad = crypto['authData']
    # keyfile = open('chacha_key.dat','rb')
    key = crypto['key']
    chacha = ChaCha20Poly1305(key)
    nonce = crypto['nonce']
    ct = chacha.decrypt(nonce, msg, aad)
    return ct

if len(argv) == 2 and argv[1] == '-e':
    message = input("Text to encrypt: ")
    print(urlsafe_b64encode(encrypt(bytes(message, 'utf-8'))).decode())
elif len(argv) == 2 and argv[1] == '-d':
    message = input("Text to decrypt: ")
    print(decrypt_text(bytes(message, 'utf-8')))
elif len(argv) == 2 and argv[1] == '-ef':
    src = input("Source file path: ")
    dest = input("Destination file path: ")
    with open(src, 'rb') as srcFile: encFile = encrypt(srcFile.read())
    with open(dest, 'wb') as destFile: destFile.write(encFile)
elif len(argv) == 2 and argv[1] == '-df':
    src = input("Source file path: ")
    dest = input("Destination file path: ")
    with open(src, 'rb') as srcFile: decFile = decrypt_file(srcFile.read())
    with open(dest, 'wb') as destFile: destFile.write(decFile)
