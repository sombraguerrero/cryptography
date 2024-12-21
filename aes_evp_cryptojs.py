from hashlib import md5
from base64 import b64decode
from io import BytesIO
from os import getenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

"""
Derive the key and the IV from the given password and salt.
"""
def EVP_BytesToKey(mySalt):
    password = bytes(getenv('gc_pwd'), 'utf-8')
    dtot = md5(password + mySalt).digest()
    d = [dtot]
    while len(dtot) < 48:
        d.append(md5(d[-1] + password + mySalt).digest())
        dtot += d[-1]
    key = dtot[:32]
    iv = dtot[32:48]
    return key, iv
    
def decrypt(myText):
    parsedData = b64decode(myText)
    sr = BytesIO()
    sr.write(parsedData)
    sr.seek(8)
    salt = sr.read(8)
    key, iv = EVP_BytesToKey(salt)
    cipherData = sr.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    ct = decryptor.update(cipherData) + decryptor.finalize()
    return ct
    
myInput = input("Text to decrypt: ");
print(decrypt(myInput).decode())