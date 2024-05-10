#pip install cryptography
from cryptography.fernet import Fernet
from sys import argv
def encrypt(msg):
    k = Fernet.generate_key()
    with open('fernet.key','wb') as fKey: fKey.write(k)
    f = Fernet(k)
    x = f.encrypt(msg)
    return x
    
def decrypt(msg):
    with open('fernet.key','r') as keyfile: k = keyfile.read()
    f = Fernet(k)
    x = f.decrypt(msg)
    return x

if len(argv) == 2 and argv[1] == '-e':
    message = input("Text to encrypt: ")
    print(encrypt(bytes(message, 'utf-8')).decode())
elif len(argv) == 2 and argv[1] == '-d':
    message = input("Text to decrypt: ")
    print(decrypt(bytes(message, 'utf-8')).decode())
elif len(argv) == 2 and argv[1] == '-ef':
    src = input("Source file path: ")
    dest = input("Destination file path: ")
    with open(src, 'rb') as srcFile: encFile = encrypt(srcFile.read())
    with open(dest, 'wb') as destFile: destFile.write(encFile)
elif len(argv) == 2 and argv[1] == '-df':
    src = input("Source file path: ")
    dest = input("Destination file path: ")
    with open(src, 'rb') as srcFile: decFile = decrypt(srcFile.read())
    with open(dest, 'wb') as destFile: destFile.write(decFile)
    