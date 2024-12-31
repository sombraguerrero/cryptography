#pip install cryptography
from cryptography.fernet import Fernet
from sys import argv
from os.path import exists

def encrypt(msg, kfname):
    if not exists(kfname):
        k = Fernet.generate_key()
        with open(kfname,'wb') as fKey: fKey.write(k)
    else:
        with open(kfname, 'r') as file: k = file.read()
    f = Fernet(k)
    x = f.encrypt(msg)
    return x
    
def decrypt(msg, kfname):
    with open(kfname,'r') as keyfile: k = keyfile.read()
    f = Fernet(k)
    x = f.decrypt(msg)
    return x

if len(argv) == 2 and argv[1] == '-e':
    kfilename = input("Key file name: ")
    message = input("Text to encrypt: ")
    print(encrypt(bytes(message, 'utf-8'), kfilename).decode())
elif len(argv) == 2 and argv[1] == '-d':
    kfilename = input("Key file name: ")
    message = input("Text to decrypt: ")
    print(decrypt(bytes(message, 'utf-8'), kfilename).decode())
elif len(argv) == 2 and argv[1] == '-ef':
    kfilename = input("Key file name: ")
    src = input("Source file path: ")
    dest = input("Destination file path: ")
    with open(src, 'rb') as srcFile: encFile = encrypt(srcFile.read(), kfilename)
    with open(dest, 'wb') as destFile: destFile.write(encFile)
elif len(argv) == 2 and argv[1] == '-df':
    kfilename = input("Key file name: ")
    src = input("Source file path: ")
    dest = input("Destination file path: ")
    with open(src, 'rb') as srcFile: decFile = decrypt(srcFile.read(), kfilename)
    with open(dest, 'wb') as destFile: destFile.write(decFile)
    