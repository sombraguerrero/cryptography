#pip install cryptography
from cryptography.fernet import Fernet
k = Fernet.generate_key()
with open('fernet.key','wb') as fKey: fKey.write(k)
f = Fernet(Fernet.generate_key()) # base64.urlsafe_b64encode(os.urandom(32))
someFile = input('File to process: ')
message = input('Text to process: ')
with open(someFile,'rb') as img: token1 = f.encrypt(img.read())
with open('encrypted_img.dat','wb') as cipherImg: cipherImg.write(token1)
with open('encrypted_img.dat','rb') as readCipherImg: cipherImgBytes = readCipherImg.read()
with open('decrypted_img.jpg','wb') as decImg: decImg.write(f.decrypt(cipherImgBytes))
with open('fernet.key', 'r') as kfile: key2 = kfile.read()
f2 = Fernet(key2)
token2 = f2.encrypt(bytes(message, 'utf-8'))
print(token2.decode())
print(f2.decrypt(token2).decode())