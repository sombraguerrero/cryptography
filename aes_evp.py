from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import showwarning
from hashlib import md5, sha256, sha3_512
from os import urandom
from base64 import b64encode, b64decode
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class AES_Util(Tk):
    def __init__(self):
        super().__init__()
        self.iv = []
        self.ivLength = 16
        self.key = []
        self.keyLength = 32
        self.salt = bytes()
        # configure the root window
        self.title('AES-EVP Utility')
        self.geometry("1152x480")
        self.methodSel = StringVar(value='encrypt');
        self.digestSel = IntVar(value=3);
        self.onDigestChanged()
        self.md5Btn = Radiobutton(text='Level 1', variable=self.digestSel, value=1,font=('Aptos',12),command=self.onDigestChanged).grid(row=1,column=0)
        self.sha256Btn = Radiobutton(text='Level 2', variable=self.digestSel, value=2,font=('Aptos',12),command=self.onDigestChanged).grid(row=1,column=1)
        self.sha3Btn = Radiobutton(text='Level 3', variable=self.digestSel, value=3,font=('Aptos',12),command=self.onDigestChanged).grid(row=1,column=2)
        self.encryptBtn = Radiobutton(text='Encrypt', variable=self.methodSel, value='encrypt',font=('Aptos',12)).grid(row=2,column=0)
        self.decryptBtn = Radiobutton(text='Decrypt', variable=self.methodSel, value='decrypt',font=('Aptos',12)).grid(row=2,column=1)
        self.pwdLabel = Label(text="Enter the Password", font=('Aptos',12)).grid(row=3, column=0)
        self.password= Entry(show="*",width=60)
        self.password.grid(row=3, column=1)
        self.inputLabel = Label(text="Input", font=('Aptos',12)).grid(row=4,column=0)
        self.inputTxt = ScrolledText(width=100,height=10)
        self.inputTxt.grid(row=4,column=1) # Important to do the layout calls separately when you want the widget to be referenceable because they return null
        self.inputLabel = Label(text="Output", font=('Aptos',12)).grid(row=5,column=0)
        self.outputTxt = ScrolledText(width=100,height=10)
        self.outputTxt.grid(row=5,column=1) # Important to do the layout calls separately when you want the widget to be referenceable because they return null
        self.inputTxt.bind("<Control-Key-a>", self.select_all)
        self.inputTxt.bind("<Control-Key-a>", self.select_all)
        self.outputTxt.bind("<Control-Key-a>", self.select_all)
        self.outputTxt.bind("<Control-Key-a>", self.select_all)
        self.submitBtn = Button(text="Process Text", font=('Aptos',12),command=self.onSubmitText).grid(row=6,column=0)
        
    def onSubmitText(self):
        self.outputTxt.delete('1.0','end')
        if self.inputTxt.compare("end-1c", "!=", "1.0"):
            if self.methodSel.get() == 'encrypt':
                self.outputTxt.insert('1.0', b64encode(self.encrypt()).decode())
            elif self.methodSel.get() == 'decrypt':
                self.outputTxt.insert('1.0', self.decrypt().decode())
        else:
            showwarning(title='Invalid input', message='No text in input field!')
            
    def select_all(self, event):
        event.widget.tag_add(SEL, "1.0", END)
        event.widget.mark_set(INSERT, "1.0")
        event.widget.see(INSERT)
        return 'break'
    
    def onDigestChanged(self):
        sel = self.digestSel.get()
        if sel == 1:          # MD5
            self.saltSize = 8
            self.digestFunc = md5
        elif sel == 2:        # SHA-256
            self.saltSize = 8
            self.digestFunc = sha256
        else:                 # SHA3-512
            self.saltSize = 16
            self.digestFunc = sha3_512
            
    """
    Derive the key and the IV from the given password and salt.
    """
    def EVP_BytesToKey(self, genSalt):
        password = self.password.get().encode('utf-8')
        if genSalt:
            self.salt = urandom(self.saltSize)
            
        dtot = self.digestFunc(password + self.salt).digest()
        d = [dtot]
        
        while len(dtot) < (self.keyLength + self.ivLength):
            d.append(self.digestFunc(d[-1] + password + self.salt).digest())
            dtot += d[-1]
        self.key = dtot[:self.keyLength]
        self.iv = dtot[self.keyLength:self.keyLength + self.ivLength]

    def encrypt(self):
        self.EVP_BytesToKey(True)  # generates salt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(self.inputTxt.get('1.0','end-1c').encode()) + padder.finalize() # Only the cipher text should be padded
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded) + encryptor.finalize() # Only the padded cipher text should be fed into the encryptor
        # Atomic construction of the OpenSSL-style blob
        return b"Salted__" + self.salt + ct

    def decrypt(self):
        parsed = b64decode(self.inputTxt.get('1.0','end-1c'))
        sr = BytesIO(parsed)
        sr.seek(8)  # skip "Salted__"
        # Read salt based on digest selection
        self.salt = sr.read(self.saltSize)
        self.EVP_BytesToKey(False)
        cipherData = sr.read()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(cipherData) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

if __name__ == "__main__":
    form1 = AES_Util()
    form1.mainloop()
    