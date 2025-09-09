from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import showwarning
from hashlib import sha3_512
from os import urandom
from base64 import b64encode, b64decode
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class AES_Util(Tk):
    def __init__(self):
        super().__init__()
        self.salt = urandom(16)
        self.keyLength = 32
        self.ivLength = 16
        self.iv = []
        self.key = []
        # configure the root window
        self.title('AES-EVP Utility')
        self.geometry("1024x500")
        self.methodSel = StringVar(value='encrypt');
        self.digestSel = StringVar(value='SHA3-512');
        self.encryptBtn = Radiobutton(text='Encrypt', variable=self.methodSel, value='encrypt',font=('Aptos',12)).grid(row=1,column=0)
        self.decryptBtn = Radiobutton(text='Decrypt', variable=self.methodSel, value='decrypt',font=('Aptos',12)).grid(row=1,column=1)
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
                self.outputTxt.insert('1.0', b64encode(b'Salted__' + self.salt + self.encrypt()).decode())
            elif self.methodSel.get() == 'decrypt':
                self.outputTxt.insert('1.0', self.decrypt().decode())
        else:
            showwarning(title='Invalid input', message='No text in input field!')
            
    def select_all(self, event):
        event.widget.tag_add(SEL, "1.0", END)
        event.widget.mark_set(INSERT, "1.0")
        event.widget.see(INSERT)
        return 'break'
        
    """
    Derive the key and the IV from the given password and salt.
    """
    def EVP_BytesToKey(self):
         password = bytes(self.password.get(), 'utf-8')
         dtot = sha3_512(password + self.salt).digest()
         d = [dtot]
         while len(dtot) < (self.ivLength + self.keyLength):
             d.append(sha3_512(d[-1] + password + self.salt).digest())
             dtot += d[-1]
             
         self.key = dtot[:self.keyLength]
         self.iv = dtot[self.keyLength:self.keyLength + self.ivLength]
         
    def encrypt(self):
        self.EVP_BytesToKey()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(bytes(self.inputTxt.get('1.0','end-1c'),'utf-8')) + padder.finalize()
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
    def decrypt(self):
        parsedData = b64decode(self.inputTxt.get('1.0', 'end-1c'))
        sr = BytesIO()
        sr.write(parsedData)
        sr.seek(8)
        self.salt = sr.read(16)
        self.EVP_BytesToKey()
        cipherData = sr.read()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        ct = decryptor.update(cipherData) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(ct) + unpadder.finalize()
        return unpadded_data


    
if __name__ == "__main__":
    form1 = AES_Util()
    form1.mainloop()