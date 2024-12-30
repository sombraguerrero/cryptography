from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.messagebox import showwarning
from os import urandom
from os.path import exists
from base64 import urlsafe_b64encode, urlsafe_b64decode
from uuid import uuid4
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pickle import dump, load

class AES_Util(Tk):
    DefaultKeyPath = 'aesgcm.key'
    def __init__(self):
        super().__init__()
        # configure the root window
        self.title('AES-GCM Utility')
        self.geometry("1024x500")
        self.radioSel = StringVar(value='encrypt');
        self.keyPromptVal = IntVar()
        self.genKeyVal = IntVar()
        self.encryptBtn = Radiobutton(text='Encrypt', variable=self.radioSel, value='encrypt',font=('Aptos',12)).grid(row=1,column=0)
        self.decryptBtn = Radiobutton(text='Decrypt', variable=self.radioSel, value='decrypt',font=('Aptos',12)).grid(row=1,column=1)
        self.keyPrompt = Checkbutton(text='Prompt for key file',variable=self.keyPromptVal, onvalue=1, offvalue=0,font=('Aptos',12))
        self.keyPrompt.grid(row=2,column=1)
        self.genKeyPrompt = Checkbutton(text='Generate encryption key',variable=self.genKeyVal, onvalue=1, offvalue=0,font=('Aptos',12))
        self.genKeyPrompt.grid(row=2,column=0)
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
        self.fileBtn = Button(text="Process Files", font=('Aptos',12),command=self.onSubmitFile).grid(row=7,column=0)
        
    def onSubmitText(self):
        self.outputTxt.delete('1.0','end')
        if self.inputTxt.compare("end-1c", "!=", "1.0"):
            if self.radioSel.get() == 'encrypt':
                self.outputTxt.insert('1.0', urlsafe_b64encode(self.encrypt(bytes(self.inputTxt.get('1.0','end'), 'utf-8'))).decode())
            elif self.radioSel.get() == 'decrypt':
                self.outputTxt.insert('1.0', self.decrypt(urlsafe_b64decode(self.inputTxt.get('1.0','end'))).decode())
        else:
            showwarning(title='Invalid input', message='No text in input field!')
            
    def select_all(self, event):
        event.widget.tag_add(SEL, "1.0", END)
        event.widget.mark_set(INSERT, "1.0")
        event.widget.see(INSERT)
        return 'break'
        
            
    def onSubmitFile(self):
        self.open_save_file()
        if self.radioSel.get() == 'encrypt':
            with open(self.inputTxt.get('1.0', 'end-1c'), 'rb') as srcFile: encFile = self.encrypt(srcFile.read())
            with open(self.outputTxt.get('1.0', 'end-1c'), 'wb') as destFile: destFile.write(encFile)
        else:
            with open(self.inputTxt.get('1.0', 'end-1c'), 'rb') as srcFile: decFile = self.decrypt(srcFile.read())
            with open(self.outputTxt.get('1.0', 'end-1c'), 'wb') as destFile: destFile.write(decFile)
            
    def open_save_key(self, newKey):
        if newKey == True:
            return asksaveasfilename(initialdir = "/",title = "New Key Destination")
        else:
            return askopenfilename(initialdir = "/",title = "Existing Key Location")
            
    def open_save_file(self):
        self.inputTxt.delete('1.0','end')
        self.inputTxt.insert('1.0', askopenfilename(initialdir = "/",title = "Source File")) 
        self.outputTxt.delete('1.0','end')
        self.outputTxt.insert('1.0', asksaveasfilename(initialdir = "/",title = "Destination File"))
        
    def encrypt(self, data):
        crypto = None
        if self.genKeyVal.get() == 1 and self.keyPromptVal.get() == 0:
            crypto2 = {'authData': uuid4().bytes, 'nonce': urandom(12), 'key': AESGCM.generate_key(bit_length=256)}
            with open(AES_Util.DefaultKeyPath, 'wb') as file: dump(crypto2, file)
        elif self.genKeyVal.get() == 1 and self.keyPromptVal.get() == 1:
            crypto2 = {'authData': uuid4().bytes, 'nonce': urandom(12), 'key': AESGCM.generate_key(bit_length=256)}
            with open(self.open_save_key(True), 'wb') as file: dump(crypto2, file)
        elif self.genKeyVal.get() == 0 and self.keyPromptVal.get() == 0:
            if not exists(AES_Util.DefaultKeyPath):
                crypto2 = {'authData': uuid4().bytes, 'nonce': urandom(12), 'key': AESGCM.generate_key(bit_length=256)}
                with open(AES_Util.DefaultKeyPath, 'wb') as file: dump(crypto2, file)
            else:
                with open(AES_Util.DefaultKeyPath, 'rb') as file: crypto = load(file)
                crypto2 = {'authData': crypto['authData'], 'nonce': crypto['nonce'], 'key': crypto['key']}
        else:
            keyLoc = self.open_save_key(False)
            with open(keyLoc, 'rb') as file: crypto = load(file)
            crypto2 = {'authData': uuid4().bytes, 'nonce': urandom(12), 'key': crypto['key']}
            with open(keyLoc, 'wb') as file2: dump(crypto2, file2)
            
        aad = crypto2['authData']
        key = crypto2['key']
        aesgcm = AESGCM(key)
        nonce = crypto2['nonce']
        ct = aesgcm.encrypt(nonce, data, aad)
        return ct
    
    def decrypt(self, data):
        if self.keyPromptVal.get() == 0:
            with open(AES_Util.DefaultKeyPath, 'rb') as file: crypto = load(file) 
        else:
            with open(self.open_save_key(False), 'rb') as file: crypto = load(file) 
            
        aad = crypto['authData']
        key = crypto['key']
        aesgcm = AESGCM(key)
        nonce = crypto['nonce']
        ct = aesgcm.decrypt(nonce, data, aad)
        return ct
    
if __name__ == "__main__":
    form1 = AES_Util()
    form1.mainloop()