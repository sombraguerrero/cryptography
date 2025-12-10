using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Text;
using System.Linq;
using System.Net.Http;
using LoremNETCore;

namespace AES_Redone
{
    public partial class Form1 : Form
    {
        static Mode CurrentMode;
        static bool pwdMatch = false;
        static readonly private int salt_iv_len = 16;
        static readonly private int keyLength = 32;
        internal enum Mode
        {
            EncPwdText,
            EncPwdFiles,
            DecPwdText,
            DecPwdFiles,
            OSSLCompatEnc,
            OSSLCompatDec,
            B64Enc,
            B64Dec,
            OSSLCompatEncFiles,
            OSSLCompatDecFiles,
            EncExisting,
            DecExisting,
            Ignore

        };

        private void SetMode()
        {
            if (encryptBtn.Checked && !fileChk.Checked && !osslChk.Checked && !b64btn.Checked)
            {
                CurrentMode = Mode.EncPwdText;
                browseInputBtn.Enabled = browseOutputBtn.Enabled = false;
            }
            else if (encryptBtn.Checked && fileChk.Checked & !osslChk.Checked)
            {
                CurrentMode = Mode.EncPwdFiles;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (decryptBtn.Checked && !fileChk.Checked && !osslChk.Checked && !b64btn.Checked)
            {
                CurrentMode = Mode.DecPwdText;
                browseInputBtn.Enabled = browseOutputBtn.Enabled = false;
            }
            else if (decryptBtn.Checked && fileChk.Checked && !osslChk.Checked)
            {
                CurrentMode = Mode.DecPwdFiles;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (osslChk.Checked && encryptBtn.Checked && !fileChk.Checked)
            {
                CurrentMode = Mode.OSSLCompatEnc;
            }
            else if (osslChk.Checked && decryptBtn.Checked && !fileChk.Checked)
            {
                CurrentMode = Mode.OSSLCompatDec;
            }
            else if (osslChk.Checked && encryptBtn.Checked && fileChk.Checked)
            {
                CurrentMode = Mode.OSSLCompatEncFiles;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (osslChk.Checked && decryptBtn.Checked && fileChk.Checked)
            {
                CurrentMode = Mode.OSSLCompatDecFiles;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (b64btn.Checked && encryptBtn.Checked)
            {
                CurrentMode = Mode.B64Enc;
            }
            else if (b64btn.Checked && decryptBtn.Checked)
            {
                CurrentMode = Mode.B64Dec;
            }

        }

        static byte[] EncryptFileToBytes_Aes(byte[] inFile, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (inFile == null || inFile.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.BaseStream.Write(inFile, 0, inFile.Length);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        static string EncryptStringToString_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            string encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static void DecrypFileFromBytes_Aes(byte[] inFile, byte[] Key, byte[] IV, string dest)
        {
            // Check arguments.
            if (inFile == null || inFile.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(inFile))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (FileStream outFileStream = new FileStream(dest, FileMode.Create))
                        {
                            csDecrypt.CopyTo(outFileStream);
                        }
                    }
                }
            }
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        public Form1()
        {
            InitializeComponent();
        }

        private byte[] GenerateIVKey(string pwd, out byte[] nonce, int iters)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(salt_iv_len);
            nonce = RandomNumberGenerator.GetBytes(salt_iv_len);
            return Rfc2898DeriveBytes.Pbkdf2(pwd, salt, iters, HashAlgorithmName.SHA512, keyLength);
        }

        private byte[] GenerateIV() => RandomNumberGenerator.GetBytes(16);

        private void GenerateIVKey(string pwd, out byte[] iv, out byte[] k, byte[] salt)
        {
            byte[] password = Encoding.UTF8.GetBytes(pwd);
            HashAlgorithm hashAlg = shaBtn.Checked ? SHA512.Create() : MD5.Create();
            using (hashAlg)
            {
                byte[] keyAndIv = new byte[keyLength + salt_iv_len];
                byte[] currentHash = [];
                int i = 0;

                while (i < keyLength + salt_iv_len)
                {
                    hashAlg.TransformBlock(currentHash, 0, currentHash.Length, currentHash, 0);
                    hashAlg.TransformBlock(password, 0, password.Length, password, 0);
                    hashAlg.TransformBlock(salt, 0, salt.Length, salt, 0);
                    hashAlg.TransformFinalBlock([], 0, 0);
                    currentHash = hashAlg.Hash;
                    hashAlg.Initialize();

                    int remainingBytes = Math.Min(keyLength + salt_iv_len - i, currentHash.Length);
                    Array.Copy(currentHash, 0, keyAndIv, i, remainingBytes);
                    i += remainingBytes;
                }

                k = new byte[keyLength];
                iv = new byte[salt_iv_len];
                Array.Copy(keyAndIv, 0, k, 0, keyLength);
                Array.Copy(keyAndIv, keyLength, iv, 0, salt_iv_len);

            }
        }

        static byte[] MakeOpenSSLBytes(byte[] cipherText, byte[] generatedSalt)
        {
            byte[] salted = Encoding.UTF8.GetBytes("Salted__");
            return salted.Concat(generatedSalt).Concat(cipherText).ToArray();
        }

        private string DecryptFromOpenSSLString(string encryptedOSSLString)
        {
            string finalText = "ERROR";
            int headerLength = 8;
            byte[] objectIn = Convert.FromBase64String(encryptedOSSLString);
            byte[] saltedLabel = new byte[headerLength];
            byte[] mySalt = new byte[salt_iv_len];
            int cipherTextLength = objectIn.Length - (headerLength + salt_iv_len);
            byte[] cipherText = new byte[cipherTextLength];
            byte[] myVector;
            byte[] myKey;

            using (MemoryStream ms = new MemoryStream(objectIn))
            {
                ms.Read(saltedLabel, 0, headerLength);
                ms.Read(mySalt, 0, salt_iv_len);
                ms.Read(cipherText, 0, cipherTextLength);
            }
            if (Encoding.UTF8.GetString(saltedLabel).Equals("Salted__"))
            {
                GenerateIVKey(pwdTxtBox.Text, out myVector, out myKey, mySalt);
                finalText = DecryptStringFromBytes_Aes(cipherText, myKey, myVector);
            }
            return finalText;
        }

        void DecryptFromOpenSSLBytes(byte[] cipherBytes, string path, string pw)
        {
            int headerLength = 8;
            byte[] saltedLabel = new byte[headerLength];
            byte[] mySalt = new byte[salt_iv_len];
            int cipherTextLength = cipherBytes.Length - (headerLength + salt_iv_len);
            byte[] cipherText = new byte[cipherTextLength];
            byte[] myVector;
            byte[] myKey;

            using (MemoryStream ms = new MemoryStream(cipherBytes))
            {
                ms.Read(saltedLabel, 0, headerLength);
                ms.Read(mySalt, 0, salt_iv_len);
                ms.Read(cipherText, 0, cipherTextLength);
            }
            if (Encoding.UTF8.GetString(saltedLabel).Equals("Salted__"))
            {
                GenerateIVKey(pw, out myVector, out myKey, mySalt);
                DecrypFileFromBytes_Aes(cipherText, myKey, myVector, path);
            }
        }

        private void ClearAllArrays(byte[] a, byte[] b, byte[] c)
        {
            Array.Clear(a);
            Array.Clear(b);
            Array.Clear(c);
        }

        private void ClearAllArrays(byte[] a, byte[] b)
        {
            Array.Clear(a);
            Array.Clear(b);
        }

        private Mode PBKDF2_Mode()
        {
            if (decryptBtn.Checked && !string.IsNullOrEmpty(kFilePath.Text) && !string.IsNullOrEmpty(ivFilePath.Text))
            {
                return Mode.DecExisting;
            }
            else if (encryptBtn.Checked && !string.IsNullOrEmpty(kFilePath.Text))
            {
                return Mode.EncExisting;
            }
            else
            {
                return Mode.Ignore;
            }
        }

        private void processBtn_Click(object sender, EventArgs e)
        {
            int iterations = Convert.ToInt32(itersBox.Value);
            string keyPath, ivPath;
            string kGenPath, nonceGenPath;
            if (pwdMatch || (!(pwdMatch || PBKDF2_Mode().Equals(Mode.Ignore))))
            {
                byte[] myKey, myVector, mySalt;
                switch (CurrentMode)
                {
                    case Mode.EncPwdText:
                        if (PBKDF2_Mode().Equals(Mode.EncExisting))
                        {
                            myKey = File.ReadAllBytes(kFilePath.Text);
                            myVector = GenerateIV();
                            if (!string.IsNullOrEmpty(ivFilePath.Text))
                                MessageBox.Show("The existing IV will be ignored and a replacement will be generated.", "Notice");
                            nonceGenPath = !string.IsNullOrEmpty(ivGenPath.Text) ? ivGenPath.Text : "pbkdf2_iv.dat";
                            File.WriteAllBytes(nonceGenPath, myVector);
                        }
                        else
                        {
                            myKey = GenerateIVKey(pwdTxtBox.Text, out myVector, iterations);
                            kGenPath = !string.IsNullOrEmpty(keyGenPath.Text) ? keyGenPath.Text : "pbkdf2_key.dat";
                            nonceGenPath = !string.IsNullOrEmpty(ivGenPath.Text) ? ivGenPath.Text : "pbkdf2_iv.dat";
                            File.WriteAllBytes(kGenPath, myKey);
                            File.WriteAllBytes(nonceGenPath, myVector);
                        }
                        outputTxt.Text = EncryptStringToString_Aes(inputTxt.Text, myKey, myVector);
                        ClearAllArrays(myKey, myVector);
                        break;
                    case Mode.DecPwdText:
                        //GenerateIVKey(pwdTxtBox.Text, out myVector, out myKey, iterations);
                        keyPath = !string.IsNullOrEmpty(kFilePath.Text) ? kFilePath.Text : "pbkdf2_key.dat";
                        ivPath = !string.IsNullOrEmpty(ivFilePath.Text) ? ivFilePath.Text : "pbkdf2_iv.dat";
                        outputTxt.Text = DecryptStringFromBytes_Aes(Convert.FromBase64String(inputTxt.Text), File.ReadAllBytes(keyPath), File.ReadAllBytes(ivPath));
                        break;
                    case Mode.EncPwdFiles:
                        if (PBKDF2_Mode().Equals(Mode.EncExisting))
                        {
                            myKey = File.ReadAllBytes(kFilePath.Text);
                            myVector = GenerateIV();
                            if (!string.IsNullOrEmpty(ivFilePath.Text))
                                MessageBox.Show("The existing IV will be ignored and a replacement will be generated.", "Notice");
                            nonceGenPath = !string.IsNullOrEmpty(ivGenPath.Text) ? ivGenPath.Text : "pbkdf2_iv.dat";
                            File.WriteAllBytes(nonceGenPath, myVector);
                        }
                        else
                        {
                            myKey = GenerateIVKey(pwdTxtBox.Text, out myVector, iterations);
                            kGenPath = !string.IsNullOrEmpty(keyGenPath.Text) ? keyGenPath.Text : "pbkdf2_key.dat";
                            nonceGenPath = !string.IsNullOrEmpty(ivGenPath.Text) ? ivGenPath.Text : "pbkdf2_iv.dat";
                            File.WriteAllBytes(kGenPath, myKey);
                            File.WriteAllBytes(nonceGenPath, myVector);
                        }
                        File.WriteAllBytes(outputTxt.Text, EncryptFileToBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector));
                        MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                        ClearAllArrays(myKey, myVector);
                        break;
                    case Mode.DecPwdFiles:
                        //GenerateIVKey(pwdTxtBox.Text, out myVector, out myKey, iterations);
                        keyPath = !string.IsNullOrEmpty(kFilePath.Text) ? kFilePath.Text : "pbkdf2_key.dat";
                        ivPath = !string.IsNullOrEmpty(ivFilePath.Text) ? ivFilePath.Text : "pbkdf2_iv.dat";
                        DecrypFileFromBytes_Aes(File.ReadAllBytes(inputTxt.Text), File.ReadAllBytes(keyPath), File.ReadAllBytes(ivPath), outputTxt.Text);
                        MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                        break;
                    case Mode.OSSLCompatEnc:
                        mySalt = RandomNumberGenerator.GetBytes(salt_iv_len);
                        GenerateIVKey(pwdTxtBox.Text, out myVector, out myKey, mySalt);
                        outputTxt.Text = Convert.ToBase64String(MakeOpenSSLBytes(EncryptStringToBytes_Aes(inputTxt.Text, myKey, myVector), mySalt));
                        ClearAllArrays(myKey, myVector, mySalt);
                        break;
                    case Mode.OSSLCompatDec:
                        outputTxt.Text = DecryptFromOpenSSLString(inputTxt.Text);
                        break;
                    case Mode.OSSLCompatEncFiles:
                        mySalt = RandomNumberGenerator.GetBytes(salt_iv_len);
                        GenerateIVKey(pwdTxtBox.Text, out myVector, out myKey, mySalt);
                        File.WriteAllBytes(outputTxt.Text, MakeOpenSSLBytes(EncryptFileToBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector), mySalt));
                        MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                        ClearAllArrays(myKey, myVector, mySalt);
                        break;
                    case Mode.OSSLCompatDecFiles:
                        DecryptFromOpenSSLBytes(File.ReadAllBytes(inputTxt.Text), outputTxt.Text, pwdTxtBox.Text);
                        MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                        break;
                    case Mode.B64Enc:
                        MessageBox.Show("Password will be ignored.", "Inform");
                        outputTxt.Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(inputTxt.Text));
                        break;
                    case Mode.B64Dec:
                        MessageBox.Show("Password will be ignored.", "Inform");
                        outputTxt.Text = Encoding.UTF8.GetString(Convert.FromBase64String(inputTxt.Text));
                        break;
                }

            }
            else if (CurrentMode.Equals(Mode.B64Enc) || CurrentMode.Equals(Mode.B64Dec))
            {
                switch (CurrentMode)
                {
                    case Mode.B64Enc:
                        outputTxt.Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(inputTxt.Text));
                        break;
                    case Mode.B64Dec:
                        outputTxt.Text = Encoding.UTF8.GetString(Convert.FromBase64String(inputTxt.Text));
                        break;
                }
            }
            else if (PBKDF2_Mode().Equals(Mode.Ignore))
            {
                MessageBox.Show("Password mismatch!", "Warning");
            }
        }

        private void fileChk_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }

        private void encryptBtn_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }

        private void decryptBtn_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }

        private void browseInputBtn_Click(object sender, EventArgs e)
        {
            openInput.ShowDialog();
        }

        private void browseOutputBtn_Click(object sender, EventArgs e)
        {
            saveOutput.ShowDialog();
        }

        private void openInput_FileOk(object sender, System.ComponentModel.CancelEventArgs e)
        {
            inputTxt.Text = openInput.FileName;
        }

        private void saveOutput_FileOk(object sender, System.ComponentModel.CancelEventArgs e)
        {
            outputTxt.Text = saveOutput.FileName;
        }

        private void pwdBtn_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }

        private void verPassTxt_TextChanged(object sender, EventArgs e)
        {
            if (verPassTxt.Text.Equals(pwdTxtBox.Text))
            {
                verPassTxt.BackColor = System.Drawing.Color.Green;
                pwdTxtBox.BackColor = System.Drawing.Color.Green;
                pwdMatch = true;
            }
            else
            {
                verPassTxt.BackColor = System.Drawing.Color.Red;
                pwdMatch = false;
            }
        }

        private void pwdTxtBox_TextChanged(object sender, EventArgs e)
        {
            if (pwdTxtBox.Text.Equals(verPassTxt.Text))
            {
                pwdTxtBox.BackColor = System.Drawing.Color.Green;
                verPassTxt.BackColor = System.Drawing.Color.Green;
                pwdMatch = true;
            }
            else
            {
                pwdTxtBox.BackColor = System.Drawing.Color.Red;
                pwdMatch = false;
            }
        }

        private void b64btn_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }

        private void osslChk_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }

        private void loremBtn_Click(object sender, EventArgs e)
        {
            inputTxt.Text = Generate.Paragraph(20, 30, 3, 5);
        }

        private void browseKeyBtn_Click(object sender, EventArgs e)
        {
            if (openKey.ShowDialog() == DialogResult.OK)
            {
                kFilePath.Text = openKey.FileName;
            }
        }

        private void browseIVBtn_Click(object sender, EventArgs e)
        {
            if (openIV.ShowDialog() == DialogResult.OK)
            {
                ivFilePath.Text = openIV.FileName;
            }
        }

        private void genPathBtn_Click(object sender, EventArgs e)
        {
            if (saveKeyGen.ShowDialog() == DialogResult.OK)
            {
                keyGenPath.Text = saveKeyGen.FileName;
            }
        }

        private void ivPathBtn_Click(object sender, EventArgs e)
        {
            if (saveIVGen.ShowDialog() == DialogResult.OK)
            {
                ivGenPath.Text = saveIVGen.FileName;
            }
        }
    }
}

