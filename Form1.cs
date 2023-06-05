using System;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Text;

namespace AES_Redone
{
    public partial class Form1 : Form
    {
        static Mode CurrentMode;

        internal enum Mode
        {
            EncIntText = 1,
            EncIntFiles = 2,
            DecIntText = 3,
            DecIntFiles = 4,
            EncExtText = 5,
            EncExtFiles = 6,
            DecExtText = 7,
            DecExtFiles = 8,
            EncPwdText = 9,
            EncPwdFiles = 10,
            DecPwdText = 11,
            DecPwdFiles = 12
        };

        private void SetMode()
        {
            if (encryptBtn.Checked && !ivkBtn.Checked && !pwdBtn.Checked && !fileChk.Checked)
            {
                CurrentMode = Mode.EncIntText;
            }
            else if (encryptBtn.Checked && pwdBtn.Checked &&  !fileChk.Checked)
            {
                CurrentMode = Mode.EncPwdText;
                pwdTxtBox.Enabled = true;
            }
            else if (encryptBtn.Checked && pwdBtn.Checked && fileChk.Checked)
            {
                CurrentMode = Mode.EncPwdFiles;
                pwdTxtBox.Enabled = true;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (decryptBtn.Checked && pwdBtn.Checked && !fileChk.Checked)
            {
                CurrentMode = Mode.DecPwdText;
                pwdTxtBox.Enabled= true;
            }
            else if (decryptBtn.Checked && pwdBtn.Checked && fileChk.Checked)
            {
                CurrentMode= Mode.DecPwdFiles;
                pwdTxtBox.Enabled = true;
                browseInputBtn.Enabled= true;
                browseOutputBtn.Enabled= true;
            }
            else if (encryptBtn.Checked && !ivkBtn.Checked && fileChk.Checked)
            {
                CurrentMode = Mode.EncIntFiles;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (encryptBtn.Checked && ivkBtn.Checked && !fileChk.Checked)
            {
                CurrentMode = Mode.EncExtText;
                keyFileTxt.Enabled = true;
                vectorFileTxt.Enabled = true;
                browseKeyBtn.Enabled = true;
                BrowseVectorBtn.Enabled = true;
            }
            else if (encryptBtn.Checked && ivkBtn.Checked && fileChk.Checked)
            {
                CurrentMode = Mode.EncExtFiles;
                keyFileTxt.Enabled = true;
                vectorFileTxt.Enabled = true;
                browseKeyBtn.Enabled = true;
                BrowseVectorBtn.Enabled = true;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (decryptBtn.Checked && !ivkBtn.Checked && !pwdBtn.Checked && !fileChk.Checked)
                CurrentMode = Mode.DecIntText;
            else if (decryptBtn.Checked && !ivkBtn.Checked && fileChk.Checked)
            {
                CurrentMode = Mode.DecIntFiles;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }
            else if (decryptBtn.Checked && ivkBtn.Checked && !fileChk.Checked)
            {
                CurrentMode = Mode.DecExtText;
                keyFileTxt.Enabled = true;
                vectorFileTxt.Enabled = true;
                browseKeyBtn.Enabled = true;
                BrowseVectorBtn.Enabled = true;
            }
            else if (decryptBtn.Checked && ivkBtn.Checked && fileChk.Checked)
            {
                CurrentMode = Mode.DecExtFiles;
                keyFileTxt.Enabled = true;
                vectorFileTxt.Enabled = true;
                browseKeyBtn.Enabled = true;
                BrowseVectorBtn.Enabled = true;
                browseInputBtn.Enabled = true;
                browseOutputBtn.Enabled = true;
            }

        }

        static bool isValidateKV()
        {
            ResourceManager manager = new ResourceManager("AES_Redone.Properties.Resources", Assembly.GetExecutingAssembly());
            return manager.GetString("enc_uuid").Equals(Environment.GetEnvironmentVariable("enc_uuid", EnvironmentVariableTarget.User));
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
        static string EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
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

        private void GenerateIVKey(string pwd, out byte[] iv, out byte[] k)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(pwd);
            k = SHA256.Create().ComputeHash(passwordBytes);
            iv = MD5.Create().ComputeHash(passwordBytes);
        }

        private void processBtn_Click(object sender, EventArgs e)
        {
            ResourceManager manager = new ResourceManager("AES_Redone.Properties.Resources", Assembly.GetExecutingAssembly());
            byte[] myKey, myVector;
            if (CurrentMode <= Mode.DecIntFiles)
            {
                myKey = Convert.FromBase64String(manager.GetString("intKey"));
                myVector = Convert.FromBase64String(manager.GetString("intVec"));
            }
            else if (CurrentMode >= Mode.EncPwdText)
            {
                GenerateIVKey(pwdTxtBox.Text, out myVector, out myKey);
            }
            else
            {
                myKey = File.ReadAllBytes(keyFileTxt.Text);
                myVector = File.ReadAllBytes(vectorFileTxt.Text);
            }
            switch (CurrentMode)
            {
                case Mode.EncIntText:
                    outputTxt.Text = EncryptStringToBytes_Aes(inputTxt.Text, myKey, myVector);
                    Environment.SetEnvironmentVariable("enc_uuid", manager.GetString("enc_uuid"), EnvironmentVariableTarget.User);
                    break;
                case Mode.EncPwdText:
                    outputTxt.Text = EncryptStringToBytes_Aes(inputTxt.Text, myKey, myVector);
                    break;
                case Mode.DecPwdText:
                    outputTxt.Text = DecryptStringFromBytes_Aes(Convert.FromBase64String(inputTxt.Text), myKey, myVector);
                    break;
                case Mode.DecIntText:
                    if (isValidateKV())
                        outputTxt.Text = DecryptStringFromBytes_Aes(Convert.FromBase64String(inputTxt.Text), myKey, myVector);
                    else
                        MessageBox.Show("Key/Vector pair mismatch. Unable to perform decryption.");
                    break;
                case Mode.EncExtText:
                    outputTxt.Text = EncryptStringToBytes_Aes(inputTxt.Text, myKey, myVector);
                    break;
                case Mode.DecExtText:
                    outputTxt.Text = DecryptStringFromBytes_Aes(Convert.FromBase64String(inputTxt.Text), myKey, myVector);
                    break;
                case Mode.EncPwdFiles:
                    File.WriteAllBytes(outputTxt.Text, EncryptFileToBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector));
                    MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                    break;
                case Mode.DecPwdFiles:
                    DecrypFileFromBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector, outputTxt.Text);
                    MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                    break;
                case Mode.EncIntFiles:
                    File.WriteAllBytes(outputTxt.Text, EncryptFileToBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector));
                    Environment.SetEnvironmentVariable("enc_uuid", manager.GetString("enc_uuid"), EnvironmentVariableTarget.User);
                    MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                    break;
                case Mode.DecIntFiles:
                    if (isValidateKV())
                    {
                        DecrypFileFromBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector, outputTxt.Text);
                        MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                    }
                    else
                        MessageBox.Show("Key/Vector pair mismatch. Unable to perform decryption.");
                    break;
                case Mode.EncExtFiles:
                    File.WriteAllBytes(outputTxt.Text, EncryptFileToBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector));
                    MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                    break;
                case Mode.DecExtFiles:
                    DecrypFileFromBytes_Aes(File.ReadAllBytes(inputTxt.Text), myKey, myVector, outputTxt.Text);
                    MessageBox.Show($"File created at {outputTxt.Text}", "Complete");
                    break;
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

        private void vectorOpen_FileOk(object sender, System.ComponentModel.CancelEventArgs e)
        {
            vectorFileTxt.Text = vectorOpen.FileName;
        }

        private void openKey_FileOk(object sender, System.ComponentModel.CancelEventArgs e)
        {
            keyFileTxt.Text = openKey.FileName;
        }

        private void BrowseVectorBtn_Click(object sender, EventArgs e)
        {
            vectorOpen.ShowDialog();
        }

        private void browseKeyBtn_Click(object sender, EventArgs e)
        {
            openKey.ShowDialog();
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

        private void ivkBtn_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }

        private void pwdBtn_CheckedChanged(object sender, EventArgs e)
        {
            SetMode();
        }
    }
}
