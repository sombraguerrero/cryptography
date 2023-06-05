using System.Text;
using System.Security.Cryptography;
using System.Resources;

namespace GenericCryptoJS
{
    public class CryptoJS
    {
        static private ResourceManager manager = new ResourceManager("CryptoJS.Properties.Resources", System.Reflection.Assembly.GetExecutingAssembly()); 
        static public string Encrypt(string input)
        {
            byte[] myKey, myVector, mySalt;
            mySalt = RandomNumberGenerator.GetBytes(8);
            GenerateIVKey(manager.GetString("genericPwd"), out myVector, out myKey, mySalt);
            return Convert.ToBase64String(MakeOpenSSLBytes(EncryptStringToBytes_Aes(input, myKey, myVector), mySalt));
        }

        static public string Decrypt(string input) => DecryptFromOpenSSLString(input);


        // See http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
        //Credit to https://gist.github.com/caspencer/1339719 for this function
        static void GenerateIVKey(string pwd, out byte[] iv, out byte[] k, byte[] salt)
        {
            // generate key and iv
            List<byte> concatenatedHashes = new List<byte>(48);
            byte[] password = Encoding.UTF8.GetBytes(pwd);
            byte[] currentHash = new byte[0];

            //Might need to use SHA256 here depending on what version of OpenSSL is implemented by whatever version of cryptoJS Fremont is using.
            MD5 md5 = MD5.Create();
            //SHA256 sha256 = SHA256.Create();
            bool enoughBytesForKey = false;
            while (!enoughBytesForKey)
            {
                int preHashLength = salt != null ? currentHash.Length + password.Length + salt.Length : currentHash.Length + password.Length;
                byte[] preHash = new byte[preHashLength];
                Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
                Buffer.BlockCopy(password, 0, preHash, currentHash.Length, password.Length);
                if (salt != null)
                    Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + password.Length, salt.Length);
                currentHash = md5.ComputeHash(preHash);
                concatenatedHashes.AddRange(currentHash);
                if (concatenatedHashes.Count >= 48)
                    enoughBytesForKey = true;
            }
            k = new byte[32];
            iv = new byte[16];
            concatenatedHashes.CopyTo(0, k, 0, 32);
            concatenatedHashes.CopyTo(32, iv, 0, 16);
            //sha256.Clear();
            md5.Clear();
        }

        static byte[] MakeOpenSSLBytes(byte[] cipherText, byte[] generatedSalt)
        {
            byte[] salted = Encoding.UTF8.GetBytes("Salted__");
            return salted.Concat(generatedSalt).Concat(cipherText).ToArray();
        }

        private static string DecryptFromOpenSSLString(string encryptedOSSLString)
        {
            string finalText = "ERROR";
            int headerLength = 8;
            byte[] objectIn = Convert.FromBase64String(encryptedOSSLString);
            byte[] saltedLabel = new byte[headerLength];
            byte[] mySalt = new byte[headerLength];
            int cipherTextLength = objectIn.Length - 16;
            byte[] cipherText = new byte[cipherTextLength];
            byte[] myVector;
            byte[] myKey;

            using (MemoryStream ms = new MemoryStream(objectIn))
            {
                ms.Read(saltedLabel, 0, headerLength);
                ms.Read(mySalt, 0, headerLength);
                ms.Read(cipherText, 0, cipherTextLength);
            }
            if (Encoding.UTF8.GetString(saltedLabel).Equals("Salted__"))
            {
                GenerateIVKey(manager.GetString("genericPwd"), out myVector, out myKey, mySalt);
                finalText = DecryptStringFromBytes_Aes(cipherText, myKey, myVector);
            }
            return finalText;
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
    }

}
