using System.Text;
using System.Security.Cryptography;
using System.Resources;

namespace GenericCryptoJS
{
    public class CryptoJS
    {
        static private ResourceManager manager = new ResourceManager("CryptoJS.Properties.Resources", System.Reflection.Assembly.GetExecutingAssembly()); 
        static public string Encrypt(string input, HashAlgorithm h)
        {
            byte[] myKey, myVector, mySalt;
            mySalt = RandomNumberGenerator.GetBytes(96);
            byte[] key_iv = EVP_BytesToKey(Encoding.UTF8.GetBytes(manager.GetString("genericPwd")), mySalt, 32, 16, h);
            myKey = key_iv.Take(32).ToArray();
            myVector = key_iv.Skip(32).Take(16).ToArray();
            return Convert.ToBase64String(MakeOpenSSLBytes(EncryptStringToBytes_Aes(input, myKey, myVector), mySalt));
        }
        static public string Decrypt(string input, HashAlgorithm h) => DecryptFromOpenSSLString(input, h);

        // See http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
        //Credit to https://gist.github.com/caspencer/1339719 for this function
        public static byte[] EVP_BytesToKey(byte[] password, byte[] salt, int key_len, int iv_len, HashAlgorithm md)
        {
            using (md)
            {
                byte[] key_iv = new byte[key_len + iv_len];
                int offset = 0;
                byte[] input = password.Concat(salt).ToArray();
                while (offset < key_iv.Length)
                {
                    md.Initialize(); // Reset MD state
                    byte[] digest = md.ComputeHash(input);
                    int bytesToCopy = Math.Min(digest.Length, key_iv.Length - offset);
                    Array.Copy(digest, 0, key_iv, offset, bytesToCopy);
                    offset += bytesToCopy;
                    if (offset < key_iv.Length) { input = digest.Concat(password).ToArray(); }
                }
                return key_iv;
            }
        }

        static byte[] MakeOpenSSLBytes(byte[] cipherText, byte[] generatedSalt)
        {
            byte[] salted = Encoding.UTF8.GetBytes("Salted__");
            return salted.Concat(generatedSalt).Concat(cipherText).ToArray();
        }

        private static string DecryptFromOpenSSLString(string encryptedOSSLString, HashAlgorithm h)
        {
            string finalText = "ERROR";
            const int headerLength = 8;
            const int saltLength = 96;
            byte[] objectIn = Convert.FromBase64String(encryptedOSSLString);
            byte[] saltedLabel = new byte[headerLength];
            byte[] mySalt = new byte[saltLength];
            int cipherTextLength = objectIn.Length - (headerLength + saltLength);
            byte[] cipherText = new byte[cipherTextLength];
            byte[] myVector;
            byte[] myKey;

            using (MemoryStream ms = new MemoryStream(objectIn))
            {
                ms.Read(saltedLabel, 0, headerLength);
                ms.Read(mySalt, 0, saltLength);
                ms.Read(cipherText, 0, cipherTextLength);
            }
            if (Encoding.UTF8.GetString(saltedLabel).Equals("Salted__"))
            {
                byte[] key_iv = EVP_BytesToKey(Encoding.UTF8.GetBytes(manager.GetString("genericPwd")), mySalt, 32, 16, h);
                myKey = key_iv.Take(32).ToArray();
                myVector = key_iv.Skip(32).Take(16).ToArray();
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
