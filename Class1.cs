using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Text;
using static iGCM.IGCM;

namespace iGCM
{

    public interface IKeyStorage
    {
        byte[] Key { get; set; }
    }

    public static class DependencyInjection
    {
        public static IServiceCollection AddKeyStorage(this IServiceCollection services)
        {
            services.AddSingleton<IKeyStorage, KeyStorage>();
            return services;
        }
    }

    public class IGCM
    {
        /***
         * A note about exporting classes in DLLs:
         * Static members, if initialized before any constructor is called, can cause the consuming program 
         * to throw a Type Initializor exception
         */

        public class KeyStorage : IKeyStorage
        {
            public byte[] Key { get; set; }
            public KeyStorage()
            {
                Key = UnwrapKey().Result;
            }
        }

        public async static Task<byte[]>  UnwrapKey()
        {
            CryptographyClient client = new CryptographyClient(new Uri("https://sombramain.vault.azure.net/keys/Main/"), new DefaultAzureCredential());
            byte[] rawKeyBytes = Convert.FromBase64String(Settings1.Default.myKey);
            UnwrapResult result =  await client.UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep, rawKeyBytes);
            return result.Key;
        }
        public static byte[] EncryptData(string plainText, byte[] key)
        {
            ReadOnlySpan<byte> data = new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(plainText));
            ReadOnlySpan<byte> myKey = new ReadOnlySpan<byte>(key);
            // encryptionKey = 32-bytes/ 256 bits
            using (var aes = new AesGcm(myKey, AesGcm.TagByteSizes.MaxSize))
            {
                // AesGcm.NonceByteSizes.MaxSize = 12 bytes
                // AesGcm.TagByteSizes.MaxSize = 16 bytes
                Span<byte> buffer = new byte[data.Length + AesGcm.NonceByteSizes.MaxSize + AesGcm.TagByteSizes.MaxSize];
                var nonce = buffer.Slice(data.Length, AesGcm.NonceByteSizes.MaxSize);
                RandomNumberGenerator.Fill(nonce);
                aes.Encrypt(nonce, data, buffer.Slice(0, data.Length), buffer.Slice(data.Length + AesGcm.NonceByteSizes.MaxSize, AesGcm.TagByteSizes.MaxSize));
                // buffer has encrypted data bytes + 12 bytes of Nonce + 16 bytes of Tag
                return buffer.ToArray();
            }
        }

        public static byte[] EncryptData(byte[] plainData, byte[] key)
        {
            ReadOnlySpan<byte> data = new ReadOnlySpan<byte>(plainData);
            ReadOnlySpan<byte> myKey = new ReadOnlySpan<byte>(key);
            // encryptionKey = 32-bytes/ 256 bits
            using (var aes = new AesGcm(myKey, AesGcm.TagByteSizes.MaxSize))
            {
                // AesGcm.NonceByteSizes.MaxSize = 12 bytes
                // AesGcm.TagByteSizes.MaxSize = 16 bytes
                Span<byte> buffer = new byte[data.Length + AesGcm.NonceByteSizes.MaxSize + AesGcm.TagByteSizes.MaxSize];
                var nonce = buffer.Slice(data.Length, AesGcm.NonceByteSizes.MaxSize);
                RandomNumberGenerator.Fill(nonce);
                aes.Encrypt(nonce, data, buffer.Slice(0, data.Length), buffer.Slice(data.Length + AesGcm.NonceByteSizes.MaxSize, AesGcm.TagByteSizes.MaxSize));
                // buffer has encrypted data bytes + 12 bytes of Nonce + 16 bytes of Tag
                return buffer.ToArray();
            }
        }

        public static byte[] DecryptData(string cipherText, byte[] key)
        {
            // encryptedData has encrypted data bytes + 12 bytes of Nonce + 16 bytes of Tag
            ReadOnlySpan<byte> myKey = new ReadOnlySpan<byte>(key);
            Span<byte> encryptedData = new Span<byte>(Convert.FromBase64String(cipherText));
            var tag = encryptedData.Slice(encryptedData.Length - AesGcm.TagByteSizes.MaxSize, AesGcm.TagByteSizes.MaxSize);
            var nonce = encryptedData.Slice(encryptedData.Length - AesGcm.TagByteSizes.MaxSize - AesGcm.NonceByteSizes.MaxSize, AesGcm.NonceByteSizes.MaxSize);
            var cipherBytes = encryptedData.Slice(0, encryptedData.Length - AesGcm.TagByteSizes.MaxSize - AesGcm.NonceByteSizes.MaxSize);
            Span<byte> buffer = new byte[cipherBytes.Length];
            using (var aes = new AesGcm(myKey, AesGcm.TagByteSizes.MaxSize))
            {
                aes.Decrypt(nonce, cipherBytes, tag, buffer);
            }
            return buffer.ToArray();
        }

        public static byte[] DecryptData(byte[] cipherData, byte[] key)
        {
            // encryptedData has encrypted data bytes + 12 bytes of Nonce + 16 bytes of Tag
            ReadOnlySpan<byte> myKey = new ReadOnlySpan<byte>(key);
            Span<byte> plainData = new Span<byte>(cipherData);
            var tag = plainData.Slice(cipherData.Length - AesGcm.TagByteSizes.MaxSize, AesGcm.TagByteSizes.MaxSize);
            var nonce = plainData.Slice(cipherData.Length - AesGcm.TagByteSizes.MaxSize - AesGcm.NonceByteSizes.MaxSize, AesGcm.NonceByteSizes.MaxSize);
            var cipherBytes = plainData.Slice(0, cipherData.Length - AesGcm.TagByteSizes.MaxSize - AesGcm.NonceByteSizes.MaxSize);
            Span<byte> buffer = new byte[cipherBytes.Length];
            using (var aes = new AesGcm(myKey, AesGcm.TagByteSizes.MaxSize))
            {
                aes.Decrypt(nonce, cipherBytes, tag, buffer);
            }
            return buffer.ToArray();
        }
    }
}
