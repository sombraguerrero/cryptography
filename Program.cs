using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;

Console.Write("Specify a key file to be wrapped: ");
byte[] rawKeyBytes = File.ReadAllBytes(Console.ReadLine());
CryptographyClient client = new CryptographyClient(new Uri("https://sombramain.vault.azure.net/keys/Main/"), new DefaultAzureCredential());

WrapResult wrapResult = await client.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep, rawKeyBytes);
byte[] wrappedKey = wrapResult.EncryptedKey;
Console.WriteLine(Convert.ToBase64String(wrappedKey));
_ = Console.ReadKey();