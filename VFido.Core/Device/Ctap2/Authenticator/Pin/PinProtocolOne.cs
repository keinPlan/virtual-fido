using System.Security.Cryptography;

namespace VFido.Core.Device.Ctap2.Authenticator.Pin
{
    /// <summary>
    /// PIN/UV Auth Protocol One (CTAP2 section 6.5.6): shared secret is SHA-256 of the raw ECDH
    /// Z coordinate, encryption is AES-256-CBC with a zero IV and no padding, and the "authenticate"
    /// function is the left 16 bytes of HMAC-SHA256.
    /// </summary>
    internal static class PinProtocolOne
    {
        private static readonly byte[] ZeroIv = new byte[16];

        internal static byte[] DeriveSharedSecret(ECDiffieHellman authenticatorKey, ECParameters platformPublicKey)
        {
            using var platformKey = ECDiffieHellman.Create(platformPublicKey);
            var z = authenticatorKey.DeriveRawSecretAgreement(platformKey.PublicKey);
            return SHA256.HashData(z);
        }

        internal static byte[] Encrypt(byte[] sharedSecret, byte[] plaintext)
        {
            using var aes = CreateAes(sharedSecret);
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        internal static byte[] Decrypt(byte[] sharedSecret, byte[] ciphertext)
        {
            using var aes = CreateAes(sharedSecret);
            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }

        internal static byte[] Authenticate(byte[] key, byte[] message) =>
            HMACSHA256.HashData(key, message)[..16];

        private static Aes CreateAes(byte[] key)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.IV = ZeroIv;
            return aes;
        }
    }
}
