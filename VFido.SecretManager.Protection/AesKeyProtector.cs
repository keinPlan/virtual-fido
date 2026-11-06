using System.Security.Cryptography;
using System.Text;

namespace VFido.SecretManager.Protection
{
    /// <summary>
    /// Derives an AES-256 key from username+password+salt via PBKDF2, then wraps/unwraps key
    /// blobs with AES-GCM. The derived key never touches disk - only the salt does - so a stolen
    /// key file is useless without the matching username/password.
    /// </summary>
    public static class AesKeyProtector
    {
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int Iterations = 100_000;

        public static byte[] DeriveKey(string username, string password, byte[] salt) =>
            Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes($"{username}_{password}"), salt, Iterations, HashAlgorithmName.SHA256, KeySize);

        /// <summary>Layout: nonce (12) || tag (16) || ciphertext.</summary>
        public static byte[] Encrypt(byte[] aesKey, byte[] plaintext)
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            using var aesGcm = new AesGcm(aesKey, TagSize);
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            var result = new byte[NonceSize + TagSize + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
            Buffer.BlockCopy(tag, 0, result, NonceSize, TagSize);
            Buffer.BlockCopy(ciphertext, 0, result, NonceSize + TagSize, ciphertext.Length);
            return result;
        }

        public static byte[] Decrypt(byte[] aesKey, byte[] blob)
        {
            if (blob.Length < NonceSize + TagSize) throw new CryptographicException("Truncated encrypted payload.");
            var nonce = blob[..NonceSize];
            var tag = blob[NonceSize..(NonceSize + TagSize)];
            var ciphertext = blob[(NonceSize + TagSize)..];
            var plaintext = new byte[ciphertext.Length];

            using var aesGcm = new AesGcm(aesKey, TagSize);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }
    }
}
