using VFido.SecretManager.FileBasedSecretStore;
using System.Security.Cryptography;
using System.Text;

namespace VFido.SecretManager.Protection
{
    /// <summary>
    /// FileBasedSecretStore/FileBasedCredentialStore derive an AES key from username+password+salt
    /// with no other way to tell a wrong password from a right one up front - LoadKey/Find would
    /// only fail once something is actually decrypted, deep inside a CTAP2 operation. This writes
    /// a small known-plaintext "verifier" the first time a store directory is created, and checks
    /// it on every later open so a wrong password fails immediately and clearly instead.
    /// </summary>
    public static class PasswordVerifier
    {
        private const string VerifierFileName = "verifier.bin";
        private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("VFIDO-VERIFY");

        public static void EnsureOrVerify(string directory, byte[] aesKey, bool isNewStore)
        {
            var path = Path.Combine(directory, VerifierFileName);

            if (isNewStore)
            {
                File.WriteAllBytes(path, AesKeyProtector.Encrypt(aesKey, Plaintext));
                return;
            }

            if (!File.Exists(path)) throw new InvalidDataException("Storage password verifier is missing.");

            byte[] decrypted;
            try
            {
                decrypted = AesKeyProtector.Decrypt(aesKey, File.ReadAllBytes(path));
            }
            catch (CryptographicException)
            {
                throw new InvalidCredentialsException();
            }

            if (!decrypted.AsSpan().SequenceEqual(Plaintext))
                throw new InvalidCredentialsException();
        }
    }
}
