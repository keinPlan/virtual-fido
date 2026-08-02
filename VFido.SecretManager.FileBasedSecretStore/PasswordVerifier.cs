using System.Security.Cryptography;
using System.Text;

namespace VFido.SecretManager.FileBasedSecretStore
{
    /// <summary>Thrown when a store directory already existed but the derived key can't decrypt it - i.e. the username/password don't match what the store was created with.</summary>
    public sealed class InvalidCredentialsException : Exception
    {
        public InvalidCredentialsException() : base("Incorrect username or password.") { }
    }

    /// <summary>
    /// FileBasedSecretStore/FileBasedCredentialStore derive an AES key from username+password+salt
    /// with no other way to tell a wrong password from a right one up front - LoadKey/Find would
    /// only fail once something is actually decrypted, deep inside a CTAP2 operation. This writes
    /// a small known-plaintext "verifier" the first time a store directory is created, and checks
    /// it on every later open so a wrong password fails immediately and clearly instead.
    /// </summary>
    internal static class PasswordVerifier
    {
        private const string VerifierFileName = "verifier.bin";
        private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("VFIDO-VERIFY");

        internal static void EnsureOrVerify(string directory, byte[] aesKey, bool isNewStore)
        {
            var path = Path.Combine(directory, VerifierFileName);

            if (isNewStore || !File.Exists(path))
            {
                File.WriteAllBytes(path, AesKeyProtector.Encrypt(aesKey, Plaintext));
                return;
            }

            byte[] decrypted;
            try
            {
                decrypted = AesKeyProtector.Decrypt(aesKey, File.ReadAllBytes(path));
            }
            catch (Exception)
            {
                throw new InvalidCredentialsException();
            }

            if (!decrypted.AsSpan().SequenceEqual(Plaintext))
                throw new InvalidCredentialsException();
        }
    }
}
