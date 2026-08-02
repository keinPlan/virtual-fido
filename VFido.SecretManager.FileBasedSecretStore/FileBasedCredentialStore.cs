using System.Security.Cryptography;
using System.Text.Json;

namespace VFido.SecretManager.FileBasedSecretStore
{
    /// <summary>
    /// Persists credential registrations to disk, one file per credential, each AES-GCM encrypted
    /// the same way FileBasedSecretStore protects its keys (own directory, own salt - so this can
    /// live in a sibling "credentials" folder next to FileBasedSecretStore's "keys" folder under a
    /// stick's own config directory). Without this, a file-based-secret-manager stick would forget
    /// which credentials it registered on every restart even though its signing keys survive.
    /// </summary>
    public class FileBasedCredentialStore : ICredentialStore
    {
        private const int SaltSize = 16;
        private const string SaltFileName = "salt.bin";
        private const string CredentialFileExtension = ".cred";

        private readonly string _directory;
        private readonly byte[] _aesKey;

        public FileBasedCredentialStore(string directory, string username, string password)
        {
            _directory = directory;
            Directory.CreateDirectory(_directory);

            var isNewStore = !File.Exists(Path.Combine(_directory, SaltFileName));
            var salt = LoadOrCreateSalt();
            _aesKey = AesKeyProtector.DeriveKey(username, password, salt);

            PasswordVerifier.EnsureOrVerify(_directory, _aesKey, isNewStore);
        }

        public void Save(StoredCredential credential)
        {
            var plaintext = JsonSerializer.SerializeToUtf8Bytes(credential);
            var encrypted = AesKeyProtector.Encrypt(_aesKey, plaintext);
            File.WriteAllBytes(CredentialFilePath(credential.CredentialId), encrypted);
        }

        public StoredCredential? Find(byte[] credentialId)
        {
            var path = CredentialFilePath(credentialId);
            if (!File.Exists(path))
                return null;

            return Decode(File.ReadAllBytes(path));
        }

        public IReadOnlyList<StoredCredential> FindByRp(string rpId) =>
            FindAll().Where(c => c.RpId == rpId).ToList();

        public IReadOnlyList<StoredCredential> FindAll() =>
            Directory.EnumerateFiles(_directory, "*" + CredentialFileExtension)
                .Select(path => Decode(File.ReadAllBytes(path)))
                .ToList();

        public void Delete(byte[] credentialId)
        {
            var path = CredentialFilePath(credentialId);
            if (File.Exists(path))
                File.Delete(path);
        }

        private StoredCredential Decode(byte[] encrypted)
        {
            var plaintext = AesKeyProtector.Decrypt(_aesKey, encrypted);
            return JsonSerializer.Deserialize<StoredCredential>(plaintext)
                ?? throw new InvalidOperationException("Corrupt credential file: empty payload.");
        }

        private string CredentialFilePath(byte[] credentialId) =>
            Path.Combine(_directory, Convert.ToHexString(credentialId) + CredentialFileExtension);

        private byte[] LoadOrCreateSalt()
        {
            var saltPath = Path.Combine(_directory, SaltFileName);
            if (File.Exists(saltPath))
                return File.ReadAllBytes(saltPath);

            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            File.WriteAllBytes(saltPath, salt);
            return salt;
        }
    }
}
