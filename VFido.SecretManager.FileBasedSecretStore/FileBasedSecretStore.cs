using System.Security.Cryptography;

namespace VFido.SecretManager.FileBasedSecretStore
{
    /// <summary>
    /// Persists P-256 keys to disk, one file per key, each AES-GCM encrypted with a key derived
    /// via PBKDF2(username, password, salt). The salt is generated once per store directory and
    /// kept alongside the encrypted keys in plaintext - it isn't secret, only the username and
    /// password (never persisted) are. Losing either makes every key file permanently
    /// unrecoverable, matching the TPM-backed stores this seam is meant to also support.
    /// </summary>
    public class FileBasedSecretStore : IKeyStore, IPinStateStore
    {
        private const int SaltSize = 16;
        private const string SaltFileName = "salt.bin";
        private const string KeyFileExtension = ".key";
        private const string PinStateFileName = "pin.bin";

        private readonly string _directory;
        private readonly byte[] _aesKey;

        public FileBasedSecretStore(string directory, string username, string password)
        {
            _directory = directory;
            Directory.CreateDirectory(_directory);

            var isNewStore = !File.Exists(Path.Combine(_directory, SaltFileName));
            var salt = LoadOrCreateSalt();
            _aesKey = AesKeyProtector.DeriveKey(username, password, salt);

            PasswordVerifier.EnsureOrVerify(_directory, _aesKey, isNewStore);
        }

        public ISigningKey CreateEs256Key()
        {
            var ecdsa = Crypto.EcdsaProvider.GenerateP256();
            var keyId = Guid.NewGuid();

            var plaintext = ecdsa.ExportPkcs8PrivateKey();
            var encrypted = AesKeyProtector.Encrypt(_aesKey, plaintext);
            File.WriteAllBytes(KeyFilePath(keyId), encrypted);

            return new FileBasedSigningKey(ecdsa, keyId);
        }

        public ISigningKey LoadKey(byte[] handle)
        {
            var keyId = new Guid(handle);
            var encrypted = File.ReadAllBytes(KeyFilePath(keyId));
            var plaintext = AesKeyProtector.Decrypt(_aesKey, encrypted);

            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(plaintext, out _);
            return new FileBasedSigningKey(ecdsa, keyId);
        }

        public PinState? Load()
        {
            var path = Path.Combine(_directory, PinStateFileName);
            if (!File.Exists(path))
                return null;

            var plaintext = AesKeyProtector.Decrypt(_aesKey, File.ReadAllBytes(path));
            return System.Text.Json.JsonSerializer.Deserialize<PinState>(plaintext);
        }

        public void Save(PinState state)
        {
            var plaintext = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(state);
            var encrypted = AesKeyProtector.Encrypt(_aesKey, plaintext);
            File.WriteAllBytes(Path.Combine(_directory, PinStateFileName), encrypted);
        }

        private string KeyFilePath(Guid keyId) => Path.Combine(_directory, keyId + KeyFileExtension);

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
