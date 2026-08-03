using System.Security.Cryptography;
using VFido.SecretManager.Crypto;

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
        private const string AttestationKeyFileName = "attestation.key";
        private const string AttestationCertFileName = "attestation.crt";
        private const string AttestationIntermediateKeyFileName = "attestation-intermediate.key";
        private const string AttestationIntermediateCertFileName = "attestation-intermediate.crt";
        private const string AttestationRootKeyFileName = "attestation-root.key";
        private const string AttestationRootCertFileName = "attestation-root.crt";

        /// <summary>Fixed AAGUID identifying every stick backed by this store type, regardless of directory.</summary>
        private static readonly Guid AaguidGuid = new("f11e0a10-0ea1-4b1f-8b0a-1b0a1e0a1b0a");

        private readonly string _directory;
        private readonly byte[] _aesKey;

        public byte[] Aaguid => AaguidGuid.ToByteArray();

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

        /// <summary>
        /// Builds a self-signed root, an intermediate the root issues, and a leaf the intermediate
        /// issues, each generated and persisted lazily (only the first missing link and everything
        /// above it). Only the leaf and intermediate are returned - the root is the trust anchor
        /// and never goes into x5c, so nothing outside this class ever needs its DER.
        /// </summary>
        public AttestationCertificate GetOrCreateAttestationCertificate()
        {
            var intermediateCertDer = GetOrCreateIntermediateCert();

            var leafCertPath = Path.Combine(_directory, AttestationCertFileName);
            var leafKeyPath = KeyFilePath(AttestationKeyGuid);

            if (File.Exists(leafCertPath) && File.Exists(leafKeyPath))
                return new AttestationCertificate(AttestationKeyHandle, new[] { File.ReadAllBytes(leafCertPath), intermediateCertDer });

            using var intermediateKey = LoadPrivateKey(Path.Combine(_directory, AttestationIntermediateKeyFileName));
            var leafKey = Crypto.EcdsaProvider.GenerateP256();
            var leafCertDer = AttestationCertificateFactory.CreateAttestationLeaf(leafKey, intermediateKey, intermediateCertDer, Aaguid);

            File.WriteAllBytes(leafKeyPath, AesKeyProtector.Encrypt(_aesKey, leafKey.ExportPkcs8PrivateKey()));
            File.WriteAllBytes(leafCertPath, leafCertDer);

            return new AttestationCertificate(AttestationKeyHandle, new[] { leafCertDer, intermediateCertDer });
        }

        private byte[] GetOrCreateIntermediateCert()
        {
            var intermediateCertPath = Path.Combine(_directory, AttestationIntermediateCertFileName);
            if (File.Exists(intermediateCertPath))
                return File.ReadAllBytes(intermediateCertPath);

            var rootCertDer = GetOrCreateRootCert();
            using var rootKey = LoadPrivateKey(Path.Combine(_directory, AttestationRootKeyFileName));

            var intermediateKey = Crypto.EcdsaProvider.GenerateP256();
            var intermediateCertDer = AttestationCertificateFactory.CreateIntermediate(intermediateKey, rootKey, rootCertDer);

            File.WriteAllBytes(Path.Combine(_directory, AttestationIntermediateKeyFileName), AesKeyProtector.Encrypt(_aesKey, intermediateKey.ExportPkcs8PrivateKey()));
            File.WriteAllBytes(intermediateCertPath, intermediateCertDer);

            return intermediateCertDer;
        }

        private byte[] GetOrCreateRootCert()
        {
            var rootCertPath = Path.Combine(_directory, AttestationRootCertFileName);
            if (File.Exists(rootCertPath))
                return File.ReadAllBytes(rootCertPath);

            var rootKey = Crypto.EcdsaProvider.GenerateP256();
            var rootCertDer = AttestationCertificateFactory.CreateSelfSignedRoot(rootKey);

            File.WriteAllBytes(Path.Combine(_directory, AttestationRootKeyFileName), AesKeyProtector.Encrypt(_aesKey, rootKey.ExportPkcs8PrivateKey()));
            File.WriteAllBytes(rootCertPath, rootCertDer);

            return rootCertDer;
        }

        private ECDsa LoadPrivateKey(string path)
        {
            var plaintext = AesKeyProtector.Decrypt(_aesKey, File.ReadAllBytes(path));
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(plaintext, out _);
            return ecdsa;
        }

        /// <summary>
        /// Fixed handle for the leaf attestation key, distinguishing it from the random
        /// per-credential Guids <see cref="CreateEs256Key"/> hands out so <see cref="LoadKey"/> can
        /// route to the fixed <see cref="AttestationKeyFileName"/> instead of a "{guid}.key" file.
        /// </summary>
        private static readonly Guid AttestationKeyGuid = new("00000000-0000-0000-0000-000000000001");
        private static byte[] AttestationKeyHandle => AttestationKeyGuid.ToByteArray();

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

        private string KeyFilePath(Guid keyId) => keyId == AttestationKeyGuid
            ? Path.Combine(_directory, AttestationKeyFileName)
            : Path.Combine(_directory, keyId + KeyFileExtension);

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
