using System.Security.Cryptography;
using VFido.SecretManager.Crypto;

namespace VFido.SecretManager.FileBasedSecretStore
{
    /// <summary>
    /// Persists P-256 keys to disk, one file per key, each AES-GCM encrypted with a key derived
    /// via PBKDF2(username, password, salt). The salt is generated once per stick and kept in
    /// plaintext under <see cref="_authDirectory"/> (shared with <see cref="FileBasedCredentialStore"/>)
    /// - it isn't secret, only the username and password (never persisted) are. Losing either makes
    /// every key file permanently unrecoverable, matching the TPM-backed stores this seam is meant
    /// to also support.
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
        private readonly string _attestationDirectory;
        private readonly string _authDirectory;
        private readonly byte[] _aesKey;

        // Guid.ToByteArray() emits .NET's native mixed-endian layout (first three fields
        // little-endian), which scrambles the hyphenated hex an RP displays for the AAGUID field -
        // it must be the raw 16 bytes in RFC 4122 (big-endian) order instead.
        public byte[] Aaguid => AaguidGuid.ToByteArray(bigEndian: true);

        /// <param name="authDirectory">
        /// Where salt.bin/verifier.bin live. Shared with <see cref="FileBasedCredentialStore"/> (via
        /// its own authDirectory parameter) so both stores derive the identical AES key from one
        /// username+password, instead of each keeping its own salt.
        /// </param>
        public FileBasedSecretStore(string directory, string username, string password, string? attestationDirectory = null, string? authDirectory = null)
        {
            _directory = directory;
            Directory.CreateDirectory(_directory);

            _attestationDirectory = attestationDirectory ?? directory;
            Directory.CreateDirectory(_attestationDirectory);

            _authDirectory = authDirectory ?? directory;
            Directory.CreateDirectory(_authDirectory);

            var isNewStore = !File.Exists(Path.Combine(_authDirectory, SaltFileName));
            var salt = LoadOrCreateSalt();
            _aesKey = AesKeyProtector.DeriveKey(username, password, salt);

            PasswordVerifier.EnsureOrVerify(_authDirectory, _aesKey, isNewStore);
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

            var leafCertPath = Path.Combine(_attestationDirectory, AttestationCertFileName);
            var leafKeyPath = KeyFilePath(AttestationKeyGuid);

            if (File.Exists(leafCertPath) && File.Exists(leafKeyPath))
                return new AttestationCertificate(AttestationKeyHandle, new[] { File.ReadAllBytes(leafCertPath), intermediateCertDer });

            using var intermediateKey = LoadPrivateKey(Path.Combine(_attestationDirectory, AttestationIntermediateKeyFileName));
            var leafKey = Crypto.EcdsaProvider.GenerateP256();
            var leafCertDer = AttestationCertificateFactory.CreateAttestationLeaf(leafKey, intermediateKey, intermediateCertDer, Aaguid);

            File.WriteAllBytes(leafKeyPath, AesKeyProtector.Encrypt(_aesKey, leafKey.ExportPkcs8PrivateKey()));
            File.WriteAllBytes(leafCertPath, leafCertDer);

            return new AttestationCertificate(AttestationKeyHandle, new[] { leafCertDer, intermediateCertDer });
        }

        private byte[] GetOrCreateIntermediateCert()
        {
            var intermediateCertPath = Path.Combine(_attestationDirectory, AttestationIntermediateCertFileName);
            if (File.Exists(intermediateCertPath))
                return File.ReadAllBytes(intermediateCertPath);

            var rootCertDer = GetOrCreateRootCert();
            using var rootKey = LoadPrivateKey(Path.Combine(_attestationDirectory, AttestationRootKeyFileName));

            var intermediateKey = Crypto.EcdsaProvider.GenerateP256();
            var intermediateCertDer = AttestationCertificateFactory.CreateIntermediate(intermediateKey, rootKey, rootCertDer);

            File.WriteAllBytes(Path.Combine(_attestationDirectory, AttestationIntermediateKeyFileName), AesKeyProtector.Encrypt(_aesKey, intermediateKey.ExportPkcs8PrivateKey()));
            File.WriteAllBytes(intermediateCertPath, intermediateCertDer);

            return intermediateCertDer;
        }

        private byte[] GetOrCreateRootCert()
        {
            var rootCertPath = Path.Combine(_attestationDirectory, AttestationRootCertFileName);
            if (File.Exists(rootCertPath))
                return File.ReadAllBytes(rootCertPath);

            var rootKey = Crypto.EcdsaProvider.GenerateP256();
            var rootCertDer = AttestationCertificateFactory.CreateSelfSignedRoot(rootKey);

            File.WriteAllBytes(Path.Combine(_attestationDirectory, AttestationRootKeyFileName), AesKeyProtector.Encrypt(_aesKey, rootKey.ExportPkcs8PrivateKey()));
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
            var path = Path.Combine(_authDirectory, PinStateFileName);
            if (!File.Exists(path))
                return null;

            var plaintext = AesKeyProtector.Decrypt(_aesKey, File.ReadAllBytes(path));
            return System.Text.Json.JsonSerializer.Deserialize<PinState>(plaintext);
        }

        public void Save(PinState state)
        {
            var plaintext = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(state);
            var encrypted = AesKeyProtector.Encrypt(_aesKey, plaintext);
            File.WriteAllBytes(Path.Combine(_authDirectory, PinStateFileName), encrypted);
        }

        public void DeleteKey(byte[] handle)
        {
            var path = KeyFilePath(new Guid(handle));
            if (File.Exists(path))
                File.Delete(path);
        }

        private string KeyFilePath(Guid keyId) => keyId == AttestationKeyGuid
            ? Path.Combine(_attestationDirectory, AttestationKeyFileName)
            : Path.Combine(_directory, keyId + KeyFileExtension);

        private byte[] LoadOrCreateSalt()
        {
            var saltPath = Path.Combine(_authDirectory, SaltFileName);
            if (File.Exists(saltPath))
                return File.ReadAllBytes(saltPath);

            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            File.WriteAllBytes(saltPath, salt);
            return salt;
        }
    }
}
