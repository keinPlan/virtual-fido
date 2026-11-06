using VFido.SecretManager.Protection;
using System.Security.Cryptography;
using VFido.SecretManager.Crypto;

namespace VFido.SecretManager.FileBasedSecretStore
{
    /// <summary>
    /// P-256 key persistence and attestation. Payload protection is injected through IFileStorage.
    /// Legacy password constructors and PIN methods remain as compatibility adapters.
    /// </summary>
    public class FileBasedSecretStore : IKeyStore, IPinStateStore, ICredentialKeyTransfer, IDisposable
    {
        private const string KeyFileExtension = ".key";
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
        private readonly IFileStorage _files;
        private readonly FilePinStateStore _pin;
        private IDisposable? _ownedProtection;

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
            : this(directory, PasswordStorageProtection.OpenOrCreate(authDirectory ?? directory, username, password), attestationDirectory, authDirectory) { }

        public FileBasedSecretStore(string directory, byte[] aesKey, string? attestationDirectory = null, string? authDirectory = null)
            : this(directory, new AesPayloadProtector(aesKey), attestationDirectory, authDirectory) { }

        private FileBasedSecretStore(string directory, AesPayloadProtector protector, string? attestationDirectory, string? authDirectory)
            : this(directory, new EncryptedFileStorage(protector), attestationDirectory, authDirectory) => _ownedProtection = protector;

        public FileBasedSecretStore(string directory, IFileStorage files, string? attestationDirectory = null, string? authDirectory = null)
        {
            if (!files.Encrypted) throw new ArgumentException("Private keys require protected storage.", nameof(files));
            _directory = directory;
            _attestationDirectory = attestationDirectory ?? directory;
            _authDirectory = authDirectory ?? directory;
            Directory.CreateDirectory(_directory);
            Directory.CreateDirectory(_attestationDirectory);
            _files = files;
            _pin = new FilePinStateStore(_authDirectory, files);
        }

        public byte[] ExportPkcs8(byte[] handle) =>
            _files.Read(KeyFilePath(new Guid(handle)));

        public byte[] ImportPkcs8(byte[] privateKey)
        {
            using var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(privateKey, out var read);
            if (read != privateKey.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new InvalidDataException("Only P-256 private keys are supported.");
            var keyId = Guid.NewGuid();
            var path = KeyFilePath(keyId);
            try { _files.Write(path, privateKey); }
            catch { File.Delete(path); throw; }
            return keyId.ToByteArray();
        }

        public ISigningKey CreateEs256Key()
        {
            var ecdsa = Crypto.EcdsaProvider.GenerateP256();
            var keyId = Guid.NewGuid();

            var plaintext = ecdsa.ExportPkcs8PrivateKey();
            _files.Write(KeyFilePath(keyId), plaintext);

            return new FileBasedSigningKey(ecdsa, keyId);
        }

        public ISigningKey LoadKey(byte[] handle)
        {
            var keyId = new Guid(handle);
            var plaintext = _files.Read(KeyFilePath(keyId));

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

            _files.Write(leafKeyPath, leafKey.ExportPkcs8PrivateKey());
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

            _files.Write(Path.Combine(_attestationDirectory, AttestationIntermediateKeyFileName), intermediateKey.ExportPkcs8PrivateKey());
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

            _files.Write(Path.Combine(_attestationDirectory, AttestationRootKeyFileName), rootKey.ExportPkcs8PrivateKey());
            File.WriteAllBytes(rootCertPath, rootCertDer);

            return rootCertDer;
        }

        private ECDsa LoadPrivateKey(string path)
        {
            var plaintext = _files.Read(path);
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

        // Compatibility for callers using the original combined key/PIN store.
        public PinState? Load() => _pin.Load();
        public void Save(PinState state) => _pin.Save(state);
        public void Dispose() => _ownedProtection?.Dispose();

        public void DeleteKey(byte[] handle)
        {
            var path = KeyFilePath(new Guid(handle));
            if (File.Exists(path))
                File.Delete(path);
        }

        private string KeyFilePath(Guid keyId) => keyId == AttestationKeyGuid
            ? Path.Combine(_attestationDirectory, AttestationKeyFileName)
            : Path.Combine(_directory, keyId + KeyFileExtension);

    }
}
