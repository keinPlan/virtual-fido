using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using VFido.SecretManager.FileBasedSecretStore;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer.Pki
{
    /// <summary>
    /// Owns the two-tier CA (root + intermediate) that issues this server's own TLS certificate and
    /// every client's mTLS leaf certificate. Root/intermediate private keys are only ever touched by
    /// the admin CLI (init/create-user/revoke-user) - the running server never decrypts them, it only
    /// loads the already-issued public certs/PFXs those commands produced.
    ///
    /// Private keys are protected with the exact same primitive <see cref="FileBasedSecretStore"/>
    /// uses for per-user passwords (PBKDF2-SHA256 + AES-256-GCM + a known-plaintext verifier), just
    /// keyed off a standalone passphrase instead of a username+password pair - one crypto primitive
    /// for the whole server instead of two.
    /// </summary>
    public sealed class CaManager
    {
        private const string RootCertFile = "root.crt";
        private const string RootKeyFile = "root.key.enc";
        private const string IntermediateCertFile = "intermediate.crt";
        private const string IntermediateKeyFile = "intermediate.key.enc";
        private const string MasterProtectionPfxFile = "master-protection.pfx";

        private const string RootSubjectName = "CN=VFido mTLS Root CA";
        private const string IntermediateSubjectName = "CN=VFido mTLS Intermediate CA, O=VFido";
        private static readonly TimeSpan CaValidity = TimeSpan.FromDays(20 * 365);
        private static readonly TimeSpan LeafValidity = TimeSpan.FromDays(2 * 365);

        private readonly string _pkiRoot;

        public CaManager(string pkiRoot)
        {
            _pkiRoot = pkiRoot;
            Directory.CreateDirectory(_pkiRoot);
        }

        public bool IsInitialized =>
            File.Exists(Path.Combine(_pkiRoot, RootCertFile)) && File.Exists(Path.Combine(_pkiRoot, IntermediateCertFile));

        /// <summary>Creates the root and intermediate CA if they don't already exist. Safe to call repeatedly - a no-op once initialized.</summary>
        public void EnsureRootAndIntermediate(string passphrase)
        {
            var aesKey = DeriveAndVerifyPassphraseKey(passphrase);

            if (File.Exists(Path.Combine(_pkiRoot, RootCertFile)))
                return;

            using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var rootCertDer = CreateSelfSignedRoot(rootKey);
            File.WriteAllBytes(Path.Combine(_pkiRoot, RootCertFile), rootCertDer);
            File.WriteAllBytes(Path.Combine(_pkiRoot, RootKeyFile), AesKeyProtector.Encrypt(aesKey, rootKey.ExportPkcs8PrivateKey()));

            using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var intermediateCertDer = CreateIntermediate(intermediateKey, rootKey, rootCertDer);
            File.WriteAllBytes(Path.Combine(_pkiRoot, IntermediateCertFile), intermediateCertDer);
            File.WriteAllBytes(Path.Combine(_pkiRoot, IntermediateKeyFile), AesKeyProtector.Encrypt(aesKey, intermediateKey.ExportPkcs8PrivateKey()));
        }

        public byte[] ExportIntermediateCertificate() => File.ReadAllBytes(Path.Combine(_pkiRoot, IntermediateCertFile));

        /// <summary>Issues the server's own TLS leaf certificate, exported as a password-protected PFX.</summary>
        public byte[] IssueServerCertificate(string passphrase, string subjectName, string? pfxPassword)
        {
            using var intermediate = LoadIntermediate(passphrase);
            using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var leaf = IssueLeaf($"CN={subjectName}", leafKey, intermediate,
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
            using var leafWithKey = leaf.CopyWithPrivateKey(leafKey);
            return leafWithKey.Export(X509ContentType.Pfx, pfxPassword);
        }

        /// <summary>Issues a client mTLS leaf certificate with <c>CN=&lt;username&gt;</c> (the identity the server binds a login/session to), exported as a password-protected PFX.</summary>
        public byte[] IssueClientCertificate(string username, string passphrase, string? pfxPassword)
        {
            using var intermediate = LoadIntermediate(passphrase);
            using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var leaf = IssueLeaf($"CN={username}", leafKey, intermediate,
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
            using var leafWithKey = leaf.CopyWithPrivateKey(leafKey);
            return leafWithKey.Export(X509ContentType.Pfx, pfxPassword);
        }

        /// <summary>
        /// Self-signed certificate used solely to protect the ASP.NET Core Data Protection key ring
        /// that wraps passwordless users' per-user keys. Unlike the CA keys above, the running server
        /// must load this unattended on every startup (it's not an offline admin-only operation), so
        /// it's stored like the server's own TLS PFX - protected by file permissions, not a passphrase.
        /// RSA (not ECDsa like the CA hierarchy) because ASP.NET Core's CertificateXmlEncryptor goes
        /// through System.Security.Cryptography.Xml.EncryptedXml, which only supports RSA certificates.
        /// </summary>
        public void EnsureMasterProtectionCertificate()
        {
            var path = Path.Combine(_pkiRoot, MasterProtectionPfxFile);
            if (File.Exists(path))
                return;

            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=VFido Data Protection Key Ring", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            using var cert = request.CreateSelfSigned(notBefore, notBefore + CaValidity);
            File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx));
        }

        public X509Certificate2 LoadMasterProtectionCertificate() =>
            new(Path.Combine(_pkiRoot, MasterProtectionPfxFile));

        public void Revoke(string serialNumberHex) => RevocationStore.Add(_pkiRoot, serialNumberHex);

        private X509Certificate2 LoadIntermediate(string passphrase)
        {
            var aesKey = DeriveAndVerifyPassphraseKey(passphrase);
            var certDer = File.ReadAllBytes(Path.Combine(_pkiRoot, IntermediateCertFile));
            var keyPlaintext = AesKeyProtector.Decrypt(aesKey, File.ReadAllBytes(Path.Combine(_pkiRoot, IntermediateKeyFile)));

            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(keyPlaintext, out _);
            using var cert = new X509Certificate2(certDer);
            return cert.CopyWithPrivateKey(ecdsa);
        }

        private byte[] DeriveAndVerifyPassphraseKey(string passphrase)
        {
            const string saltFile = "salt.bin";
            var saltPath = Path.Combine(_pkiRoot, saltFile);
            var isNew = !File.Exists(saltPath);

            byte[] salt;
            if (isNew)
            {
                salt = RandomNumberGenerator.GetBytes(16);
                File.WriteAllBytes(saltPath, salt);
            }
            else
            {
                salt = File.ReadAllBytes(saltPath);
            }

            var aesKey = AesKeyProtector.DeriveKey("ca", passphrase, salt);
            PasswordVerifier.EnsureOrVerify(_pkiRoot, aesKey, isNew);
            return aesKey;
        }

        private static byte[] CreateSelfSignedRoot(ECDsa rootKey)
        {
            var request = new CertificateRequest(RootSubjectName, rootKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            using var root = request.CreateSelfSigned(notBefore, notBefore + CaValidity);
            return root.Export(X509ContentType.Cert);
        }

        private static byte[] CreateIntermediate(ECDsa intermediateKey, ECDsa rootKey, byte[] rootCertificateDer)
        {
            var request = new CertificateRequest(IntermediateSubjectName, intermediateKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

            using var root = new X509Certificate2(rootCertificateDer);
            using var rootWithKey = root.CopyWithPrivateKey(rootKey);
            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            var serialNumber = RandomNumberGenerator.GetBytes(16);
            using var issued = request.Create(rootWithKey, notBefore, notBefore + CaValidity, serialNumber);
            return issued.Export(X509ContentType.Cert);
        }

        private static X509Certificate2 IssueLeaf(string subjectName, ECDsa leafKey, X509Certificate2 intermediateWithKey, X509KeyUsageExtension keyUsage)
        {
            var request = new CertificateRequest(subjectName, leafKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
            request.CertificateExtensions.Add(keyUsage);
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            var serialNumber = RandomNumberGenerator.GetBytes(16);
            return request.Create(intermediateWithKey, notBefore, notBefore + LeafValidity, serialNumber);
        }
    }
}
