using System.Security.Cryptography;
using VFido.SecretManager.Crypto;

namespace VFido.SecretManager.MemoryBasedSecretStore
{
    /// <summary>
    /// In-process P-256 keys, held only for the process lifetime. Default provider until a
    /// TPM- or server-backed IKeyStore replaces it; on-disk persistence is a separate future
    /// implementation of this same seam, not this class.
    /// </summary>
    public class MemoryBasedSecretStore : IKeyStore
    {
        /// <summary>Fixed AAGUID identifying every stick backed by this store type.</summary>
        private static readonly Guid AaguidGuid = new("6d90ff30-1e3a-4c6a-8b7b-9a4e6a2c9f30");

        private AttestationCertificate? _attestationCertificate;

        // Guid.ToByteArray() emits .NET's native mixed-endian layout (first three fields
        // little-endian), which scrambles the hyphenated hex an RP displays for the AAGUID field -
        // it must be the raw 16 bytes in RFC 4122 (big-endian) order instead.
        public byte[] Aaguid => AaguidGuid.ToByteArray(bigEndian: true);

        public ISigningKey CreateEs256Key() => new MemoryBasedSigningKey(Crypto.EcdsaProvider.GenerateP256());

        public ISigningKey LoadKey(byte[] handle)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(handle, out _);
            return new MemoryBasedSigningKey(ecdsa);
        }

        public AttestationCertificate GetOrCreateAttestationCertificate()
        {
            if (_attestationCertificate != null)
                return _attestationCertificate;

            using var rootKey = Crypto.EcdsaProvider.GenerateP256();
            var rootCertDer = AttestationCertificateFactory.CreateSelfSignedRoot(rootKey);

            using var intermediateKey = Crypto.EcdsaProvider.GenerateP256();
            var intermediateCertDer = AttestationCertificateFactory.CreateIntermediate(intermediateKey, rootKey, rootCertDer);

            var leafKey = Crypto.EcdsaProvider.GenerateP256();
            var leafCertDer = AttestationCertificateFactory.CreateAttestationLeaf(leafKey, intermediateKey, intermediateCertDer, Aaguid);

            _attestationCertificate = new AttestationCertificate(leafKey.ExportPkcs8PrivateKey(), new[] { leafCertDer, intermediateCertDer });
            return _attestationCertificate;
        }
    }
}
