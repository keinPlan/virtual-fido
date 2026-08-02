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
        private AttestationCertificate? _attestationCertificate;

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
            var leafCertDer = AttestationCertificateFactory.CreateAttestationLeaf(leafKey, intermediateKey, intermediateCertDer);

            _attestationCertificate = new AttestationCertificate(leafKey.ExportPkcs8PrivateKey(), new[] { leafCertDer, intermediateCertDer });
            return _attestationCertificate;
        }
    }
}
