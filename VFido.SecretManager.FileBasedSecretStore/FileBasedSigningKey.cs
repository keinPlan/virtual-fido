using System.Security.Cryptography;
using VFido.SecretManager.Crypto;

namespace VFido.SecretManager.FileBasedSecretStore
{
    public class FileBasedSigningKey : ISigningKey
    {
        private const int AlgEs256 = -7;

        private readonly ECDsa _ecdsa;
        private readonly Guid _keyId;

        public FileBasedSigningKey(ECDsa ecdsa, Guid keyId)
        {
            _ecdsa = ecdsa;
            _keyId = keyId;
        }

        public int CoseAlgorithm => AlgEs256;

        public byte[] Sign(byte[] data) => EcdsaProvider.SignDerSha256(_ecdsa, data);

        public byte[] ExportCosePublicKey() => CoseKeyEncoder.Encode(_ecdsa.ExportParameters(includePrivateParameters: false));

        /// <summary>Opaque reference to the encrypted key file on disk - never raw key material.</summary>
        public byte[] ExportHandle() => _keyId.ToByteArray();
    }
}
