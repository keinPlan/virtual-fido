using System.Security.Cryptography;
using VFido.SecretManager.Crypto;

namespace VFido.SecretManager.MemoryBasedSecretStore
{
    public class MemoryBasedSigningKey : ISigningKey
    {
        private const int AlgEs256 = -7;

        private readonly ECDsa _ecdsa;

        public MemoryBasedSigningKey(ECDsa ecdsa)
        {
            _ecdsa = ecdsa;
        }

        public int CoseAlgorithm => AlgEs256;

        public byte[] Sign(byte[] data) => EcdsaProvider.SignDerSha256(_ecdsa, data);

        public byte[] ExportCosePublicKey() => CoseKeyEncoder.Encode(_ecdsa.ExportParameters(includePrivateParameters: false));

        public byte[] ExportHandle() => _ecdsa.ExportPkcs8PrivateKey();
    }
}
