using System.Security.Cryptography;
using VFido.Core.Device.Ctap2.Authenticator.Crypto;

namespace VFido.Core.Device.Ctap2.Authenticator.Keys
{
    internal class SoftwareEcdsaSigningKey : ISigningKey
    {
        private const int AlgEs256 = -7;

        private readonly ECDsa _ecdsa;

        internal SoftwareEcdsaSigningKey(ECDsa ecdsa)
        {
            _ecdsa = ecdsa;
        }

        public int CoseAlgorithm => AlgEs256;

        public byte[] Sign(byte[] data) => EcdsaProvider.SignDerSha256(_ecdsa, data);

        public byte[] ExportCosePublicKey() => CoseKeyEncoder.Encode(_ecdsa.ExportParameters(includePrivateParameters: false));

        public byte[] ExportHandle() => _ecdsa.ExportPkcs8PrivateKey();
    }
}
