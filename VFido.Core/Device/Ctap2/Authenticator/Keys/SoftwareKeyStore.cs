using System.Security.Cryptography;
using VFido.Core.Device.Ctap2.Authenticator.Crypto;

namespace VFido.Core.Device.Ctap2.Authenticator.Keys
{
    /// <summary>In-process P-256 keys. Default provider until a TPM-backed IKeyStore replaces it.</summary>
    internal class SoftwareKeyStore : IKeyStore
    {
        public ISigningKey CreateEs256Key() => new SoftwareEcdsaSigningKey(EcdsaProvider.GenerateP256());

        public ISigningKey LoadKey(byte[] handle)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(handle, out _);
            return new SoftwareEcdsaSigningKey(ecdsa);
        }
    }
}
