using System.Security.Cryptography;

namespace VFido.SecretManager.MemoryBasedSecretStore
{
    /// <summary>
    /// In-process P-256 keys, held only for the process lifetime. Default provider until a
    /// TPM- or server-backed IKeyStore replaces it; on-disk persistence is a separate future
    /// implementation of this same seam, not this class.
    /// </summary>
    public class MemoryBasedSecretStore : IKeyStore
    {
        public ISigningKey CreateEs256Key() => new MemoryBasedSigningKey(Crypto.EcdsaProvider.GenerateP256());

        public ISigningKey LoadKey(byte[] handle)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(handle, out _);
            return new MemoryBasedSigningKey(ecdsa);
        }
    }
}
