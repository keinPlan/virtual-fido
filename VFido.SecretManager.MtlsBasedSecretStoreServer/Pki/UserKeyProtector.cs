using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer.Pki
{
    /// <summary>
    /// Gives passwordless users the same at-rest AES key their password-protected counterparts get
    /// via PBKDF2 - a random 32-byte key generated once, wrapped with ASP.NET Core Data Protection
    /// instead (there's no password to derive from). The key ring itself is protected by the master
    /// protection certificate (<see cref="CaManager.EnsureMasterProtectionCertificate"/>), configured
    /// once at server startup - this class just wraps/unwraps individual per-user keys through it.
    /// </summary>
    public sealed class UserKeyProtector
    {
        private const string WrappedKeyFileName = "wrapped.key";

        private readonly IDataProtector _protector;

        public UserKeyProtector(IDataProtectionProvider provider) =>
            _protector = provider.CreateProtector("VFido.SecretManager.MtlsBasedSecretStoreServer.UserKey");

        public byte[] GetOrCreateKey(string userDirectory)
        {
            var path = Path.Combine(userDirectory, WrappedKeyFileName);
            if (File.Exists(path))
                return Convert.FromBase64String(_protector.Unprotect(File.ReadAllText(path)));

            var key = RandomNumberGenerator.GetBytes(32);
            File.WriteAllText(path, _protector.Protect(Convert.ToBase64String(key)));
            return key;
        }

        public static bool HasWrappedKey(string userDirectory) =>
            File.Exists(Path.Combine(userDirectory, WrappedKeyFileName));
    }
}
