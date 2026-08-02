using System.Security.Cryptography;

namespace VFido.SecretManager.MemoryBasedSecretStore
{
    /// <summary>
    /// Username/password store for the process lifetime, salted+hashed with PBKDF2. Default
    /// provider until a real identity backend (AD, IdP) replaces it; users are seeded at startup
    /// by the caller.
    /// </summary>
    public sealed class InMemoryUserCredentialStore : IUserCredentialStore
    {
        private const int SaltSize = 16;
        private const int HashSize = 32;
        private const int Iterations = 100_000;

        private readonly Dictionary<string, (byte[] Salt, byte[] Hash)> _users = new();

        public void AddUser(string username, string password)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
            _users[username] = (salt, hash);
        }

        public bool Validate(string username, string password)
        {
            if (!_users.TryGetValue(username, out var entry))
                return false;

            var candidate = Rfc2898DeriveBytes.Pbkdf2(password, entry.Salt, Iterations, HashAlgorithmName.SHA256, HashSize);
            return CryptographicOperations.FixedTimeEquals(candidate, entry.Hash);
        }
    }
}
