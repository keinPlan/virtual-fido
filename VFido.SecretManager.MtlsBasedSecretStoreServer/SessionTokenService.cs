using System.Collections.Concurrent;
using System.Security.Cryptography;
using VFido.SecretManager;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>Issues and validates the opaque bearer tokens handed out after a successful login.</summary>
    public sealed class SessionTokenService
    {
        private readonly TimeSpan _lifetime;
        private readonly ConcurrentDictionary<string, Session> _sessions = new();

        public SessionTokenService(TimeSpan lifetime) => _lifetime = lifetime;

        public LoginResponse IssueToken(string username)
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var expiresAt = DateTimeOffset.UtcNow + _lifetime;
            _sessions[token] = new Session(username, expiresAt);
            return new LoginResponse(token, expiresAt);
        }

        public bool TryValidate(string? token, out string username)
        {
            username = string.Empty;
            if (string.IsNullOrEmpty(token) || !_sessions.TryGetValue(token, out var session))
                return false;

            if (DateTimeOffset.UtcNow >= session.ExpiresAt)
            {
                _sessions.TryRemove(token, out _);
                return false;
            }

            username = session.Username;
            return true;
        }

        private sealed record Session(string Username, DateTimeOffset ExpiresAt);
    }
}
