using System.Collections.Concurrent;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>
    /// Holds already-built <see cref="IFido2SecretManager"/> instances so the (possibly expensive,
    /// key-derivation-involving) per-user store construction happens once per session/identity rather
    /// than per request. Password users are keyed by bearer token (evicted on logout/expiry);
    /// passwordless users are keyed by username directly since there's no token/expiry for them.
    /// </summary>
    public sealed class UserSessionCache
    {
        private readonly ConcurrentDictionary<string, IFido2SecretManager> _byToken = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, IFido2SecretManager> _byUsername = new(StringComparer.Ordinal);

        public void SetForToken(string token, IFido2SecretManager manager) => _byToken[token] = manager;

        public bool TryGetForToken(string token, out IFido2SecretManager manager) => _byToken.TryGetValue(token, out manager!);

        public void EvictToken(string token) => _byToken.TryRemove(token, out _);

        public IFido2SecretManager GetOrAddForUsername(string username, Func<IFido2SecretManager> factory) =>
            _byUsername.GetOrAdd(username, _ => factory());
    }
}
