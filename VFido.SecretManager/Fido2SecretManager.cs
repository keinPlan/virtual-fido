using System.Security.Cryptography;

namespace VFido.SecretManager
{
    /// <summary>
    /// Default <see cref="IFido2SecretManager"/> implementation: composes a pluggable
    /// <see cref="IKeyStore"/> (where key material actually lives) with a pluggable
    /// <see cref="ICredentialStore"/> (where credential metadata + key handles are kept).
    /// Neither store is ever exposed past this class. Both stores are in-process here, so every
    /// method completes synchronously under the Task wrapper; a remote implementation of
    /// IFido2SecretManager would await a network call instead.
    /// </summary>
    public sealed partial class Fido2SecretManager : IFido2SecretManager, IPasskeyBackupManager, IDisposable
    {
        private readonly object _sync = new();
        private readonly IKeyStore _keys;
        private readonly ICredentialStore _credentials;
        private readonly IPinStateStore? _pinState;

        private readonly bool _ownsKeyStore;
        private bool _disposed;

        public Fido2SecretManager(IKeyStore keys, ICredentialStore credentials, IPinStateStore? pinState = null, bool ownsKeyStore = false)
        {
            _keys = keys;
            _credentials = credentials;
            _pinState = pinState ?? keys as IPinStateStore;
            _ownsKeyStore = ownsKeyStore;
        }

        public Task<byte[]> GetAaguidAsync()
        {
            lock (_sync) { ThrowIfDisposed(); return Task.FromResult(_keys.Aaguid); }
        }

        public Task<CredentialRegistration> CreateCredentialAsync(string rpId, byte[] userId, string userName, string userDisplayName, bool isResident, int credProtect)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                var key = _keys.CreateEs256Key();
                var credentialId = RandomNumberGenerator.GetBytes(32);

                _credentials.Save(new StoredCredential
                {
                    CredentialId = credentialId,
                    RpId = rpId,
                    UserId = userId,
                    KeyHandle = key.ExportHandle(),
                    SignCount = 0,
                    IsResident = isResident,
                    UserName = userName,
                    UserDisplayName = userDisplayName,
                    CredProtect = credProtect,
                });

                return Task.FromResult(new CredentialRegistration(credentialId, key.ExportCosePublicKey(), key.CoseAlgorithm));
            }
        }

        public Task<bool> CredentialExistsAsync(byte[] credentialId, string rpId)
        {
            lock (_sync) { ThrowIfDisposed(); return Task.FromResult(_credentials.Find(credentialId) is { } credential && credential.RpId == rpId); }
        }

        public Task<CredentialInfo?> FindCredentialAsync(byte[] credentialId, string rpId)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                var credential = _credentials.Find(credentialId);
                return Task.FromResult(credential != null && credential.RpId == rpId ? ToInfo(credential) : null);
            }
        }

        public Task<IReadOnlyList<CredentialInfo>> FindResidentCredentialsAsync(string rpId)
        {
            lock (_sync) { ThrowIfDisposed(); return Task.FromResult<IReadOnlyList<CredentialInfo>>(_credentials.FindByRp(rpId).Where(c => c.IsResident).Select(ToInfo).ToList()); }
        }

        public Task<IReadOnlyList<CredentialInfo>> FindAllCredentialsAsync()
        {
            lock (_sync) { ThrowIfDisposed(); return Task.FromResult<IReadOnlyList<CredentialInfo>>(_credentials.FindAll().Select(ToInfo).ToList()); }
        }

        public Task DeleteCredentialAsync(byte[] credentialId)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                if (_credentials.Find(credentialId) is { } credential)
                    _keys.DeleteKey(credential.KeyHandle);

                _credentials.Delete(credentialId);
                return Task.CompletedTask;
            }
        }

        public Task<uint> IncrementSignCountAsync(byte[] credentialId)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                var credential = RequireCredential(credentialId);
                if (credential.DisableSignCount) return Task.FromResult(0u);
                credential.SignCount++;
                // Must persist explicitly: ICredentialStore.Find isn't guaranteed to return a live,
                // shared reference (InMemoryCredentialStore does; FileBasedCredentialStore decodes a
                // fresh copy from disk every call), so mutating in place alone can silently lose the
                // increment and make every login look like a replay of a previous sign count.
                _credentials.Save(credential);
                return Task.FromResult(credential.SignCount);
            }
        }

        public Task<byte[]> SignAsync(byte[] credentialId, byte[] data)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                var credential = RequireCredential(credentialId);
                return Task.FromResult(_keys.LoadKey(credential.KeyHandle).Sign(data));
            }
        }

        public Task<IReadOnlyList<byte[]>> GetAttestationCertificateChainAsync()
        {
            lock (_sync) { ThrowIfDisposed(); return Task.FromResult(_keys.GetOrCreateAttestationCertificate().CertificateChainDer); }
        }

        public Task<byte[]> SignWithAttestationKeyAsync(byte[] data)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                var attestation = _keys.GetOrCreateAttestationCertificate();
                return Task.FromResult(_keys.LoadKey(attestation.KeyHandle).Sign(data));
            }
        }

        public Task<PinState?> LoadPinStateAsync()
        {
            lock (_sync) { ThrowIfDisposed(); return Task.FromResult(_pinState?.Load()); }
        }

        public Task SavePinStateAsync(PinState state)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                _pinState?.Save(state);
                return Task.CompletedTask;
            }
        }

        private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                if (_ownsKeyStore) (_keys as IDisposable)?.Dispose();
            }
        }
        private StoredCredential RequireCredential(byte[] credentialId) =>
            _credentials.Find(credentialId) ?? throw new InvalidOperationException("Unknown credential.");

        private static CredentialInfo ToInfo(StoredCredential credential) => new(
            credential.CredentialId, credential.RpId, credential.UserId,
            credential.UserName, credential.UserDisplayName, credential.IsResident, credential.SignCount, credential.CredProtect);
    }
}
