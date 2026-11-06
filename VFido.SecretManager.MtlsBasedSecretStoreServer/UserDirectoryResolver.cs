using System.Security.Cryptography;
using VFido.SecretManager.Protection;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;
using VFido.SecretManager.MemoryBasedSecretStore;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>
    /// Maps a username to its on-disk layout under <see cref="MtlsBasedSecretStoreServerOptions.SecretsRootPath"/>
    /// (<c>&lt;username&gt;\{keys,credentials,certs}</c>, the same convention the GUI's StickConfigStore uses
    /// client-side) and builds the <see cref="IFido2SecretManager"/> for it - either from a login
    /// password (verified via the store's own <see cref="InvalidCredentialsException"/> check) or,
    /// for passwordless identities, from a Data-Protection-wrapped random key.
    /// </summary>
    public sealed class UserDirectoryResolver : IDisposable
    {
        private readonly string _secretsRoot;
        private readonly UserKeyProtector _keyProtector;
        private readonly ServerStorageProvider _provider;
        private readonly MtlsBasedSecretStoreServerOptions _options;
        private bool _disposed;
        private readonly object _sync = new();
        private readonly Dictionary<string, IFido2SecretManager> _managers = new(StringComparer.Ordinal);

        public UserDirectoryResolver(MtlsBasedSecretStoreServerOptions options, UserKeyProtector keyProtector)
        {
            _secretsRoot = options.SecretsRootPath;
            _keyProtector = keyProtector;
            _provider = options.StorageProvider;
            _options = options;
        }

        public string GetUserDirectory(string username) => Path.Combine(_secretsRoot, username);

        public bool UserExists(string username) => Directory.Exists(GetUserDirectory(username));

        public int GetMemoryCredentialCount(string username)
        {
            lock (_sync)
                return _managers.TryGetValue(username, out var manager)
                    ? manager.FindAllCredentialsAsync().GetAwaiter().GetResult().Count : 0;
        }

        /// <summary>A user directory created without a password (see <see cref="UserKeyProtector"/>) never gets a <c>verifier.bin</c> - its presence is what distinguishes the two modes.</summary>
        public bool RequiresPassword(string username) =>
            File.Exists(Path.Combine(GetUserDirectory(username), "verifier.bin"));

        /// <summary>Throws <see cref="InvalidCredentialsException"/> if the password doesn't match what the directory was created with.</summary>
        public IFido2SecretManager BuildManagerFromPassword(string username, string password) =>
            BuildManager(username, PasswordStorageProtection.Open(GetUserDirectory(username), username, password));

        public IFido2SecretManager BuildPasswordlessManager(string username)
        {
            var directory = GetUserDirectory(username);
            Directory.CreateDirectory(directory);
            var key = _keyProtector.GetOrCreateKey(directory);
            try { return BuildManager(username, new AesPayloadProtector(key)); }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        private IFido2SecretManager BuildManager(string username, AesPayloadProtector protection)
        {
            // Authentication/unlocking runs before cache lookup on every login.
            try
            {
                lock (_sync)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);
                    if (_managers.TryGetValue(username, out var existing))
                    {
                        protection.Dispose();
                        return existing;
                    }
                    var directory = GetUserDirectory(username);
                    IFido2SecretManager manager;
                    if (_provider == ServerStorageProvider.Memory)
                    {
                        protection.Dispose();
                        manager = new Fido2SecretManager(new MemoryBasedSecretStore.MemoryBasedSecretStore(),
                            new InMemoryCredentialStore(), new MemoryPinStateStore());
                    }
                    else
                    {
                        var encryptedFiles = new EncryptedFileStorage(protection);
                        IFileStorage credentialFiles = _options.EncryptCredentialFiles ? encryptedFiles : new PlainFileStorage();
                        var credentials = new FileBasedCredentialStore(Path.Combine(directory, "credentials"), credentialFiles);
                        var pin = new FilePinStateStore(directory, encryptedFiles);
                        IKeyStore keys;
                        if (_provider == ServerStorageProvider.File)
                            keys = new FileBasedSecretStore.FileBasedSecretStore(Path.Combine(directory, "keys"),
                                encryptedFiles, Path.Combine(directory, "certs"), directory);
                        else if (_provider == ServerStorageProvider.Tpm)
                        {
                            ServerTpmMaster.CopyToUser(_options, directory);
                            keys = new TpmBasedSecretStore.TpmBasedSecretStore(Path.Combine(directory, "keys"),
                                masterPassword: ServerTpmMaster.GetAuthorization(_options));
                        }
                        else throw new InvalidOperationException("StorageProvider must be File, Tpm, or Memory.");
                        manager = new Fido2SecretManager(keys, credentials, pin, ownsKeyStore: true, ownedStorage: protection);
                    }
                    _managers.Add(username, manager);
                    return manager;
                }
            }
            catch { protection.Dispose(); throw; }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                foreach (var manager in _managers.Values)
                    (manager as IDisposable)?.Dispose();
                _managers.Clear();
            }
        }

        private sealed class MemoryPinStateStore : IPinStateStore
        {
            private PinState? _state;
            public PinState? Load() => _state;
            public void Save(PinState state) => _state = state;
        }
    }
}
