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
        private readonly object _sync = new();
        private readonly Dictionary<string, IFido2SecretManager> _managers = new(StringComparer.Ordinal);

        public UserDirectoryResolver(MtlsBasedSecretStoreServerOptions options, UserKeyProtector keyProtector)
        {
            _secretsRoot = options.SecretsRootPath;
            _keyProtector = keyProtector;
            _provider = options.StorageProvider;
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
        public IFido2SecretManager BuildManagerFromPassword(string username, string password)
        {
            var userDirectory = GetUserDirectory(username);
            var keyStore = new VFido.SecretManager.FileBasedSecretStore.FileBasedSecretStore(
                Path.Combine(userDirectory, "keys"), username, password, Path.Combine(userDirectory, "certs"), userDirectory);
            var credentialStore = new FileBasedCredentialStore(
                Path.Combine(userDirectory, "credentials"), username, password, userDirectory);
            // FileBasedSecretStore also implements IPinStateStore; Fido2SecretManager detects and
            // forwards LoadPinStateAsync/SavePinStateAsync to it automatically.
            return BuildManager(username, keyStore, credentialStore,
                () => new TpmBasedCredentialStore(Path.Combine(userDirectory, "tpm", "credentials"), username, password, userDirectory));
        }

        public IFido2SecretManager BuildPasswordlessManager(string username)
        {
            var userDirectory = GetUserDirectory(username);
            Directory.CreateDirectory(userDirectory);
            var key = _keyProtector.GetOrCreateKey(userDirectory);

            var keyStore = new VFido.SecretManager.FileBasedSecretStore.FileBasedSecretStore(
                Path.Combine(userDirectory, "keys"), key, Path.Combine(userDirectory, "certs"), userDirectory);
            var credentialStore = new FileBasedCredentialStore(
                Path.Combine(userDirectory, "credentials"), key, userDirectory);
            return BuildManager(username, keyStore, credentialStore,
                () => new TpmBasedCredentialStore(Path.Combine(userDirectory, "tpm", "credentials"), key, userDirectory));
        }

        private IFido2SecretManager BuildManager(string username,
            VFido.SecretManager.FileBasedSecretStore.FileBasedSecretStore fileKeys,
            FileBasedCredentialStore fileCredentials, Func<ICredentialStore> tpmCredentials)
        {
            if (_provider == ServerStorageProvider.File)
                return new Fido2SecretManager(fileKeys, fileCredentials);

            // Password verification above must run on every login, including cache hits.
            lock (_sync)
            {
                if (_managers.TryGetValue(username, out var existing)) return existing;
                IFido2SecretManager manager;
                if (_provider == ServerStorageProvider.Memory)
                {
                    manager = new Fido2SecretManager(new MemoryBasedSecretStore.MemoryBasedSecretStore(),
                        new InMemoryCredentialStore(), new MemoryPinStateStore());
                }
                else if (_provider == ServerStorageProvider.Tpm)
                {
                    var directory = Path.Combine(GetUserDirectory(username), "tpm", "keys");
                    // Separate protected authorization for unattended TPM access, also for password users.
                    var authorization = Convert.ToBase64String(_keyProtector.GetOrCreateKey(GetUserDirectory(username)));
                    if (!File.Exists(Path.Combine(directory, "master.json")))
                    {
                        using var master = TpmMasterKey.Generate();
                        TpmBasedSecretStore.TpmBasedSecretStore.Provision(directory, master, masterPassword: authorization);
                    }
                    var credentials = tpmCredentials();
                    var keys = new TpmBasedSecretStore.TpmBasedSecretStore(directory, masterPassword: authorization);
                    manager = new Fido2SecretManager(keys, credentials, fileKeys, ownsKeyStore: true);
                }
                else throw new InvalidOperationException("StorageProvider must be File, Tpm, or Memory.");
                _managers.Add(username, manager);
                return manager;
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
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
