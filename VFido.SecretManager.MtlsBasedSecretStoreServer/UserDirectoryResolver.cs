using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>
    /// Maps a username to its on-disk layout under <see cref="MtlsBasedSecretStoreServerOptions.SecretsRootPath"/>
    /// (<c>&lt;username&gt;\{keys,credentials,certs}</c>, the same convention the GUI's StickConfigStore uses
    /// client-side) and builds the <see cref="IFido2SecretManager"/> for it - either from a login
    /// password (verified via the store's own <see cref="InvalidCredentialsException"/> check) or,
    /// for passwordless identities, from a Data-Protection-wrapped random key.
    /// </summary>
    public sealed class UserDirectoryResolver
    {
        private readonly string _secretsRoot;
        private readonly UserKeyProtector _keyProtector;

        public UserDirectoryResolver(MtlsBasedSecretStoreServerOptions options, UserKeyProtector keyProtector)
        {
            _secretsRoot = options.SecretsRootPath;
            _keyProtector = keyProtector;
        }

        public string GetUserDirectory(string username) => Path.Combine(_secretsRoot, username);

        public bool UserExists(string username) => Directory.Exists(GetUserDirectory(username));

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
            return new Fido2SecretManager(keyStore, credentialStore);
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
            return new Fido2SecretManager(keyStore, credentialStore);
        }
    }
}
