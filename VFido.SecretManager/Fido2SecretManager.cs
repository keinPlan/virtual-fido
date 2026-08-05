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
    public sealed class Fido2SecretManager : IFido2SecretManager
    {
        private readonly IKeyStore _keys;
        private readonly ICredentialStore _credentials;
        private readonly IPinStateStore? _pinState;

        public Fido2SecretManager(IKeyStore keys, ICredentialStore credentials)
        {
            _keys = keys;
            _credentials = credentials;
            // FileBasedSecretStore (the only IKeyStore that persists) implements IPinStateStore too -
            // detecting it here means PIN persistence "just works" for any IKeyStore that opts in,
            // without every caller having to thread a separate store through by hand.
            _pinState = keys as IPinStateStore;
        }

        public Task<byte[]> GetAaguidAsync() => Task.FromResult(_keys.Aaguid);

        public Task<CredentialRegistration> CreateCredentialAsync(string rpId, byte[] userId, string userName, string userDisplayName, bool isResident, int credProtect)
        {
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

        public Task<bool> CredentialExistsAsync(byte[] credentialId, string rpId) =>
            Task.FromResult(_credentials.Find(credentialId) is { } credential && credential.RpId == rpId);

        public Task<CredentialInfo?> FindCredentialAsync(byte[] credentialId, string rpId)
        {
            var credential = _credentials.Find(credentialId);
            return Task.FromResult(credential != null && credential.RpId == rpId ? ToInfo(credential) : null);
        }

        public Task<IReadOnlyList<CredentialInfo>> FindResidentCredentialsAsync(string rpId) =>
            Task.FromResult<IReadOnlyList<CredentialInfo>>(_credentials.FindByRp(rpId).Where(c => c.IsResident).Select(ToInfo).ToList());

        public Task<IReadOnlyList<CredentialInfo>> FindAllCredentialsAsync() =>
            Task.FromResult<IReadOnlyList<CredentialInfo>>(_credentials.FindAll().Select(ToInfo).ToList());

        public Task DeleteCredentialAsync(byte[] credentialId)
        {
            if (_credentials.Find(credentialId) is { } credential)
                _keys.DeleteKey(credential.KeyHandle);

            _credentials.Delete(credentialId);
            return Task.CompletedTask;
        }

        public Task<uint> IncrementSignCountAsync(byte[] credentialId)
        {
            var credential = RequireCredential(credentialId);
            credential.SignCount++;
            // Must persist explicitly: ICredentialStore.Find isn't guaranteed to return a live,
            // shared reference (InMemoryCredentialStore does; FileBasedCredentialStore decodes a
            // fresh copy from disk every call), so mutating in place alone can silently lose the
            // increment and make every login look like a replay of a previous sign count.
            _credentials.Save(credential);
            return Task.FromResult(credential.SignCount);
        }

        public Task<byte[]> SignAsync(byte[] credentialId, byte[] data)
        {
            var credential = RequireCredential(credentialId);
            return Task.FromResult(_keys.LoadKey(credential.KeyHandle).Sign(data));
        }

        public Task<IReadOnlyList<byte[]>> GetAttestationCertificateChainAsync() =>
            Task.FromResult(_keys.GetOrCreateAttestationCertificate().CertificateChainDer);

        public Task<byte[]> SignWithAttestationKeyAsync(byte[] data)
        {
            var attestation = _keys.GetOrCreateAttestationCertificate();
            return Task.FromResult(_keys.LoadKey(attestation.KeyHandle).Sign(data));
        }

        public Task<PinState?> LoadPinStateAsync() => Task.FromResult(_pinState?.Load());

        public Task SavePinStateAsync(PinState state)
        {
            _pinState?.Save(state);
            return Task.CompletedTask;
        }

        private StoredCredential RequireCredential(byte[] credentialId) =>
            _credentials.Find(credentialId) ?? throw new InvalidOperationException("Unknown credential.");

        private static CredentialInfo ToInfo(StoredCredential credential) => new(
            credential.CredentialId, credential.RpId, credential.UserId,
            credential.UserName, credential.UserDisplayName, credential.IsResident, credential.SignCount, credential.CredProtect);
    }
}
