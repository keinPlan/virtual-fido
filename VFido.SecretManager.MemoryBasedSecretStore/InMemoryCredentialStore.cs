namespace VFido.SecretManager.MemoryBasedSecretStore
{
    /// <summary>
    /// Keeps credentials only for the process lifetime. Fine for M2 (non-resident keys the
    /// relying party gives back on every request); swap for a persisted store once Reset/
    /// discoverable credentials need to survive a restart.
    /// </summary>
    public class InMemoryCredentialStore : ICredentialStore
    {
        private readonly Dictionary<string, StoredCredential> _byId = new();

        public void Save(StoredCredential credential) => _byId[Key(credential.CredentialId)] = credential;

        public StoredCredential? Find(byte[] credentialId) =>
            _byId.TryGetValue(Key(credentialId), out var credential) ? credential : null;

        public IReadOnlyList<StoredCredential> FindByRp(string rpId) =>
            _byId.Values.Where(c => c.RpId == rpId).ToList();

        private static string Key(byte[] credentialId) => Convert.ToBase64String(credentialId);
    }
}
