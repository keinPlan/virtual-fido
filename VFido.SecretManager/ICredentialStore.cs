namespace VFido.SecretManager
{
    public interface ICredentialStore
    {
        void Save(StoredCredential credential);
        StoredCredential? Find(byte[] credentialId);
        IReadOnlyList<StoredCredential> FindByRp(string rpId);
    }
}
