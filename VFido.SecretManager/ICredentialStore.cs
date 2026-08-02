namespace VFido.SecretManager
{
    public interface ICredentialStore
    {
        void Save(StoredCredential credential);
        StoredCredential? Find(byte[] credentialId);
        IReadOnlyList<StoredCredential> FindByRp(string rpId);
        IReadOnlyList<StoredCredential> FindAll();
        void Delete(byte[] credentialId);
    }
}
