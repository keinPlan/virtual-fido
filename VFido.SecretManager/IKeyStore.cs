namespace VFido.SecretManager
{
    /// <summary>
    /// Creates and reloads credential signing keys. This is the seam different secret backends
    /// implement (file-based, TPM-based, server-based): CreateEs256Key() would ask the backend
    /// for a key and LoadKey() would rehydrate a wrapper around its persistent handle, keeping
    /// ICredentialStore and Fido2Authenticator unaware of where keys actually live.
    /// </summary>
    public interface IKeyStore
    {
        ISigningKey CreateEs256Key();
        ISigningKey LoadKey(byte[] handle);
    }
}
