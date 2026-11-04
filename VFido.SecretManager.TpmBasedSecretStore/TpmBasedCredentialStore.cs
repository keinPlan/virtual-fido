namespace VFido.SecretManager.TpmBasedSecretStore;

/// <summary>Encrypted disk metadata; credential private keys remain TPM-wrapped in the key store.</summary>
public sealed class TpmBasedCredentialStore : FileBasedSecretStore.FileBasedCredentialStore
{
    public TpmBasedCredentialStore(string directory, byte[] metadataKey, string? authDirectory = null)
        : base(directory, metadataKey, authDirectory) { }

    public TpmBasedCredentialStore(string directory, string username, string password, string? authDirectory = null)
        : base(directory, username, password, authDirectory) { }
}
