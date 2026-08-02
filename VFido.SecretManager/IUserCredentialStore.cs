namespace VFido.SecretManager
{
    /// <summary>
    /// Validates a human login (username/password) presented to a server-hosted
    /// <see cref="IFido2SecretManager"/> once its transport channel is established - the seam a
    /// real identity backend (AD, IdP) would implement in place of an in-process store.
    /// </summary>
    public interface IUserCredentialStore
    {
        bool Validate(string username, string password);
    }
}
