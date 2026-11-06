namespace VFido.SecretManager.FileBasedSecretStore
{
    /// <summary>Thrown when a store directory already existed but the derived key can't decrypt it - i.e. the username/password don't match what the store was created with.</summary>
    public sealed class InvalidCredentialsException : Exception
    {
        public InvalidCredentialsException() : base("Incorrect username or password.") { }
    }

}
