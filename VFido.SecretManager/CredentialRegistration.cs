namespace VFido.SecretManager
{
    /// <summary>Result of creating a new credential: everything a caller needs to build attestedCredentialData - never the key handle.</summary>
    public sealed record CredentialRegistration(byte[] CredentialId, byte[] CosePublicKey, int CoseAlgorithm);
}
