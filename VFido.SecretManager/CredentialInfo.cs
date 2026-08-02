namespace VFido.SecretManager
{
    /// <summary>Public-safe view of a stored credential - metadata only, never the key handle.</summary>
    public sealed record CredentialInfo(
        byte[] CredentialId,
        string RpId,
        byte[] UserId,
        string UserName,
        string UserDisplayName,
        bool IsResident,
        uint SignCount);
}
