namespace VFido.SecretManager
{
    // One request/response pair per IFido2SecretManager method. byte[] members round-trip as base64
    // via System.Text.Json, so these carry credential ids / user ids / signatures as-is.

    public sealed record CreateCredentialRequest(string RpId, byte[] UserId, string UserName, string UserDisplayName, bool IsResident, int CredProtect = 1);

    public sealed record CredentialExistsRequest(byte[] CredentialId, string RpId);
    public sealed record CredentialExistsResponse(bool Exists);

    public sealed record FindCredentialRequest(byte[] CredentialId, string RpId);
    public sealed record FindCredentialResponse(CredentialInfo? Credential);

    public sealed record FindResidentCredentialsRequest(string RpId);
    public sealed record FindResidentCredentialsResponse(IReadOnlyList<CredentialInfo> Credentials);

    public sealed record FindAllCredentialsResponse(IReadOnlyList<CredentialInfo> Credentials);

    public sealed record DeleteCredentialRequest(byte[] CredentialId);
    public sealed record DeleteCredentialResponse();

    public sealed record IncrementSignCountRequest(byte[] CredentialId);
    public sealed record IncrementSignCountResponse(uint SignCount);

    public sealed record SignRequest(byte[] CredentialId, byte[] Data);
    public sealed record SignResponse(byte[] Signature);

    public sealed record GetAttestationCertificateChainResponse(IReadOnlyList<byte[]> CertificateChainDer);

    public sealed record SignWithAttestationKeyRequest(byte[] Data);
    public sealed record SignWithAttestationKeyResponse(byte[] Signature);

    public sealed record GetAaguidResponse(byte[] Aaguid);

    public sealed record GetPinStateResponse(PinState? State);

    public sealed record SavePinStateRequest(PinState State);
    public sealed record SavePinStateResponse();
}
