namespace VFido.Core.Device.Ctap2.Model
{
    internal record GetAssertionResult(
        byte[] CredentialId,
        byte[] AuthenticatorData,
        byte[] Signature,
        UserEntity? User = null,
        int? NumberOfCredentials = null);
}
