using System.Collections.Generic;

namespace VFido.Core.Device.Ctap2.Model
{
    internal record MakeCredentialRequest(
        byte[] ClientDataHash,
        RelyingParty RelyingParty,
        UserEntity User,
        IReadOnlyList<PublicKeyCredentialParameters> PubKeyCredParams,
        byte[]? PinUvAuthParam = null,
        byte? PinUvAuthProtocol = null,
        bool RequireResidentKey = false,
        bool RequireUserVerification = false,
        IReadOnlyList<byte[]>? ExcludeList = null);
}
