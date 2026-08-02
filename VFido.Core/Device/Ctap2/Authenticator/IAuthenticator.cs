using VFido.Core.Device.Ctap2.Authenticator.Pin;
using VFido.Core.Device.Ctap2.Model;

namespace VFido.Core.Device.Ctap2.Authenticator
{
    /// <summary>Authenticator business logic: no CBOR, no transport, just CTAP2 semantics.</summary>
    internal interface IAuthenticator
    {
        bool IsPinSet { get; }
        byte[] Aaguid { get; }
        PinUsagePreference PinUsage { get; }

        Task<MakeCredentialResult> MakeCredentialAsync(MakeCredentialRequest request);
        Task<GetAssertionResult> GetAssertionAsync(GetAssertionRequest request);
        Task<GetAssertionResult> GetNextAssertionAsync();
        Task<ClientPinResult> ClientPinAsync(ClientPinRequest request);
    }
}
