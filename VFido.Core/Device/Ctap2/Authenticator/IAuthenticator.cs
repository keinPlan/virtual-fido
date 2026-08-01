using VFido.Core.Device.Ctap2.Model;

namespace VFido.Core.Device.Ctap2.Authenticator
{
    /// <summary>Authenticator business logic: no CBOR, no transport, just CTAP2 semantics.</summary>
    internal interface IAuthenticator
    {
        bool IsPinSet { get; }

        MakeCredentialResult MakeCredential(MakeCredentialRequest request);
        GetAssertionResult GetAssertion(GetAssertionRequest request);
        GetAssertionResult GetNextAssertion();
        ClientPinResult ClientPin(ClientPinRequest request);
    }
}
