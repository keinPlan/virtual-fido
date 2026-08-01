namespace VFido.Core.Device.Ctap2.Authenticator
{
    /// <summary>
    /// Gates authenticatorMakeCredential/GetAssertion on an explicit user action, mirroring the
    /// physical tap a real security key requires before it signs. Without this gate, a virtual
    /// authenticator answers instantly, so when several are attached the fastest one silently wins
    /// the request instead of the platform ever getting a chance to let a human pick.
    /// </summary>
    public interface IUserPresenceGate
    {
        bool RequestApproval(string operation, string rpId);
    }
}
