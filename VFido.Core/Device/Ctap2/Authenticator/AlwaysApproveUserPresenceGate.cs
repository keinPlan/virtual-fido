namespace VFido.Core.Device.Ctap2.Authenticator
{
    /// <summary>Default gate for hosts (tests, headless use) that don't wire up a real prompt.</summary>
    internal sealed class AlwaysApproveUserPresenceGate : IUserPresenceGate
    {
        internal static readonly AlwaysApproveUserPresenceGate Instance = new();

        public bool RequestApproval(string operation, string rpId) => true;
    }
}
