namespace VFido.Core.Device.Ctap2.Authenticator.Pin
{
    /// <summary>
    /// Per-stick policy for how strongly this authenticator insists on PIN/UV proof during
    /// makeCredential/getAssertion, independent of what the platform's request asks for.
    /// </summary>
    public enum PinUsagePreference
    {
        /// <summary>Honor whatever the platform's request asks for (today's unmodified behavior).</summary>
        Prefer,

        /// <summary>Never insist on UV, even if the platform's request asks for it.</summary>
        Avoid,

        /// <summary>Always require UV, even if the platform's request doesn't ask for it.</summary>
        Always,
    }
}
