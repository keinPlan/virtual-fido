using IAuthenticator = VFido.Core.Device.Ctap2.Authenticator.IAuthenticator;

namespace VFido.Core.Device.Ctap2.Commands
{
    /// <summary>authenticatorGetNextAssertion (0x08), CTAP2 section 6.3. Takes no request body.</summary>
    internal static class GetNextAssertionCommand
    {
        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        internal static async Task<byte[]> Handle(IAuthenticator authenticator)
        {
            Logger.Debug("authenticatorGetNextAssertion");
            return GetAssertionCommand.Encode(await authenticator.GetNextAssertionAsync());
        }
    }
}
