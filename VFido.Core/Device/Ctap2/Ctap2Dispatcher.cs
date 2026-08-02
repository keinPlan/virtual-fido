using System;
using VFido.Core.Device.Ctap2.Commands;
using VFido.Core.Device.Ctap2.Errors;
using IAuthenticator = VFido.Core.Device.Ctap2.Authenticator.IAuthenticator;

namespace VFido.Core.Device.Ctap2
{
    /// <summary>
    /// Entry point for CTAPHID_CBOR payloads. Splits off the command byte, routes to the
    /// matching authenticatorXxx handler, and returns a CTAP2 response: status byte followed
    /// by the (possibly empty) CBOR-encoded response map.
    /// </summary>
    internal static class Ctap2Dispatcher
    {
        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        internal static async Task<byte[]> Handle(byte[] payload, IAuthenticator authenticator)
        {
            if (payload == null || payload.Length == 0)
                return new[] { Ctap2Constants.Ctap2ErrInvalidCbor };

            var command = payload[0];
            var body = payload.AsSpan(1).ToArray();

            Logger.Trace(() => $"Dispatching CTAP2 command 0x{command:X2} ({body.Length} byte payload)");

            try
            {
                return command switch
                {
                    Ctap2Constants.AuthenticatorGetInfo => Prepend(Ctap2Constants.Ctap2Ok, GetInfoCommand.Handle(authenticator.IsPinSet)),
                    Ctap2Constants.AuthenticatorMakeCredential => Prepend(Ctap2Constants.Ctap2Ok, await MakeCredentialCommand.Handle(body, authenticator)),
                    Ctap2Constants.AuthenticatorGetAssertion => Prepend(Ctap2Constants.Ctap2Ok, await GetAssertionCommand.Handle(body, authenticator)),
                    Ctap2Constants.AuthenticatorClientPin => Prepend(Ctap2Constants.Ctap2Ok, await ClientPinCommand.Handle(body, authenticator)),
                    Ctap2Constants.AuthenticatorGetNextAssertion => Prepend(Ctap2Constants.Ctap2Ok, await GetNextAssertionCommand.Handle(authenticator)),
                    _ => LogUnknownCommand(command),
                };
            }
            catch (Ctap2Exception ex)
            {
                Logger.Warn(() => $"CTAP2 command 0x{command:X2} rejected: status=0x{ex.StatusCode:X2} ({ex.Message})");
                return new[] { ex.StatusCode };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Unhandled exception dispatching CTAP2 command 0x{0:X2}", command);
                return new[] { Ctap2Constants.Ctap2ErrInvalidCbor };
            }
        }

        private static byte[] LogUnknownCommand(byte command)
        {
            Logger.Warn(() => $"Unsupported CTAP2 command 0x{command:X2}");
            return new[] { Ctap2Constants.Ctap1ErrInvalidCommand };
        }

        private static byte[] Prepend(byte status, byte[] cbor)
        {
            var result = new byte[1 + cbor.Length];
            result[0] = status;
            Array.Copy(cbor, 0, result, 1, cbor.Length);
            return result;
        }
    }
}
