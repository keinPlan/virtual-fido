using System;
using VirtualFido.UsbIp.Device.Ctap2.Commands;

namespace VirtualFido.UsbIp.Device.Ctap2
{
    /// <summary>
    /// Entry point for CTAPHID_CBOR payloads. Splits off the command byte, routes to the
    /// matching authenticatorXxx handler, and returns a CTAP2 response: status byte followed
    /// by the (possibly empty) CBOR-encoded response map.
    /// </summary>
    internal static class Ctap2Dispatcher
    {
        internal static byte[] Handle(byte[] payload)
        {
            if (payload == null || payload.Length == 0)
                return new[] { Ctap2Constants.Ctap2ErrInvalidCbor };

            var command = payload[0];

            try
            {
                return command switch
                {
                    Ctap2Constants.AuthenticatorGetInfo => Prepend(Ctap2Constants.Ctap2Ok, GetInfoCommand.Handle()),
                    _ => new[] { Ctap2Constants.Ctap1ErrInvalidCommand },
                };
            }
            catch (Exception)
            {
                return new[] { Ctap2Constants.Ctap2ErrInvalidCbor };
            }
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
