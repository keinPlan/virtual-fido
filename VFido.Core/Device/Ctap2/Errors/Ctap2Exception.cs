using System;

namespace VFido.Core.Device.Ctap2.Errors
{
    /// <summary>
    /// Carries a specific CTAP2 status byte (see Ctap2Constants) out of request decoding or
    /// authenticator logic, so the dispatcher can report the precise failure instead of a
    /// generic CBOR-parse error.
    /// </summary>
    internal class Ctap2Exception : Exception
    {
        internal byte StatusCode { get; }

        internal Ctap2Exception(byte statusCode) : base($"CTAP2 error 0x{statusCode:X2}")
        {
            StatusCode = statusCode;
        }
    }
}
