namespace VirtualFido.UsbIp.Device.Ctap2
{
    internal static class Ctap2Constants
    {
        internal const byte AuthenticatorMakeCredential = 0x01;
        internal const byte AuthenticatorGetAssertion = 0x02;
        internal const byte AuthenticatorGetInfo = 0x04;
        internal const byte AuthenticatorClientPin = 0x06;
        internal const byte AuthenticatorReset = 0x07;
        internal const byte AuthenticatorGetNextAssertion = 0x08;

        internal const byte Ctap2Ok = 0x00;
        internal const byte Ctap1ErrInvalidCommand = 0x01;
        internal const byte Ctap2ErrInvalidCbor = 0x12;
        internal const byte Ctap2ErrMissingParameter = 0x14;
        internal const byte Ctap2ErrUnsupportedOption = 0x2D;

        // authenticatorGetInfo response map keys (CTAP2 spec, section 6.4).
        internal const int InfoKeyVersions = 0x01;
        internal const int InfoKeyExtensions = 0x02;
        internal const int InfoKeyAaguid = 0x03;
        internal const int InfoKeyOptions = 0x04;
        internal const int InfoKeyMaxMsgSize = 0x05;
        internal const int InfoKeyPinUvAuthProtocols = 0x06;
    }
}
