namespace VFido.Core.Device.Ctap2
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
        internal const byte Ctap2ErrCredentialExcluded = 0x19;
        internal const byte Ctap2ErrUnsupportedAlgorithm = 0x26;
        internal const byte Ctap2ErrOperationDenied = 0x27;
        internal const byte Ctap2ErrUnsupportedOption = 0x2D;
        internal const byte Ctap2ErrNoCredentials = 0x2E;
        internal const byte Ctap2ErrUserActionTimeout = 0x2F;
        internal const byte Ctap2ErrNotAllowed = 0x30;
        internal const byte Ctap2ErrPinInvalid = 0x31;
        internal const byte Ctap2ErrPinBlocked = 0x32;
        internal const byte Ctap2ErrPinAuthInvalid = 0x33;
        internal const byte Ctap2ErrPinNotSet = 0x35;
        internal const byte Ctap2ErrPinRequired = 0x36;
        internal const byte Ctap2ErrPinPolicyViolation = 0x37;

        // authenticatorGetInfo response map keys (CTAP2 spec, section 6.4).
        internal const int InfoKeyVersions = 0x01;
        internal const int InfoKeyExtensions = 0x02;
        internal const int InfoKeyAaguid = 0x03;
        internal const int InfoKeyOptions = 0x04;
        internal const int InfoKeyMaxMsgSize = 0x05;
        internal const int InfoKeyPinUvAuthProtocols = 0x06;
        internal const int InfoKeyMaxCredentialCountInList = 0x07;
        internal const int InfoKeyMaxCredentialIdLength = 0x08;
        internal const int InfoKeyTransports = 0x09;
        internal const int InfoKeyAlgorithms = 0x0A;
    }
}
