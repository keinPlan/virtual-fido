using System.Formats.Cbor;
using VFido.Core.Device.Ctap2.Authenticator;

namespace VFido.Core.Device.Ctap2.Commands
{
    /// <summary>
    /// authenticatorGetInfo (0x04). Takes no request body; advertises supported
    /// versions/options so a real CTAP2 client will proceed to makeCredential/getAssertion.
    /// </summary>
    internal static class GetInfoCommand
    {
        internal static byte[] Handle(bool pinIsSet)
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

            writer.WriteStartMap(8);

            writer.WriteInt32(Ctap2Constants.InfoKeyVersions);
            writer.WriteStartArray(1);
            writer.WriteTextString("FIDO_2_0");
            writer.WriteEndArray();

            writer.WriteInt32(Ctap2Constants.InfoKeyAaguid);
            writer.WriteByteString(AuthenticatorAaguid.Bytes);

            writer.WriteInt32(Ctap2Constants.InfoKeyOptions);
            writer.WriteStartMap(3);
            writer.WriteTextString("rk");
            writer.WriteBoolean(true);
            writer.WriteTextString("up");
            writer.WriteBoolean(true);
            writer.WriteTextString("clientPin");
            writer.WriteBoolean(pinIsSet);
            writer.WriteEndMap();

            writer.WriteInt32(Ctap2Constants.InfoKeyPinUvAuthProtocols);
            writer.WriteStartArray(1);
            writer.WriteInt32(1);
            writer.WriteEndArray();

            writer.WriteInt32(Ctap2Constants.InfoKeyMaxCredentialCountInList);
            writer.WriteInt32(10);

            writer.WriteInt32(Ctap2Constants.InfoKeyMaxCredentialIdLength);
            writer.WriteInt32(32); // matches the credential ID length Fido2Authenticator generates

            writer.WriteInt32(Ctap2Constants.InfoKeyTransports);
            writer.WriteStartArray(1);
            writer.WriteTextString("usb");
            writer.WriteEndArray();

            writer.WriteInt32(Ctap2Constants.InfoKeyAlgorithms);
            writer.WriteStartArray(1);
            writer.WriteStartMap(2);
            writer.WriteTextString("alg");
            writer.WriteInt32(-7);
            writer.WriteTextString("type");
            writer.WriteTextString("public-key");
            writer.WriteEndMap();
            writer.WriteEndArray();

            writer.WriteEndMap();

            return writer.Encode();
        }
    }
}
