using System;
using System.Formats.Cbor;

namespace VirtualFido.UsbIp.Device.Ctap2.Commands
{
    /// <summary>
    /// authenticatorGetInfo (0x04). Takes no request body; advertises supported
    /// versions/options so a real CTAP2 client will proceed to makeCredential/getAssertion.
    /// </summary>
    internal static class GetInfoCommand
    {
        // Fixed per-device AAGUID identifying "VirtualFido" as the authenticator model.
        private static readonly byte[] Aaguid =
        {
            0x56, 0x46, 0x49, 0x44, 0x4F, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };

        internal static byte[] Handle()
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

            writer.WriteStartMap(3);

            writer.WriteInt32(Ctap2Constants.InfoKeyVersions);
            writer.WriteStartArray(1);
            writer.WriteTextString("FIDO_2_0");
            writer.WriteEndArray();

            writer.WriteInt32(Ctap2Constants.InfoKeyAaguid);
            writer.WriteByteString(Aaguid);

            writer.WriteInt32(Ctap2Constants.InfoKeyOptions);
            writer.WriteStartMap(2);
            writer.WriteTextString("rk");
            writer.WriteBoolean(false);
            writer.WriteTextString("up");
            writer.WriteBoolean(true);
            writer.WriteEndMap();

            writer.WriteEndMap();

            return writer.Encode();
        }
    }
}
