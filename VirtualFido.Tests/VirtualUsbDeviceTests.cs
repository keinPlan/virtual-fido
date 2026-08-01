using System;
using VFido.Core.Device;
using VFido.Core.Protocol;
using Xunit;

namespace VirtualFido.Tests
{
    public class VirtualUsbDeviceTests
    {
        private static USBIP_CMD_SUBMIT BuildControlRequest(byte[] setup)
        {
            // usbip_header_basic (20 bytes) + submit-specific fixed fields (28 bytes), no OUT payload
            // for a device-to-host control transfer (Direction = IN).
            var buffer = new byte[20 + 28];
            int o = 0;

            void WriteBE(int value)
            {
                buffer[o++] = (byte)(value >> 24);
                buffer[o++] = (byte)(value >> 16);
                buffer[o++] = (byte)(value >> 8);
                buffer[o++] = (byte)value;
            }

            WriteBE(1);            // Command = USBIP_CMD_SUBMIT
            WriteBE(1);             // Seq
            WriteBE(0x00010001);    // DevID
            WriteBE(1);             // Direction = IN
            WriteBE(0);             // EndPoint = 0 (control)
            WriteBE(0);             // TransferFlags
            WriteBE(0);             // TransferBufferLength
            WriteBE(0);             // StartFrame
            WriteBE(0);             // NumberOfPackets
            WriteBE(0);             // Interval
            Array.Copy(setup, 0, buffer, o, 8);

            return USBIP_CMD_SUBMIT.Parse(buffer, 0)!;
        }

        [Fact]
        public void HandleUsbRequest_GetDeviceDescriptor_RespondsWithDeviceDescriptorBytes()
        {
            var device = new FidoUsbStick(0x00010001);
            var sink = new FakePacketSink();
            var setup = new byte[] { 0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00 }; // GET_DESCRIPTOR(DEVICE), wLength=18
            var request = BuildControlRequest(setup);

            device.HandleUsbRequest(sink, request);

            Assert.Single(sink.SentPackets);
            var response = sink.LastPacket;

            const int retSubmitHeaderSize = 48; // 20 (basic header) + 4*5 (status..error_count) + 8 (padding)
            Assert.True(response.Length >= retSubmitHeaderSize + 18);

            int status = (response[20] << 24) | (response[21] << 16) | (response[22] << 8) | response[23];
            int actualLength = (response[24] << 24) | (response[25] << 16) | (response[26] << 8) | response[27];
            Assert.Equal(0, status);
            Assert.Equal(18, actualLength);

            var descriptorBytes = response[retSubmitHeaderSize..];
            Assert.Equal(18, descriptorBytes.Length);
            Assert.Equal(18, descriptorBytes[0]);   // bLength
            Assert.Equal(0x01, descriptorBytes[1]); // bDescriptorType = DEVICE
            Assert.Equal(6483 & 0xff, descriptorBytes[8]); // idVendor low byte (little-endian on the wire)
        }

        [Fact]
        public void HandleUsbRequest_UnlinkCommand_RespondsImmediatelyWithEmptyPayload()
        {
            var device = new FidoUsbStick(0x00010001);
            var sink = new FakePacketSink();
            var setup = new byte[8];
            var request = BuildControlRequest(setup);
            request.Header.Command = 2; // USBIP_CMD_UNLINK

            device.HandleUsbRequest(sink, request);

            Assert.Single(sink.SentPackets);
            var response = sink.LastPacket;
            Assert.Equal(48, response.Length); // header only, no payload
        }
    }
}
