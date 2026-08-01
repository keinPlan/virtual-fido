using System;
using VFido.Core.Protocol;
using Xunit;

namespace VirtualFido.Tests
{
    public class UsbipCmdSubmitTests
    {
        private static byte[] BuildCmdSubmit(int command, int direction, byte[] setup, byte[]? outPayload)
        {
            // usbip_header_basic (20 bytes) + submit-specific fixed fields (28 bytes) [+ OUT payload]
            var payload = outPayload ?? Array.Empty<byte>();
            var buffer = new byte[20 + 28 + payload.Length];
            int o = 0;

            void WriteBE(int value)
            {
                buffer[o++] = (byte)(value >> 24);
                buffer[o++] = (byte)(value >> 16);
                buffer[o++] = (byte)(value >> 8);
                buffer[o++] = (byte)value;
            }

            WriteBE(command);           // Command
            WriteBE(1);                 // Seq
            WriteBE(0x00010001);        // DevID
            WriteBE(direction);         // Direction
            WriteBE(0);                 // EndPoint
            WriteBE(0);                 // TransferFlags
            WriteBE(payload.Length);    // TransferBufferLength
            WriteBE(0);                 // StartFrame
            WriteBE(0);                 // NumberOfPackets
            WriteBE(0);                 // Interval
            Array.Copy(setup, 0, buffer, o, 8); // Setup (raw USB setup packet bytes)
            o += 8;
            Array.Copy(payload, 0, buffer, o, payload.Length);

            return buffer;
        }

        [Fact]
        public void Parse_OutDirection_CopiesTransferBuffer()
        {
            var setup = new byte[8]; // SET_REPORT-style, contents irrelevant here
            var payload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
            // Direction 0 is the value USBIP_CMD_SUBMIT.Parse treats as "has an OUT transfer buffer"
            // (see the `(Direction)0 /*USBIP_DIR_OUT*/` check) - the Direction enum itself confusingly
            // names that value IN.
            var buffer = BuildCmdSubmit(command: 1, direction: 0, setup, payload);

            var cmd = USBIP_CMD_SUBMIT.Parse(buffer, 0);

            Assert.NotNull(cmd);
            Assert.Equal(1, cmd!.Header.Command);
            Assert.Equal(Direction.IN, cmd.Header.Direction);
            Assert.Equal(payload.Length, cmd.TransferBufferLength);
            Assert.Equal(payload, cmd.Buffer);
        }

        [Fact]
        public void Parse_ReturnsNull_WhenBufferTooSmallForHeader()
        {
            var buffer = new byte[10]; // smaller than a basic header

            var cmd = USBIP_CMD_SUBMIT.Parse(buffer, 0);

            Assert.Null(cmd);
        }

        [Fact]
        public void Parse_ReturnsNull_WhenOutPayloadIsIncomplete()
        {
            var setup = new byte[8];
            var fullBuffer = BuildCmdSubmit(command: 1, direction: 0, setup, new byte[] { 1, 2, 3, 4 });
            // Truncate the payload so fewer bytes are available than TransferBufferLength declares.
            var truncated = fullBuffer[..^2];

            var cmd = USBIP_CMD_SUBMIT.Parse(truncated, 0);

            Assert.Null(cmd);
        }

        [Fact]
        public void ParseSetupData_DecodesStandardGetDeviceDescriptorRequest()
        {
            // Real USB GET_DESCRIPTOR(DEVICE, index 0), wLength 18 - fields are little-endian on the wire.
            var setup = new byte[]
            {
                0x80,       // bmRequestType: device-to-host, standard, device
                0x06,       // bRequest: GET_DESCRIPTOR
                0x00, 0x01, // wValue (LE): 0x0100 -> type=DEVICE(1), index=0
                0x00, 0x00, // wIndex (LE): 0
                0x12, 0x00, // wLength (LE): 18
            };
            var buffer = BuildCmdSubmit(command: 1, direction: 0, setup, outPayload: null);
            var cmd = USBIP_CMD_SUBMIT.Parse(buffer, 0)!;

            var setupData = cmd.ParseSetupData();

            Assert.Equal(0x80, setupData.bmRequestType);
            Assert.Equal(0x06, setupData.bRequest);
            Assert.Equal(1, setupData.wValue & 0xff);        // descriptor type, as consumed by VirtualUsbDevice
            Assert.Equal(0, (setupData.wValue >> 8) & 0xff); // descriptor index
            Assert.Equal(0, setupData.wIndex);
            Assert.Equal(18, setupData.wLength);
        }
    }
}
