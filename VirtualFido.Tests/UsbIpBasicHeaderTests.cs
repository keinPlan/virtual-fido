using System.IO;
using VirtualFido.UsbIp.Protocol;
using VirtualFido.UsbIp.Protocol.Helper;
using Xunit;

namespace VirtualFido.Tests
{
    public class UsbIpBasicHeaderTests
    {
        [Fact]
        public void Parse_ReadsFieldsAsBigEndian()
        {
            byte[] buffer =
            {
                0x00, 0x00, 0x00, 0x01, // Command = 1 (USBIP_CMD_SUBMIT)
                0x00, 0x00, 0x00, 0x2A, // Seq = 42
                0x00, 0x01, 0x00, 0x02, // DevID = 0x00010002
                0x00, 0x00, 0x00, 0x00, // Direction = 0 (Direction.IN per this enum's naming; USBIP_DIR_OUT on the wire)
                0x00, 0x00, 0x00, 0x01, // EndPoint = 1
            };

            var header = UsbIpBasicHeader.Parse(buffer, 0);

            Assert.Equal(1, header.Command);
            Assert.Equal(42, header.Seq);
            Assert.Equal(0x00010002, header.DevID);
            Assert.Equal(Direction.IN, header.Direction);
            Assert.Equal(1, header.EndPoint);
        }

        [Fact]
        public void WriteToStream_RoundTripsThroughParse()
        {
            var header = new UsbIpBasicHeader
            {
                Command = 3,
                Seq = 7,
                DevID = 0x00020001,
                Direction = Direction.IN,
                EndPoint = 0x81,
            };

            using var ms = new MemoryStream();
            using (var bw = new BinaryWriter(ms, System.Text.Encoding.UTF8, true))
            {
                header.WriteToStream(bw);
            }

            var bytes = ms.ToArray();
            Assert.Equal(20, bytes.Length);

            var roundTripped = UsbIpBasicHeader.Parse(bytes, 0);
            Assert.Equal(header.Command, roundTripped.Command);
            Assert.Equal(header.Seq, roundTripped.Seq);
            Assert.Equal(header.DevID, roundTripped.DevID);
            Assert.Equal(header.Direction, roundTripped.Direction);
            Assert.Equal(header.EndPoint, roundTripped.EndPoint);
        }
    }
}
