using System.Collections.Generic;
using VFido.Core;
using VFido.Core.Device;
using Xunit;

namespace VirtualFido.Tests
{
    public class UsbIpPacketHandlerTests
    {
        private static byte[] BuildOpHeader(ushort opcode)
        {
            // op_common: version(2) + code(2) + status(4), big-endian.
            return new byte[] { 0x01, 0x11, (byte)(opcode >> 8), (byte)opcode, 0x00, 0x00, 0x00, 0x00 };
        }

        [Fact]
        public void OP_REQ_DEVLIST_RespondsWithDeviceListContainingRegisteredDevice()
        {
            var devices = new Dictionary<int, VirtualUsbDevice> { [0x00010001] = new FidoUsbStick(0x00010001) };
            var handler = new UsbIpPacketHandler(devices);
            var sink = new FakePacketSink();
            var request = BuildOpHeader(0x8005);

            var consumed = handler.HandleIncommingData(sink, request, request.Length);

            Assert.Equal(request.Length, consumed);
            Assert.Single(sink.SentPackets);
            // OP_REP_DEVLIST: version(2) + code(2, reply code has high bit cleared) + status(4) + ndev(4) + ...
            var response = sink.LastPacket;
            Assert.Equal(0x00, response[2]);
            Assert.Equal(0x05, response[3]); // reply opcode 0x0005 (request 0x8005 with top bit cleared)
            var deviceCount = (response[8] << 24) | (response[9] << 16) | (response[10] << 8) | response[11];
            Assert.Equal(1, deviceCount);
        }

        [Fact]
        public void OP_REQ_DEVINFO_AttachesRegisteredDeviceAndReportsSuccess()
        {
            var device = new FidoUsbStick(0x00010001);
            var devices = new Dictionary<int, VirtualUsbDevice> { [0x00010001] = device };
            var handler = new UsbIpPacketHandler(devices);
            var sink = new FakePacketSink();

            var busId = System.Text.Encoding.ASCII.GetBytes("1-1\0");
            var request = new byte[8 + 32];
            BuildOpHeader(0x8003).CopyTo(request, 0);
            busId.CopyTo(request, 8);

            var consumed = handler.HandleIncommingData(sink, request, request.Length);

            Assert.Equal(request.Length, consumed);
            Assert.Same(device, handler.AttachedDevice);
            Assert.Single(sink.SentPackets);
            Assert.Equal(0x00, sink.LastPacket[7]); // status field (4-byte big-endian int): 0 = OK
        }

        [Fact]
        public void OP_REQ_DEVINFO_ForUnknownBusId_ReportsFailureAndDoesNotAttach()
        {
            var devices = new Dictionary<int, VirtualUsbDevice>();
            var handler = new UsbIpPacketHandler(devices);
            var sink = new FakePacketSink();

            var busId = System.Text.Encoding.ASCII.GetBytes("9-9\0");
            var request = new byte[8 + 32];
            BuildOpHeader(0x8003).CopyTo(request, 0);
            busId.CopyTo(request, 8);

            handler.HandleIncommingData(sink, request, request.Length);

            Assert.Null(handler.AttachedDevice);
            Assert.Equal(0x01, sink.LastPacket[7]); // status field (4-byte big-endian int): 1 = error
        }
    }
}
