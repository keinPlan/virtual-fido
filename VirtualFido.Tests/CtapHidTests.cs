using System;
using VirtualFido.UsbIp.Device;
using VirtualFido.UsbIp.Device.Ctap;
using VirtualFido.UsbIp.Protocol;
using Xunit;

namespace VirtualFido.Tests
{
    public class CtapHidTests
    {
        private const int InterruptEndpoint = 1;
        private const int RetSubmitHeaderSize = 48; // 20 (basic header) + 4*5 (status..error_count) + 8 (padding)

        private static USBIP_CMD_SUBMIT BuildInterruptRequest(int direction, byte[]? outPayload, int transferBufferLength)
        {
            // usbip_header_basic (20 bytes) + submit-specific fixed fields (28 bytes) [+ OUT payload]
            var payloadLength = direction == 0 ? (outPayload?.Length ?? 0) : 0;
            var buffer = new byte[20 + 28 + payloadLength];
            int o = 0;

            void WriteBE(int value)
            {
                buffer[o++] = (byte)(value >> 24);
                buffer[o++] = (byte)(value >> 16);
                buffer[o++] = (byte)(value >> 8);
                buffer[o++] = (byte)value;
            }

            WriteBE(1);                    // Command = USBIP_CMD_SUBMIT
            WriteBE(1);                    // Seq
            WriteBE(0x00010001);            // DevID
            WriteBE(direction);             // Direction (0 = buffer-bearing/OUT, per USBIP_CMD_SUBMIT.Parse)
            WriteBE(InterruptEndpoint);     // EndPoint
            WriteBE(0);                     // TransferFlags
            WriteBE(transferBufferLength);  // TransferBufferLength
            WriteBE(0);                     // StartFrame
            WriteBE(0);                     // NumberOfPackets
            WriteBE(0);                     // Interval
            WriteBE(0);                     // Setup (high 4 bytes)
            WriteBE(0);                     // Setup (low 4 bytes)

            if (direction == 0 && outPayload != null)
                Array.Copy(outPayload, 0, buffer, o, outPayload.Length);

            return USBIP_CMD_SUBMIT.Parse(buffer, 0)!;
        }

        private static void SendOut(FidoUsbStick device, FakePacketSink sink, byte[] report)
        {
            var request = BuildInterruptRequest(0, report, report.Length);
            device.HandleUsbRequest(sink, request);
        }

        private static byte[] PollIn(FidoUsbStick device, FakePacketSink sink)
        {
            var request = BuildInterruptRequest(1, null, CtapHidConstants.PacketSize);
            device.HandleUsbRequest(sink, request);
            return sink.LastPacket[RetSubmitHeaderSize..];
        }

        private static uint ReadCid(byte[] report, int offset)
        {
            return (uint)((report[offset] << 24) | (report[offset + 1] << 16) | (report[offset + 2] << 8) | report[offset + 3]);
        }

        private static uint Handshake(FidoUsbStick device, FakePacketSink sink)
        {
            var nonce = new byte[8];
            foreach (var packet in CtapHidFramer.Frame(CtapHidConstants.BroadcastCid, CtapHidConstants.CTAPHID_INIT, nonce))
                SendOut(device, sink, packet);

            var report = PollIn(device, sink);
            return ReadCid(report, 15);
        }

        [Fact]
        public void CtapHidInit_AllocatesChannelAndEchoesNonce()
        {
            var device = new FidoUsbStick(0x00010001);
            var sink = new FakePacketSink();
            var nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            foreach (var packet in CtapHidFramer.Frame(CtapHidConstants.BroadcastCid, CtapHidConstants.CTAPHID_INIT, nonce))
                SendOut(device, sink, packet);

            var report = PollIn(device, sink);

            Assert.Equal(CtapHidConstants.CTAPHID_INIT, report[4]);
            var bcnt = (report[5] << 8) | report[6];
            Assert.Equal(17, bcnt);
            Assert.Equal(nonce, report[7..15]);

            var cid = ReadCid(report, 15);
            Assert.NotEqual(0u, cid);
            Assert.NotEqual(CtapHidConstants.BroadcastCid, cid);
        }

        [Fact]
        public void CtapHidPing_FragmentedAcrossMultiplePacketsIsReassembledAndEchoedBack()
        {
            var device = new FidoUsbStick(0x00010001);
            var sink = new FakePacketSink();
            var cid = Handshake(device, sink);

            var pingPayload = new byte[80];
            for (var i = 0; i < pingPayload.Length; i++)
                pingPayload[i] = (byte)i;

            foreach (var packet in CtapHidFramer.Frame(cid, CtapHidConstants.CTAPHID_PING, pingPayload))
                SendOut(device, sink, packet);

            var reassembler = new CtapHidReassembler();
            byte[]? completed = null;
            for (var i = 0; i < 5 && completed == null; i++)
            {
                var report = PollIn(device, sink);
                if (reassembler.TryAccept(report, out _, out var cmd, out completed))
                    Assert.Equal(CtapHidConstants.CTAPHID_PING, cmd);
            }

            Assert.NotNull(completed);
            Assert.Equal(pingPayload, completed);
        }

        [Fact]
        public void CtapHidCbor_ReachesFidoUsbStickStubAndRepliesWithError()
        {
            var device = new FidoUsbStick(0x00010001);
            var sink = new FakePacketSink();
            var cid = Handshake(device, sink);

            foreach (var packet in CtapHidFramer.Frame(cid, CtapHidConstants.CTAPHID_CBOR, new byte[] { 0x04 }))
                SendOut(device, sink, packet);

            var report = PollIn(device, sink);

            Assert.Equal(CtapHidConstants.CTAPHID_ERROR, report[4]);
            var bcnt = (report[5] << 8) | report[6];
            Assert.Equal(1, bcnt);
            Assert.Equal(CtapHidConstants.CTAP1_ERR_INVALID_CMD, report[7]);
        }
    }
}
