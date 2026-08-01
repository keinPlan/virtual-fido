using System.Collections.Generic;
using VFido.Core.Protocol.Helper;

namespace VirtualFido.Tests
{
    internal class FakePacketSink : IPacketSink
    {
        public List<byte[]> SentPackets { get; } = new();

        public byte[] LastPacket => SentPackets[^1];

        public void Send(byte[] data)
        {
            SentPackets.Add(data);
        }
    }
}
