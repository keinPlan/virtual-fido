using System;
using System.Collections.Generic;

namespace VFido.Core.Device.Ctap
{
    internal static class CtapHidFramer
    {
        internal static IReadOnlyList<byte[]> Frame(uint cid, byte cmd, byte[] payload)
        {
            payload ??= Array.Empty<byte>();
            var packets = new List<byte[]>();

            var initData = new byte[CtapHidConstants.InitPacketDataSize];
            var initCopyLength = Math.Min(payload.Length, initData.Length);
            Array.Copy(payload, 0, initData, 0, initCopyLength);

            var init = new byte[CtapHidConstants.PacketSize];
            WriteCid(init, 0, cid);
            init[4] = cmd;
            init[5] = (byte)((payload.Length >> 8) & 0xff);
            init[6] = (byte)(payload.Length & 0xff);
            Array.Copy(initData, 0, init, 7, initData.Length);
            packets.Add(init);

            var offset = initCopyLength;
            byte seq = 0;
            while (offset < payload.Length)
            {
                var cont = new byte[CtapHidConstants.PacketSize];
                WriteCid(cont, 0, cid);
                cont[4] = seq;

                var remaining = payload.Length - offset;
                var chunkLength = Math.Min(remaining, CtapHidConstants.ContinuationPacketDataSize);
                Array.Copy(payload, offset, cont, 5, chunkLength);

                packets.Add(cont);
                offset += chunkLength;
                seq++;
            }

            return packets;
        }

        internal static uint ReadCid(byte[] report, int offset)
        {
            return (uint)((report[offset] << 24) | (report[offset + 1] << 16) | (report[offset + 2] << 8) | report[offset + 3]);
        }

        private static void WriteCid(byte[] buffer, int offset, uint cid)
        {
            buffer[offset] = (byte)((cid >> 24) & 0xff);
            buffer[offset + 1] = (byte)((cid >> 16) & 0xff);
            buffer[offset + 2] = (byte)((cid >> 8) & 0xff);
            buffer[offset + 3] = (byte)(cid & 0xff);
        }
    }
}
