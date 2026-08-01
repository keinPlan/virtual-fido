using System;
using System.Collections.Generic;

namespace VFido.Core.Device.Ctap
{
    internal class CtapHidReassembler
    {
        private class ChannelState
        {
            public byte Cmd;
            public int TotalLength;
            public byte[] Buffer = Array.Empty<byte>();
            public int Received;
            public byte NextSeq;
        }

        private readonly Dictionary<uint, ChannelState> _inProgress = new();

        internal bool TryAccept(byte[] report, out uint cid, out byte cmd, out byte[]? completedPayload)
        {
            cid = CtapHidFramer.ReadCid(report, 0);
            completedPayload = null;
            cmd = 0;

            var isInitPacket = (report[4] & 0x80) != 0;

            if (isInitPacket)
            {
                cmd = report[4];
                var bcnt = (report[5] << 8) | report[6];
                var state = new ChannelState
                {
                    Cmd = cmd,
                    TotalLength = bcnt,
                    Buffer = new byte[bcnt],
                };

                var copyLength = Math.Min(bcnt, CtapHidConstants.InitPacketDataSize);
                Array.Copy(report, 7, state.Buffer, 0, copyLength);
                state.Received = copyLength;

                if (state.Received >= state.TotalLength)
                {
                    completedPayload = state.Buffer;
                    _inProgress.Remove(cid);
                    return true;
                }

                _inProgress[cid] = state;
                return false;
            }

            if (!_inProgress.TryGetValue(cid, out var inProgress))
                return false; // continuation for an unknown/already-completed channel: drop it

            var seq = report[4];
            if (seq != inProgress.NextSeq)
            {
                _inProgress.Remove(cid); // out-of-order sequence: abandon the in-progress message
                return false;
            }

            cmd = inProgress.Cmd;
            var remaining = inProgress.TotalLength - inProgress.Received;
            var chunkLength = Math.Min(remaining, CtapHidConstants.ContinuationPacketDataSize);
            Array.Copy(report, 5, inProgress.Buffer, inProgress.Received, chunkLength);
            inProgress.Received += chunkLength;
            inProgress.NextSeq++;

            if (inProgress.Received < inProgress.TotalLength)
                return false;

            completedPayload = inProgress.Buffer;
            _inProgress.Remove(cid);
            return true;
        }
    }
}
