namespace VirtualFido.UsbIp.Device.Ctap
{
    internal static class CtapHidConstants
    {
        internal const uint BroadcastCid = 0xFFFFFFFF;
        internal const int PacketSize = 64;
        internal const int InitPacketDataSize = PacketSize - 7; // CID(4) + CMD(1) + BCNTH(1) + BCNTL(1)
        internal const int ContinuationPacketDataSize = PacketSize - 5; // CID(4) + SEQ(1)

        internal const byte CTAPHID_PING = 0x81;
        internal const byte CTAPHID_MSG = 0x83;
        internal const byte CTAPHID_INIT = 0x86;
        internal const byte CTAPHID_WINK = 0x88;
        internal const byte CTAPHID_CBOR = 0x90;
        internal const byte CTAPHID_CANCEL = 0x91;
        internal const byte CTAPHID_ERROR = 0xBF;
        internal const byte CTAPHID_KEEPALIVE = 0xBB;

        internal const byte CTAP1_ERR_INVALID_CMD = 0x01;
        internal const byte CTAP1_ERR_INVALID_CHANNEL = 0x0B;

        internal const byte CtapHidProtocolVersion = 2;
        internal const byte CapabilityWink = 0x01;
        internal const byte CapabilityCbor = 0x04;
    }
}
