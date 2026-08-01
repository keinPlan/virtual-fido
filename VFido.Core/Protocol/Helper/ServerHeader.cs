using System.IO;
using System.Runtime.InteropServices;

namespace VFido.Core.Protocol.Helper
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ServerHeader
    {
        public ServerHeader(ushort cmd, int status)
        {
            Version = 0x0111; // USBIP version 273 (1.17), adjust if needed
            Command = cmd;
            Status = (uint)status;
        }

        private ushort Version;
        private ushort Command;
        private uint Status;

        byte[] ToByteArray()
        {
            using (var bw = new BinaryWriter(new MemoryStream()))
            {
                WriteToStream(bw);
                bw.Flush();
                return (bw.BaseStream as MemoryStream).ToArray();
            }
        }

        public void WriteToStream(BinaryWriter bw)
        {
            bw.WriteMSB(Version);
            bw.WriteMSB(Command);
            bw.WriteMSB(Status);
        }
    }


}

