using System.IO;
using System.Runtime.InteropServices;
using VFido.Core.Protocol.Helper;


namespace VFido.Core.Protocol
{
    public struct OP_REP_IMPORT
    {
        private ServerHeader header;
        UsbDevice usbDevice;

        public OP_REP_IMPORT(int status, UsbDevice usbDevice)
        {
            header = new ServerHeader(0x0003, 0);
        }

        public byte[] ToByteArray()
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
            header.WriteToStream(bw);
            usbDevice.WriteToStream(bw);
        }
    }
}

