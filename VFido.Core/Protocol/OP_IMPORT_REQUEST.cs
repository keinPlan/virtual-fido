using System.Runtime.InteropServices;
using VFido.Core.Protocol.Helper;


namespace VFido.Core.Protocol
{
    public struct OP_IMPORT_REQUEST
    {
        private ServerHeader header;       
        public byte[] busid; // 32byte zero-terminated, padded with zeros

        public OP_IMPORT_REQUEST(string busidStr)
        {
            header = new ServerHeader(0x8003, 0);
            busid = new byte[32];
            var bytes = System.Text.Encoding.ASCII.GetBytes(busidStr);
            int len = Math.Min(bytes.Length, 31);
            Array.Copy(bytes, busid, len);
            busid[len] = 0; // Nullterminierung
        }
    }
}

