using System.Runtime.InteropServices;
using VFido.Core.Protocol.Helper;


namespace VFido.Core.Protocol
{
    public struct OP_REQ_DEVLIST
    {
        private ServerHeader header;

        public OP_REQ_DEVLIST(int status)
        {
            header = new ServerHeader(0x8005, status);
        }
    }
}

