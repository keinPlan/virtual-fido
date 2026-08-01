using System.Runtime.InteropServices;

namespace VFido.Core.Protocol.Helper
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct UsbInterface
    {
        public byte bInterfaceClass;
        public byte bInterfaceSubClass;
        public byte bInterfaceProtocol;
        public byte padding; // alignment
    }


}

