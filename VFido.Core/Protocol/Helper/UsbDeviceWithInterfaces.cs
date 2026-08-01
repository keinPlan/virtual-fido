using System.IO;
using System.Runtime.InteropServices;

namespace VFido.Core.Protocol.Helper
{
    public struct UsbDeviceWithInterfaces
    {
        public UsbDevice Device;
        [MarshalAs(UnmanagedType.LPArray)]
        public UsbInterface[] Interfaces;
        public UsbDeviceWithInterfaces(UsbDevice device, UsbInterface[] interfaces)
        {
            Device = device;
            Interfaces = interfaces ?? new UsbInterface[0];
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
            Device.WriteToStream(bw);

            foreach (var iface in Interfaces)
            {
                bw.Write(iface.bInterfaceClass);
                bw.Write(iface.bInterfaceSubClass);
                bw.Write(iface.bInterfaceProtocol);
                bw.Write((byte)0); // padding
            }

        }
    }


}

