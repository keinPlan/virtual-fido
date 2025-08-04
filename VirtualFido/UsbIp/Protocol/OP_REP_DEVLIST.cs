using System;
using System.IO;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using VirtualFido.UsbIp.Device;
using VirtualFido.UsbIp.Protocol.Helper;

namespace VirtualFido.UsbIp.Protocol
{
    public struct OP_REP_DEVLIST
    {
        private ServerHeader header;


        // Max 8 devices (USB/IP protocol limit)
        [MarshalAs(UnmanagedType.LPArray)]
        internal List<UsbDeviceWithInterfaces> devices = new List<UsbDeviceWithInterfaces>();


        internal OP_REP_DEVLIST(int status, Dictionary<int, VirtualUsbDevice> deviceDictonary)
        {
            header = new ServerHeader(0x0005, status);

            foreach (var dictEntry in deviceDictonary)
            {
                var busNum = dictEntry.Key >> 16 & 0xffff;
                var devNum = dictEntry.Key & 0xffff;
                var device = dictEntry.Value;

                devices.Add(new UsbDeviceWithInterfaces()
                {
                    Device = new UsbDevice(busNum, devNum, device),
                    Interfaces = device.UsbDescriptors_Configurations[0].USB_INTERFACE_DESCRIPTORS.Select(i => new UsbInterface()
                    {
                        bInterfaceClass = i.USB_INTERFACE_DESCRIPTOR.bInterfaceClass,
                        bInterfaceProtocol = i.USB_INTERFACE_DESCRIPTOR.bInterfaceProtocol,
                        bInterfaceSubClass = i.USB_INTERFACE_DESCRIPTOR.bInterfaceSubClass,
                        padding = 0
                    }).ToArray()
                });

            }


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
            bw.WriteMSB(devices.Count); // Anzahl der Geräte

            foreach (var device in devices)
            {
                device.WriteToStream(bw);
            }
        }


    }
}

