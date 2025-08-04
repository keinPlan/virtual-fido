using System;
using System.IO;
using System.Runtime.InteropServices;
using VirtualFido.UsbIp.Device;

namespace VirtualFido.UsbIp.Protocol.Helper
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class UsbDevice
    {
        public UsbDevice(int busNum, int busId, VirtualUsbDevice device)
        {
            bcdDevice = device.UsbDescriptor_Device.bcdDevice;
            bConfigurationValue = 1;
            bDeviceClass = device.UsbDescriptor_Device.bDeviceClass;
            bDeviceProtocol = device.UsbDescriptor_Device.bDeviceProtocol;
            bDeviceSubClass = device.UsbDescriptor_Device.bDeviceSubClass;
            idProduct = device.UsbDescriptor_Device.idProduct;
            idVendor = device.UsbDescriptor_Device.idVendor;
            bNumConfigurations = device.UsbDescriptor_Device.bNumConfigurations;
            bNumInterfaces =(byte) device.UsbDescriptors_Configurations[0].USB_INTERFACE_DESCRIPTORS.Length;
            busid = System.Text.UTF8Encoding.Default.GetBytes($"{busNum}-{busId}\0");
            busnum = (ushort)busNum;
            devnum = (ushort)busId;
            speed = 0x002;
            path = System.Text.UTF8Encoding.Default.GetBytes($"sys/devices/usbip/1.11/{busNum}-{busId}\0");
        }

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] path; // zero-terminated, padded with zeros

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] busid; // zero-terminated, padded with zeros

        public uint busnum;
        public uint devnum;
        public uint speed;
        public ushort idVendor;
        public ushort idProduct;
        public ushort bcdDevice;
        public byte bDeviceClass;
        public byte bDeviceSubClass;
        public byte bDeviceProtocol;
        public byte bConfigurationValue;
        public byte bNumConfigurations;
        public byte bNumInterfaces;



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
            bw.Write(path);
            bw.Write(new byte[256 - path.Length]); // Padding to 256 bytes
            bw.Write(busid);
            bw.Write(new byte[32 - busid.Length]); // Padding to 32 bytes
            bw.WriteMSB(busnum);
            bw.WriteMSB(devnum);
            bw.WriteMSB(speed);
            bw.WriteMSB(idVendor);
            bw.WriteMSB(idProduct);
            bw.WriteMSB(bcdDevice);
            bw.Write(bDeviceClass);
            bw.Write(bDeviceSubClass);
            bw.Write(bDeviceProtocol);
            bw.Write(bConfigurationValue);
            bw.Write(bNumConfigurations);
            bw.Write(bNumInterfaces);
        }
    }


}

