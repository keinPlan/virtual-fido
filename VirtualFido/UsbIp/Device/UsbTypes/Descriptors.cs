using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Annotations;
using VirtualFido.UsbIp.Protocol.Helper;

namespace VirtualFido.UsbIp.Device.UsbTypes
{
    public static class Converter
    {
        public static byte[] StructureToByteArray(object obj)
        {
            int len = Marshal.SizeOf(obj);

            byte[] arr = new byte[len];

            IntPtr ptr = Marshal.AllocHGlobal(len);

            Marshal.StructureToPtr(obj, ptr, true);

            Marshal.Copy(ptr, arr, 0, len);

            Marshal.FreeHGlobal(ptr);

            return arr;
        }

        public static void ByteArrayToStructure(byte[] bytearray, ref object obj)
        {
            int len = Marshal.SizeOf(obj);

            IntPtr i = Marshal.AllocHGlobal(len);

            Marshal.Copy(bytearray, 0, i, len);

            obj = Marshal.PtrToStructure(i, obj.GetType());

            Marshal.FreeHGlobal(i);
        }

    }


    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class USB_DEVICE_DESCRIPTOR
    {
        public byte bLength = 18;               // Length of this descriptor.
        public byte bDescriptorType = 0x01;       // DEVICE descriptor type (USB_DESCRIPTOR_DEVICE).
        public ushort bcdUSB;                // USB Spec Release Number (BCD).
        public byte bDeviceClass;          // Class code (assigned by the USB-IF). 0xFF-Vendor specific.
        public byte bDeviceSubClass;       // Subclass code (assigned by the USB-IF).
        public byte bDeviceProtocol;       // Protocol code (assigned by the USB-IF). 0xFF-Vendor specific.
        public byte bMaxPacketSize0;       // Maximum packet size for endpoint 0.
        public ushort idVendor;              // Vendor ID (assigned by the USB-IF).
        public ushort idProduct;             // Product ID (assigned by the manufacturer).
        public ushort bcdDevice;             // Device release number (BCD).
        public byte iManufacturer;         // Index of String Descriptor describing the manufacturer.
        public byte iProduct;              // Index of String Descriptor describing the product.
        public byte iSerialNumber;         // Index of String Descriptor with the device's serial number.
        public byte bNumConfigurations;    // Number of possible configurations.

        public byte[] ToBytes()
        {
            return Converter.StructureToByteArray(this);
        }
    }

    public class USB_CONFIGURATION
    {
        public USB_CONFIGURATION_DESCRIPTOR USB_CONFIGURATION_DESCRIPTOR;
        public USB_INTERFACE[] USB_INTERFACE_DESCRIPTORS;

        public byte[] ToBytes()
        {
            var totalSize = 0;
            totalSize += Marshal.SizeOf<USB_CONFIGURATION_DESCRIPTOR>();
            foreach (var usbInterface in USB_INTERFACE_DESCRIPTORS)
            {
                totalSize += Marshal.SizeOf<USB_INTERFACE_DESCRIPTOR>();
                
                if (usbInterface.USB_HID_DESCRIPTOR != null)                
                    totalSize += Marshal.SizeOf<USB_HID_DESCRIPTOR>();
                
                if (usbInterface.USB_ENDPOINT_DESCRIPTORS != null)
                    totalSize += Marshal.SizeOf<USB_ENDPOINT_DESCRIPTOR>() * usbInterface.USB_ENDPOINT_DESCRIPTORS.Length;
            }

            using (var ms = new MemoryStream())
            {
                USB_CONFIGURATION_DESCRIPTOR.wTotalLength = (short)totalSize;
                ms.Write(USB_CONFIGURATION_DESCRIPTOR.ToBytes());

                foreach (var usbInterface in USB_INTERFACE_DESCRIPTORS)
                {       
                    ms.Write(usbInterface.USB_INTERFACE_DESCRIPTOR.ToBytes());

                    if (usbInterface.USB_HID_DESCRIPTOR != null)
                        ms.Write(usbInterface.USB_HID_DESCRIPTOR.ToBytes());

                    if (usbInterface.USB_ENDPOINT_DESCRIPTORS != null)
                    {
                        foreach (var ep in usbInterface.USB_ENDPOINT_DESCRIPTORS)
                        {
                            ms.Write(ep.ToBytes());
                        }
                    }
                }

                return ms.ToArray();
            }

        }
    }


    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class USB_CONFIGURATION_DESCRIPTOR
    {
        public byte bLength = 9;               // Length of this descriptor.
        public byte bDescriptorType = 0x02;       // CONFIGURATION descriptor type (USB_DESCRIPTOR_CONFIGURATION).
        public short wTotalLength;          // Total length of all descriptors for this configuration.
        public byte bNumInterfaces;        // Number of interfaces in this configuration.
        public byte bConfigurationValue;   // Value of this configuration (1 based).
        public byte iConfiguration;        // Index of String Descriptor describing the configuration.
        public byte bmAttributes;          // Configuration characteristics.
        public byte bMaxPower;             // Maximum power consumed by this configuration.


        public byte[] ToBytes()
        {
            return Converter.StructureToByteArray(this);
        }
    }
    public class USB_INTERFACE
    {
        public USB_INTERFACE_DESCRIPTOR USB_INTERFACE_DESCRIPTOR;
        public USB_HID_DESCRIPTOR USB_HID_DESCRIPTOR;
        public USB_ENDPOINT_DESCRIPTOR[] USB_ENDPOINT_DESCRIPTORS;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class USB_HID_DESCRIPTOR
    {
        public byte bLength;
        public byte bDescriptorType;
        public short bcdHID;
        public byte bCountryCode;
        public byte bNumDescriptors;
        public byte bRPDescriptorType;
        public short wRPDescriptorLength;

        internal byte[] ToBytes()
        {
            return Converter.StructureToByteArray(this);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class USB_INTERFACE_DESCRIPTOR
    {
        public byte bLength = 9;               // Length of this descriptor.
        public byte bDescriptorType = 0x04;       // INTERFACE descriptor type (USB_DESCRIPTOR_INTERFACE).
        public byte bInterfaceNumber;      // Number of this interface (0 based).
        public byte bAlternateSetting;     // Value of this alternate interface setting.
        public byte bNumEndpoints;         // Number of endpoints in this interface.
        public byte bInterfaceClass;       // Class code (assigned by the USB-IF).  0xFF-Vendor specific.
        public byte bInterfaceSubClass;    // Subclass code (assigned by the USB-IF).
        public byte bInterfaceProtocol;    // Protocol code (assigned by the USB-IF).  0xFF-Vendor specific.
        public byte iInterface;            // Index of String Descriptor describing the interface.

        public byte[] ToBytes()
        {
            return Converter.StructureToByteArray(this);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class USB_ENDPOINT_DESCRIPTOR
    {
        public byte bLength = 7;               // Length of this descriptor.
        public byte bDescriptorType = 0x05;       // ENDPOINT descriptor type (USB_DESCRIPTOR_ENDPOINT).
        public byte bEndpointAddress;      // Endpoint address. Bit 7 indicates direction (0=OUT, 1=IN).
        public byte bmAttributes;          // Endpoint transfer type.
        public short wMaxPacketSize;        // Maximum packet size.
        public byte bInterval;             // Polling interval in frames.

        public byte[] ToBytes()
        {
            return Converter.StructureToByteArray(this);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class USB_STRING_DESCRIPTOR
    {
        public USB_STRING_DESCRIPTOR(string txt)
        {
            bString = System.Text.Encoding.Unicode.GetBytes(txt);
            bLength =(byte) (bString.Length  + 2) ;
        }
        public byte bLength;               // Length of this descriptor.
        public byte bDescriptorType = 0x03;       // 0x03 ENDPOINT descriptor type (USB_DESCRIPTOR_ENDPOINT).
        public byte[] bString;            // String data, encoded in UTF-16LE format.

        public byte[] ToBytes()
        {

           
            var result = new byte[bLength];
            result[0] = bLength;
            result[1] = bDescriptorType;
            Array.Copy(bString, 0, result, 2, bString.Length);
            return result;

        }
    }

}
