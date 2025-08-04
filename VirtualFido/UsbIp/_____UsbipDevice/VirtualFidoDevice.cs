using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UsbipDevice;

namespace VirtualFido.UsbIp.UsbipDevice
{






    internal class VirtualFidoDevice
    {
        private USB_DEVICE_DESCRIPTOR _DEVICE_DESCRIPTOR = new USB_DEVICE_DESCRIPTOR
        {
            bLength = 18,
            bDescriptorType = (byte)DescriptorType.USB_DESCRIPTOR_DEVICE,
            bcdUSB = 0x0200, // USB 2.0
            bDeviceClass = 0x00, // Class defined at interface level
            bDeviceSubClass = 0x00,
            bDeviceProtocol = 0x00,
            bMaxPacketSize0 = 64, // Max packet size for endpoint 0
            idVendor = 0x0483, // Example Vendor ID (STM)
            idProduct = 0x1337, // Example Product ID
            bcdDevice = 0x0100, // Device release number
            iManufacturer = 1, // Index of manufacturer string descriptor
            iProduct = 2, // Index of product string descriptor
            iSerialNumber = 3, // Index of serial number string descriptor
            bNumConfigurations = 1 // Number of configurations supported
        };

       

        CONFIG_HID2 test = new CONFIG_HID2()
        {
            dev_conf = new USB_CONFIGURATION_DESCRIPTOR
            {
                bLength = 9,
                bDescriptorType = (byte)DescriptorType.USB_DESCRIPTOR_CONFIGURATION,
                wTotalLength = 41, // Will be set later
                bNumInterfaces = 1, // Number of interfaces in this configuration
                bConfigurationValue = 1, // Value to select this configuration
                iConfiguration = 0, // Index of configuration string descriptor
                bmAttributes = 0x80, // Bus-powered
                bMaxPower = 50 // Max power consumption in mA
            },
            dev_int = new USB_INTERFACE_DESCRIPTOR[]
            {
                new USB_INTERFACE_DESCRIPTOR
                {
                    bLength = 9,
                    bDescriptorType = (byte)DescriptorType.USB_DESCRIPTOR_INTERFACE,
                    bInterfaceNumber = 0, // Interface number
                    bAlternateSetting = 0, // Alternate setting
                    bNumEndpoints = 2, // Number of endpoints
                    bInterfaceClass = 0x03, // HID class
                    bInterfaceSubClass = 0x00, // No subclass
                    bInterfaceProtocol = 0x00, // No protocol
                    iInterface = 2 // Index of interface string descriptor
                }
            },
            dev_hid = new USB_HID_DESCRIPTOR[] { 
                new USB_HID_DESCRIPTOR
                {
                    bLength = 9,
                    bDescriptorType = 0x21,
                    bcdHID = 0x0111, // HID version 1.11
                    bCountryCode = 0x00, // No country code
                    bNumDescriptors = 1, // Number of HID descriptors
                    bRPDescriptorType =  0x22, // DescriptorType.USB_DESCRIPTOR_REPORT,
                    wRPDescriptorLength = 34 // Length of the report descriptor
                } 
            },
            dev_ep = new USB_ENDPOINT_DESCRIPTOR[] {             
                new USB_ENDPOINT_DESCRIPTOR
                {
                    bLength = 7,
                    bDescriptorType = (byte)DescriptorType.USB_DESCRIPTOR_ENDPOINT,
                    bEndpointAddress = 0x81, // IN endpoint 1
                    bmAttributes = 0x03, // Interrupt transfer type
                    wMaxPacketSize = 64, // Max packet size for this endpoint
                    bInterval = 5 // Polling interval in ms
                },
                new USB_ENDPOINT_DESCRIPTOR
                {
                    bLength = 7,
                    bDescriptorType = (byte)DescriptorType.USB_DESCRIPTOR_ENDPOINT,
                    bEndpointAddress = 0x01, // OUT endpoint 1
                    bmAttributes = 0x03, // Interrupt transfer type
                    wMaxPacketSize = 64, // Max packet size for this endpoint
                    bInterval = 5 // Polling interval in ms
                }
            },
          

        };

        private Usbip _device;

        public VirtualFidoDevice(Usbip device)
        {
            _device = device;

        }
    }

}
