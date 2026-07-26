using VirtualFido.UsbIp.Device.UsbTypes;
using Xunit;

namespace VirtualFido.Tests
{
    public class DescriptorsTests
    {
        [Fact]
        public void UsbDeviceDescriptor_ToBytes_MatchesUsbSpecLayout()
        {
            var descriptor = new USB_DEVICE_DESCRIPTOR
            {
                bcdUSB = 0x0200,
                bDeviceClass = 0x00,
                bDeviceSubClass = 0x00,
                bDeviceProtocol = 0x00,
                bMaxPacketSize0 = 64,
                idVendor = 6483,
                idProduct = 0x1337,
                bcdDevice = 0x0100,
                iManufacturer = 1,
                iProduct = 2,
                iSerialNumber = 3,
                bNumConfigurations = 1,
            };

            var bytes = descriptor.ToBytes();

            Assert.Equal(18, bytes.Length);
            Assert.Equal(18, bytes[0]);   // bLength
            Assert.Equal(0x01, bytes[1]); // bDescriptorType = DEVICE
            // bcdUSB, idVendor, idProduct etc. are little-endian on the wire (Marshal struct layout).
            Assert.Equal(0x00, bytes[2]);
            Assert.Equal(0x02, bytes[3]);
            Assert.Equal(64, bytes[7]);   // bMaxPacketSize0
            Assert.Equal(1, bytes[17]);   // bNumConfigurations
        }

        [Fact]
        public void UsbEndpointDescriptor_ToBytes_Is7BytesWithCorrectFields()
        {
            var descriptor = new USB_ENDPOINT_DESCRIPTOR
            {
                bEndpointAddress = 0x81,
                bmAttributes = 0x03,
                wMaxPacketSize = 64,
                bInterval = 5,
            };

            var bytes = descriptor.ToBytes();

            Assert.Equal(7, bytes.Length);
            Assert.Equal(7, bytes[0]);      // bLength
            Assert.Equal(0x05, bytes[1]);   // bDescriptorType = ENDPOINT
            Assert.Equal(0x81, bytes[2]);   // bEndpointAddress
            Assert.Equal(0x03, bytes[3]);   // bmAttributes
            Assert.Equal(5, bytes[6]);      // bInterval
        }

        [Fact]
        public void UsbStringDescriptor_ToBytes_EncodesUtf16LeWithLengthPrefix()
        {
            var descriptor = new USB_STRING_DESCRIPTOR("Vido");

            var bytes = descriptor.ToBytes();

            // 2-byte header + 4 chars * 2 bytes (UTF-16LE) = 10 bytes
            Assert.Equal(10, bytes.Length);
            Assert.Equal(10, bytes[0]);   // bLength
            Assert.Equal(0x03, bytes[1]); // bDescriptorType = STRING
            Assert.Equal(System.Text.Encoding.Unicode.GetBytes("Vido"), bytes[2..]);
        }

        [Fact]
        public void UsbConfiguration_ToBytes_ConcatenatesInterfaceHidAndEndpointDescriptors()
        {
            var config = new USB_CONFIGURATION
            {
                USB_CONFIGURATION_DESCRIPTOR = new USB_CONFIGURATION_DESCRIPTOR
                {
                    bNumInterfaces = 1,
                    bConfigurationValue = 1,
                    iConfiguration = 4,
                    bmAttributes = 0b1000_0000,
                    bMaxPower = 50,
                },
                USB_INTERFACE_DESCRIPTORS = new[]
                {
                    new USB_INTERFACE
                    {
                        USB_INTERFACE_DESCRIPTOR = new USB_INTERFACE_DESCRIPTOR
                        {
                            bInterfaceNumber = 0,
                            bNumEndpoints = 2,
                            bInterfaceClass = 0x03,
                            iInterface = 2,
                        },
                        USB_HID_DESCRIPTOR = new USB_HID_DESCRIPTOR
                        {
                            bLength = 9,
                            bDescriptorType = 0x21,
                            bcdHID = 0x0111,
                            bNumDescriptors = 1,
                            bRPDescriptorType = 0x22,
                            wRPDescriptorLength = 0x22,
                        },
                        USB_ENDPOINT_DESCRIPTORS = new[]
                        {
                            new USB_ENDPOINT_DESCRIPTOR { bEndpointAddress = 0x81, bmAttributes = 0x03, wMaxPacketSize = 64, bInterval = 5 },
                            new USB_ENDPOINT_DESCRIPTOR { bEndpointAddress = 0x01, bmAttributes = 0x03, wMaxPacketSize = 64, bInterval = 5 },
                        },
                    },
                },
            };

            var bytes = config.ToBytes();

            // 9 (config) + 9 (interface) + 9 (HID) + 7 + 7 (endpoints) = 41, matching FidoUsbStick's wTotalLength.
            Assert.Equal(41, bytes.Length);
            Assert.Equal(9, bytes[0]);    // config descriptor bLength
            Assert.Equal(0x02, bytes[1]); // config descriptor type
            Assert.Equal(9, bytes[9]);    // interface descriptor bLength starts right after
            Assert.Equal(0x04, bytes[10]); // interface descriptor type
        }
    }
}
