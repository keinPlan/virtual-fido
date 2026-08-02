using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using VFido.Core.Device.Ctap;
using VFido.Core.Protocol;
using VFido.Core.Protocol.Helper;
using VFido.SecretManager;

namespace VFido.Core.Device
{
    internal class FidoUsbStick : VirtualUsbDevice
    {
        private NLog.Logger logger = LogManager.GetCurrentClassLogger();
        private readonly Ctap2.Authenticator.IAuthenticator _authenticator;

        public FidoUsbStick(int deviceID,
            string? serialNumber = null,
            byte[]? aaguid = null,
            Ctap2.Authenticator.IUserPresenceGate? presenceGate = null,
            IFido2SecretManager? secretManager = null,
            IPinStateStore? pinStateStore = null) : base(deviceID)
        {
            serialNumber ??= "VFIDO-" + deviceID.ToString("X8");
            aaguid ??= DefaultAaguid(deviceID);

            _authenticator = new Ctap2.Authenticator.Fido2Authenticator(
                secretManager ?? new Fido2SecretManager(
                    new VFido.SecretManager.MemoryBasedSecretStore.MemoryBasedSecretStore(),
                    new VFido.SecretManager.MemoryBasedSecretStore.InMemoryCredentialStore()),
                aaguid,
                presenceGate,
                pinStateStore);

            base.UsbDescriptor_Device = new UsbTypes.USB_DEVICE_DESCRIPTOR()
            {
                bcdUSB = 0x0200, // USB 2.0
                bDeviceClass = 0x00, // Class code (0x00 for vendor-specific)
                bDeviceSubClass = 0x00, // Subclass code
                bDeviceProtocol = 0x00, // Protocol code
                bMaxPacketSize0 = 64, // Max packet size for endpoint 0
                idVendor = 6483, // idVendor => IronKey Inc.
                idProduct = 0x1337, // Example Product ID
                bcdDevice = 0x0100, // Device release number
                iManufacturer = 1, // Index of manufacturer string descriptor
                iProduct = 2, // Index of product string descriptor
                iSerialNumber = 3, // Index of serial number string descriptor
                bNumConfigurations = 1 // Number of configurations
            };

            UsbDescriptor_Strings.Add(1, new UsbTypes.USB_STRING_DESCRIPTOR("Virtual Security"));
            UsbDescriptor_Strings.Add(2, new UsbTypes.USB_STRING_DESCRIPTOR("VFIDO Security Key"));
            UsbDescriptor_Strings.Add(3, new UsbTypes.USB_STRING_DESCRIPTOR(serialNumber));
            UsbDescriptor_Strings.Add(4, new UsbTypes.USB_STRING_DESCRIPTOR("CTAP2 HID"));

            base.UsbDescriptors_Configurations = new UsbTypes.USB_CONFIGURATION[]
            {
                 new UsbTypes.USB_CONFIGURATION()
                 {
                     USB_CONFIGURATION_DESCRIPTOR=  new  UsbTypes.USB_CONFIGURATION_DESCRIPTOR()
                     {
                        wTotalLength = 41, // Total length of all descriptors for this configuration
                        bNumInterfaces = 1, // Number of interfaces in this configuration
                        bConfigurationValue = 1, // Value to select this configuration
                        iConfiguration = 4, // Index of configuration string descriptor
                        bmAttributes = 0b1000_0000, // Bus-powered
                        bMaxPower = 50,// Max power consumption in mA,
                     },
                     USB_INTERFACE_DESCRIPTORS = new []
                     {
                         new UsbTypes.USB_INTERFACE() {
                             USB_INTERFACE_DESCRIPTOR = new UsbTypes.USB_INTERFACE_DESCRIPTOR
                             {
                                bInterfaceNumber = 0, // Interface number
                                bAlternateSetting = 0, // Alternate setting
                                bNumEndpoints = 2, // Number of endpoints in this interface
                                bInterfaceClass = 0x03, // HID class
                                bInterfaceSubClass = 0x00, // No subclass
                                bInterfaceProtocol = 0x00, // No protocol
                                iInterface = 2,// Index of interface string descriptor
                             },

                             USB_HID_DESCRIPTOR = new UsbTypes.USB_HID_DESCRIPTOR()
                             {
                                  bLength = 9, // Length of this descriptor
                                  bDescriptorType = 0x21, // HID descriptor type
                                  bcdHID = 0x0111, // HID version 1.11
                                  bCountryCode = 0x00, // No country code                                   
                                  bNumDescriptors = 1, // Number of HID descriptors
                                  bRPDescriptorType = 0x22, // Report descriptor type
                                  wRPDescriptorLength = 0x22 // Length of the report descriptor
                             },
                             USB_ENDPOINT_DESCRIPTORS = new []
                             {            
                        
                                  new UsbTypes.USB_ENDPOINT_DESCRIPTOR
                                  {
                                      bEndpointAddress = 0x81, // IN endpoint
                                      bmAttributes = 0x03, // Interrupt transfer type
                                      wMaxPacketSize = 64, // Max packet size for this endpoint
                                      bInterval = 5 // Polling interval in ms
                                  },
                                new UsbTypes.USB_ENDPOINT_DESCRIPTOR
                                  {
                                      bEndpointAddress = 0x01, // OUT endpoint
                                      bmAttributes = 0x03, // Interrupt transfer type
                                      wMaxPacketSize = 64, // Max packet size for this endpoint
                                      bInterval = 5 // Polling interval in ms
                                  },
                              },


                         }
                     },
                 }
            };
        }

        /// <summary>Deterministic 16-byte AAGUID fallback for callers (mainly tests) that don't configure a real per-stick identity.</summary>
        private static byte[] DefaultAaguid(int deviceID)
        {
            var bytes = new byte[16];
            BitConverter.GetBytes(deviceID).CopyTo(bytes, 0);
            return bytes;
        }

        protected override async Task HandleCtapMessage(uint cid, byte cmd, byte[] payload)
        {
            logger.Debug(() => $"CTAP cid={cid:X8} cmd={cmd:X2} len={payload.Length}");

            if (cmd == CtapHidConstants.CTAPHID_CBOR)
            {
                byte[] response;
                using (StartKeepAlive(cid))
                {
                    response = await Ctap2.Ctap2Dispatcher.Handle(payload, _authenticator);
                }
                logger.Debug(() => $"CTAP2 cid={cid:X8} status={response[0]:X2} responseLen={response.Length}");
                SendCtapResponse(cid, CtapHidConstants.CTAPHID_CBOR, response);
                return;
            }

            logger.Warn(() => $"CTAP cid={cid:X8} cmd={cmd:X2} not implemented (U2F/unknown command)");
            SendCtapResponse(cid, CtapHidConstants.CTAPHID_ERROR, new[] { CtapHidConstants.CTAP1_ERR_INVALID_CMD });
        }

        /// <summary>
        /// Sends CTAPHID_KEEPALIVE while a CBOR command is in flight, so the host doesn't consider
        /// this authenticator unresponsive during a (potentially long) user-presence prompt.
        /// </summary>
        private IDisposable StartKeepAlive(uint cid)
        {
            var cts = new System.Threading.CancellationTokenSource();
            _ = Task.Run(async () =>
            {
                try
                {
                    while (!cts.IsCancellationRequested)
                    {
                        await Task.Delay(100, cts.Token);
                        SendCtapResponse(cid, CtapHidConstants.CTAPHID_KEEPALIVE, new[] { CtapHidConstants.CTAPHID_KEEPALIVE_STATUS_UP_NEEDED });
                    }
                }
                catch (TaskCanceledException) { }
            });
            return new CancelOnDispose(cts);
        }

        private sealed class CancelOnDispose : IDisposable
        {
            private readonly System.Threading.CancellationTokenSource _cts;
            public CancelOnDispose(System.Threading.CancellationTokenSource cts) => _cts = cts;
            public void Dispose()
            {
                _cts.Cancel();
                _cts.Dispose();
            }
        }
    }

}
