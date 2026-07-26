
using NLog;
using System;
using System.IO;
using System.Reflection;
using VirtualFido.UsbIp.Device.UsbTypes;
using VirtualFido.UsbIp.Protocol;
using VirtualFido.UsbIp.Protocol.Helper;

namespace VirtualFido.UsbIp.Device
{


    public class VirtualUsbDevice
    {
        public int DeviceID { get; set; } = 0x00010001;
        public short DeviceBusNum { get => (short)((DeviceID >> 16) & 0xffff); } 
        public short DeviceBusID { get => (short) ((DeviceID >> 00) & 0xffff);  }

        public VirtualUsbDevice(int deviceID)
        {
            DeviceID = deviceID;
        }

        private Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        public USB_DEVICE_DESCRIPTOR UsbDescriptor_Device;
        public USB_CONFIGURATION[] UsbDescriptors_Configurations;
        public Dictionary<int, USB_STRING_DESCRIPTOR> UsbDescriptor_Strings = new();



        public void HandleUsbRequest(IPacketSink source, USBIP_CMD_SUBMIT usb_req)
        {
            try
            {
                Logger.Info(() => $"<< {usb_req.Header.Command:X2} {usb_req.Header.EndPoint:X2} {usb_req.Header.Seq:X8} {usb_req.TransferBufferLength:X8} {usb_req.Setup:X16} {BitConverter.ToString(usb_req?.Buffer?? new byte[0], 0, usb_req?.Buffer?.Length??0)}");
         
                if (usb_req.Header.Command == 2) 
                {
                    SendResponse(source, usb_req, new byte[0], 0, 0);
                    return;
                }



                if (usb_req.Header.EndPoint == 0)
                {
                    // TraceLog("#control requests");
                    handle_usb_control(source, usb_req);
                }
                else
                { 
                    Task.Delay(4000).ContinueWith(_ =>                    SendResponse(source, usb_req, new byte[0], 0, -110));
                    return;
              
                }
            }
            catch (Exception ex )
            {
                Console.WriteLine(  ex);
            }
 
        }
        
        private void handle_usb_control(IPacketSink source, USBIP_CMD_SUBMIT usb_req)
        {
            var setupData = usb_req.ParseSetupData();
            
            if ((setupData.bmRequestType & 0x60) == 0x20) // Class Request
            {
                switch (setupData.bRequest)
                {
                    case 0x0A: // SET_IDLE
                        SendResponse(source, usb_req, Array.Empty<byte>(), 0, 0);
                        return;

                    case 0x09: // SET_REPORT
                        SendResponse(source, usb_req, Array.Empty<byte>(), 0, 0);
                        return;

                    case 0x01: // GET_REPORT
                        SendResponse(source, usb_req, Array.Empty<byte>(), 0, 0);
                        return;

                    case 0x0B: // SET_PROTOCOL
                        SendResponse(source, usb_req, Array.Empty<byte>(), 0, 0);
                        return;
                }
            }

            if ((setupData.bmRequestType & 0x0f) == 0x00) // Standard Device Requests
            {
                // bRequest
                // GET_STATUS (0x00)
                if (setupData.bRequest == 0)
                {
                    // Logger.Info(() => $"{setupData} GET_STATUS");
                    SendResponse(source, usb_req, new byte[] { 0x01 /*SelfPowered*/, 0x00 }, 1, 0);
                    return;
                }
                // CLEAR_FEATURE (0x01) not needed
                // SET_FEATURE (0x03) not needed
                // SET_ADDRESS (0x05)
                // GET_DESCRIPTOR (0x06)
                if (setupData.bRequest == 6)
                {
                   // Logger.Info(() => $"{setupData} GET_DESCRIPTOR");

                    switch (setupData.wValue & 0xff)
                    {
                        case 0x01: // Device Descriptor
                            {
                                var buffer = this.UsbDescriptor_Device.ToBytes();
                                SendResponse(source, usb_req, buffer, buffer.Length, 0);
                                break;
                            }
                        case 0x02: // Configuration Descriptor
                            {

                                var data = this.UsbDescriptors_Configurations[0].ToBytes();
                                SendResponse(source, usb_req, data, setupData.wLength > data.Length ? data.Length : setupData.wLength, 0);
                                break;
                            }
                        case 0x03: // String Descriptor
                            {
                                var index = ((setupData.wValue >> 8) & 0xff);

                                if (index == 0)
                                {
                                    SendResponse(source, usb_req, new byte[] { 04, 03, 09, 04 }, 4, 0);
                                    return;
                                }


                                var buffer = (this.UsbDescriptor_Strings.Count > index) ? this.UsbDescriptor_Strings[index].ToBytes() : new byte[] { 2, 3 };
                                SendResponse(source, usb_req, buffer, buffer.Length, 0);
                                break;
                            }
                        case 0x04: // Interface Descriptor
                        case 0x05: // Endpoint Descriptor
                        case 0x06: // Device_Qualifier
                            SendResponse(source, usb_req, new byte[] { }, 0, -32); // stall
                            return;
                        case 0x22:
                        case 0x0f: // FIDO U2F HID Report Descriptor"
                            {
                                var data = new byte[] { 0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0 };

                                SendResponse(source, usb_req, data , setupData.wLength > data.Length ? data.Length : setupData.wLength, 0); // stall
                                return;
                            }
                        case 0x29: // Hub Descriptor
                        case 0x21: // Human Interface Class Descriptor (HID)
                            {
                                var buffer = this.UsbDescriptors_Configurations[0].USB_INTERFACE_DESCRIPTORS[0].USB_HID_DESCRIPTOR.ToBytes();
                                SendResponse(source, usb_req, buffer, buffer.Length, 0);
                                return;
                            }
                        //case 0x22:
                        //    SendResponse(source, usb_req, new byte[] { }, 0, -32); // stall
                        //    return;
                        default:
                            break;
                    }


                    return;
                }

                // SET_DESCRIPTOR (0x07)
                // GET_CONFIGURATION (0x08)
                // SET_CONFIGURATION (0x09)
                if (setupData.bRequest == 9)
                {
                   // Logger.Info(() => $"{setupData} SET_CONFIGURATION");
                    SendResponse(source, usb_req, new byte[0], 0, 0);
                    return;
                }
                // 0x0b set interface ?
            }

            if ((setupData.bmRequestType & 0x01) != 0x00) // Standard Interface Requests
            {
                // bRequest
                // GET_STATUS (0x00)
                // CLEAR_FEATURE (0x01)
                // SET_FEATURE (0x03)
                // SET_ADDRESS (0x05)
                if (setupData.bRequest == 6 && setupData.wValue == 0x22) 
                {
                    // GET Report Descriptor
                    // var data = this.GetDescriptor(0x22);

                    var data = new byte[] { 0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0 };
                    
                    SendResponse(source, usb_req, data, setupData.wLength > data.Length ? data.Length : setupData.wLength, 0);
                    return;

                }

                // GET_INTERFACE (0x0A)
                // SET_INTERFACE (0x11)   

                SendResponse(source, usb_req, new byte[0], 0, 0);
                return;
            }

            if ((setupData.bmRequestType & 0x02) != 0x00) // Standard Endpoint Requests
            {
                // bRequest
                // GET_STATUS (0x00)
                // CLEAR_FEATURE (0x01)
                // SYNCH_FRAME (0x12)     
                SendResponse(source, usb_req, new byte[0], 0, 0);
            }

            /*
            if (setupData.bmRequestType == 0x80) // Host Request
            {
                if (setupData.bRequest == 0x06) // Get Descriptor
                {
                    Logger.Info(() => $"Type:{setupData.bmRequestType:X2} Req:{setupData.bRequest:X2} GetDescriptor");
                    handle_get_descriptor(source, setupData, usb_req);
                    return;
                }

                if (setupData.bRequest == 0x00) // Get STATUS
                {
                    Logger.Info(() => $"Type:{setupData.bmRequestType:X2} Req:{setupData.bRequest:X2} GetStatus");
                    byte[] data = new byte[2];
                    data[0] = 0x01;
                    data[1] = 0x00;
                    SendResponse(source, usb_req, data, 2, 0);
                    return;
                }
            }

            if (setupData.bmRequestType == 0x00) // 
            {
                if (setupData.bRequest == 0x09) // Set Configuration
                {
                    Logger.Info(() => $"Type:{setupData.bmRequestType:X2} Req:{setupData.bRequest:X2} SetConfiguration");
                    // handled = handle_set_configuration(clntSocket, controlRequest, usb_req);
                    return;
                }
            }

            if (setupData.bmRequestType == 0x01)
            {
                if (setupData.bRequest == 0x0B) //SET_INTERFACE  
                {
                    Logger.Info(() => $"Type:{setupData.bmRequestType:X2} Req:{setupData.bRequest:X2} SetInterface");
                    // TraceLog("SET_INTERFACE");
                    send_usb_req(clntSocket, usb_req, null, 0, 1);
                    return;
                }
            }

            if (setupData.bmRequestType == 0x81)
            {
                if (setupData.bRequest == 0x6)  //# Get Descriptor
                {
                    if (setupData.wValue1 == 0x22)  // send initial report
                    {
                        Logger.Info(() => $"Type:0x{setupData.bmRequestType:X2} Req:0x{setupData.bRequest:X2} w1:0x${setupData.wValue1:X2} SendInitialReport");
                        //  TraceLog("send initial report");
                        // send_usb_req(source, usb_req, _report_descriptor, (uint)_report_descriptor.Length, 0);
                    }
                }
            }

            if (setupData.bmRequestType == 0x21)  // Host Request
            {
                if (setupData.bRequest == 0x0a)  // set idle
                {
                    Logger.Info(() => $"Type:0x{setupData.bmRequestType:X2} Req:0x{setupData.bRequest:X2} w1:0x${setupData.wValue1:X2} SetIdle");
                    //  TraceLog("Idle");
                    // send_usb_req(clntSocket, usb_req, null, 0, 0);
                }

                if (setupData.bRequest == 0x09)  // set report
                {
                    Logger.Info(() => $"Type:0x{setupData.bmRequestType:X2} Req:0x{setupData.bRequest:X2} w1:0x${setupData.wValue1:X2} SetReport");
                    // TraceLog("set report");

                    // byte[] data = new byte[20];
                    // if (clntSocket.Receive(data, control_req.wLength, 0) != control_req.wLength)
                    // {
                    //     TraceLog("receive error : {errno}");
                    //     Environment.Exit(-1);
                    // }
                    // ;
                    // 
                    // send_usb_req(clntSocket, usb_req, null, 0, 0);
                }
            }
*/
            Logger.Info(() => $"{setupData} Unknowen");

        }
         
        private void SendResponse(IPacketSink source, USBIP_CMD_SUBMIT usb_req, byte[] data, int size, int status)
        {
            var rsp = new USBIP_RET_SUBMIT(usb_req, data.AsSpan(0, size).ToArray(), status);

            using (var bw = new BinaryWriter(new MemoryStream(), System.Text.Encoding.UTF8, true))
            {
                rsp.WriteToStream(bw);

                var packet = (bw.BaseStream as MemoryStream).ToArray();
                Logger.Info(() => $">> {BitConverter.ToString(packet)}");
                source.Send(packet);
            }
        }

       
    }
}
