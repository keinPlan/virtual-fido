
using NLog;
using System;
using System.IO;
using System.Reflection;
using System.Threading;
using VFido.Core.Device.Ctap;
using VFido.Core.Device.UsbTypes;
using VFido.Core.Protocol;
using VFido.Core.Protocol.Helper;

namespace VFido.Core.Device
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

        private readonly object _ctapLock = new();
        private readonly CtapHidReassembler _ctapReassembler = new();
        private readonly HashSet<uint> _ctapChannels = new();
        private uint _nextCid = 1;
        private readonly Queue<byte[]> _ctapOutQueue = new();
        private readonly LinkedList<(IPacketSink source, USBIP_CMD_SUBMIT usb_req, CancellationTokenSource timeout)> _pendingInRequests = new();



        public void HandleUsbRequest(IPacketSink source, USBIP_CMD_SUBMIT usb_req)
        {
            try
            {
                Logger.Trace(() => $"<< {usb_req.Header.Command:X2} {usb_req.Header.EndPoint:X2} {usb_req.Header.Seq:X8} {usb_req.TransferBufferLength:X8} {usb_req.Setup:X16} {BitConverter.ToString(usb_req?.Buffer?? new byte[0], 0, usb_req?.Buffer?.Length??0)}");

                if (usb_req.Header.Command == 2)
                {
                    HandleUnlink(source, usb_req);
                    return;
                }



                if (usb_req.Header.EndPoint == 0)
                {
                    // TraceLog("#control requests");
                    handle_usb_control(source, usb_req);
                }
                else
                {
                    HandleInterruptRequest(source, usb_req);
                    return;
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Unhandled exception while processing USB request seq={0:X8}", usb_req.Header.Seq);
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
                return;
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
            Logger.Warn(() => $"Unhandled control request: {setupData}");

        }
         
        private void SendResponse(IPacketSink source, USBIP_CMD_SUBMIT usb_req, byte[] data, int size, int status)
        {
            var rsp = new USBIP_RET_SUBMIT(usb_req, data.AsSpan(0, size).ToArray(), status);

            using (var bw = new BinaryWriter(new MemoryStream(), System.Text.Encoding.UTF8, true))
            {
                rsp.WriteToStream(bw);

                var packet = (bw.BaseStream as MemoryStream).ToArray();
                Logger.Trace(() => $">> {BitConverter.ToString(packet)}");
                source.Send(packet);
            }
        }

        private const int CtapInPollTimeoutMs = 4000;

        private void HandleInterruptRequest(IPacketSink source, USBIP_CMD_SUBMIT usb_req)
        {
            if (usb_req.Header.Direction == (Direction)0 && usb_req.Buffer != null)
            {
                HandleCtapOutReport(usb_req.Buffer);
                SendResponse(source, usb_req, Array.Empty<byte>(), 0, 0);
                return;
            }

            HandleCtapInPoll(source, usb_req);
        }

        private void HandleCtapOutReport(byte[] report)
        {
            uint cid;
            byte cmd;
            byte[]? payload;
            bool dispatchOutsideLock;

            lock (_ctapLock)
            {
                if (!_ctapReassembler.TryAccept(report, out cid, out cmd, out payload) || payload == null)
                {
                    Logger.Trace(() => "CTAPHID report accepted into reassembler, message not yet complete");
                    return;
                }

                Logger.Debug(() => $"CTAPHID message reassembled: cid={cid:X8} cmd={cmd:X2} payloadLen={payload.Length}");

                if (cmd == CtapHidConstants.CTAPHID_INIT)
                {
                    HandleCtapInit(cid, payload);
                    dispatchOutsideLock = false;
                }
                else if (cmd == CtapHidConstants.CTAPHID_PING)
                {
                    SendCtapResponseLocked(cid, cmd, payload);
                    dispatchOutsideLock = false;
                }
                else if (cid != CtapHidConstants.BroadcastCid && !_ctapChannels.Contains(cid))
                {
                    Logger.Warn(() => $"CTAPHID message on unknown/unallocated channel cid={cid:X8} cmd={cmd:X2}");
                    SendCtapResponseLocked(cid, CtapHidConstants.CTAPHID_ERROR, new[] { CtapHidConstants.CTAP1_ERR_INVALID_CHANNEL });
                    dispatchOutsideLock = false;
                }
                else
                {
                    // HandleCtapMessage (CBOR dispatch) can block for a long time waiting on user
                    // presence, so it must run outside this lock - otherwise the keepalive sender
                    // (which needs this same lock to push CTAPHID_KEEPALIVE) starves for the whole
                    // wait and the host times the request out before the user ever gets to respond.
                    dispatchOutsideLock = true;
                }
            }

            if (dispatchOutsideLock)
            {
                // Also run off the calling thread entirely (not just outside the lock): this method
                // is invoked synchronously from HandleInterruptRequest, which still needs to ack the
                // raw USB OUT transfer right away. A USB write's ack is expected near-instantly; if a
                // user-presence wait held it up for seconds, the host's USB stack considers the
                // transfer stuck and resets/re-enumerates the device before the real CTAP response
                // can ever be delivered.
                var localCid = cid;
                var localCmd = cmd;
                var localPayload = payload;
                _ = Task.Run(() => HandleCtapMessage(localCid, localCmd, localPayload));
            }
        }

        private void HandleCtapInit(uint requestCid, byte[] nonce)
        {
            var assignedCid = requestCid;
            if (requestCid == CtapHidConstants.BroadcastCid)
            {
                assignedCid = _nextCid++;
                _ctapChannels.Add(assignedCid);
                Logger.Debug(() => $"CTAPHID_INIT: allocated new channel cid={assignedCid:X8}");
            }

            var response = new byte[17];
            Array.Copy(nonce, 0, response, 0, Math.Min(nonce.Length, 8));
            response[8] = (byte)((assignedCid >> 24) & 0xff);
            response[9] = (byte)((assignedCid >> 16) & 0xff);
            response[10] = (byte)((assignedCid >> 8) & 0xff);
            response[11] = (byte)(assignedCid & 0xff);
            response[12] = CtapHidConstants.CtapHidProtocolVersion;
            response[13] = 1; // device version major
            response[14] = 0; // device version minor
            response[15] = 0; // device version build
            response[16] = CtapHidConstants.CapabilityWink | CtapHidConstants.CapabilityCbor | CtapHidConstants.CapabilityNoMsg;

            SendCtapResponseLocked(requestCid, CtapHidConstants.CTAPHID_INIT, response);
        }

        /// <summary>
        /// Handles USBIP_CMD_UNLINK (command 2): the host cancelling a previously submitted URB,
        /// most commonly a stale CTAP IN poll it's about to replace with a fresh one. Without this,
        /// the abandoned poll stayed in <see cref="_pendingInRequests"/> and could steal the next
        /// real CTAP2 response meant for the host's current poll (FIFO match in
        /// <see cref="SendCtapResponseLocked"/>), forcing the genuine poll to sit until it hit
        /// <see cref="CtapInPollTimeoutMs"/> and the host retried - the exact "must wait ~4s" symptom
        /// during PIN entry, which does several quick CTAP2 round trips while polling.
        /// </summary>
        private void HandleUnlink(IPacketSink source, USBIP_CMD_SUBMIT usb_req)
        {
            const int EConnReset = -104;

            lock (_ctapLock)
            {
                for (var node = _pendingInRequests.First; node != null; node = node.Next)
                {
                    if (node.Value.usb_req.Header.Seq != usb_req.UnlinkSeqNum)
                        continue;

                    node.Value.timeout.Cancel();
                    _pendingInRequests.Remove(node);
                    SendResponse(node.Value.source, node.Value.usb_req, Array.Empty<byte>(), 0, EConnReset);
                    break;
                }
            }

            SendResponse(source, usb_req, Array.Empty<byte>(), 0, 0);
        }

        private void HandleCtapInPoll(IPacketSink source, USBIP_CMD_SUBMIT usb_req)
        {
            lock (_ctapLock)
            {
                if (_ctapOutQueue.Count > 0)
                {
                    var packet = _ctapOutQueue.Dequeue();
                    SendResponse(source, usb_req, packet, packet.Length, 0);
                    return;
                }

                var timeout = new CancellationTokenSource();
                var node = _pendingInRequests.AddLast((source, usb_req, timeout));

                Task.Delay(CtapInPollTimeoutMs, timeout.Token).ContinueWith(t =>
                {
                    if (t.IsCanceled)
                        return;

                    lock (_ctapLock)
                    {
                        _pendingInRequests.Remove(node);
                    }

                    Logger.Trace(() => $"CTAP IN poll timed out after {CtapInPollTimeoutMs}ms, seq={usb_req.Header.Seq:X8}");
                    SendResponse(source, usb_req, Array.Empty<byte>(), 0, -110);
                }, TaskScheduler.Default);
            }
        }

        /// <summary>
        /// Frames <paramref name="payload"/> as one or more CTAPHID HID reports and either sends it
        /// immediately (if the host is already waiting with a pending IN poll) or queues it for the
        /// next IN poll.
        /// </summary>
        protected void SendCtapResponse(uint cid, byte cmd, byte[] payload)
        {
            lock (_ctapLock)
            {
                SendCtapResponseLocked(cid, cmd, payload);
            }
        }

        private void SendCtapResponseLocked(uint cid, byte cmd, byte[] payload)
        {
            foreach (var packet in CtapHidFramer.Frame(cid, cmd, payload))
                _ctapOutQueue.Enqueue(packet);

            while (_pendingInRequests.Count > 0 && _ctapOutQueue.Count > 0)
            {
                var (pendingSource, pendingRequest, pendingTimeout) = _pendingInRequests.First.Value;
                _pendingInRequests.RemoveFirst();
                pendingTimeout.Cancel();

                var next = _ctapOutQueue.Dequeue();
                SendResponse(pendingSource, pendingRequest, next, next.Length, 0);
            }
        }

        /// <summary>
        /// Called once a complete CTAPHID message (CTAPHID_MSG/CTAPHID_CBOR/etc.) has been reassembled
        /// on an allocated channel. CTAPHID_INIT and CTAPHID_PING are handled generically above and never
        /// reach this hook. Default implementation replies with CTAPHID_ERROR(invalid command).
        /// </summary>
        protected virtual Task HandleCtapMessage(uint cid, byte cmd, byte[] payload)
        {
            SendCtapResponse(cid, CtapHidConstants.CTAPHID_ERROR, new[] { CtapHidConstants.CTAP1_ERR_INVALID_CMD });
            return Task.CompletedTask;
        }
    }
}
