using System;
using System.Buffers.Binary;
using System.IO;
using VirtualFido.UsbIp.Device;
using VirtualFido.UsbIp.Protocol;
using VirtualFido.UsbIp.Protocol.Helper;

namespace VirtualFido.UsbIp
{
    public class UsbIpPacketHandler
    {
        const int DEVICE_PACKET_HEADER_SIZE = 48;

        private readonly Dictionary<int, VirtualUsbDevice> _virtualUsbDevices;
        public VirtualUsbDevice AttachedDevice { get; private set; } = null;
        private bool isAttached = false;

        public UsbIpPacketHandler(Dictionary<int, VirtualUsbDevice> virtualUsbDevices)
        {
            _virtualUsbDevices = virtualUsbDevices;
        }

        public int HandleIncommingData(IPacketSink client, byte[] buffer, int bytesInBuffer)
        {
            if (!isAttached)
                return HandleServerMsg(client, buffer, bytesInBuffer);
            return HandleDeviceMsg(client, buffer, bytesInBuffer);
        }

        private int HandleServerMsg(IPacketSink client, byte[] buffer, int bytesInBuffer)
        {
            var bufferOffset = 0;

            while (bytesInBuffer >= (bufferOffset + 8))
            {
                var version = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(bufferOffset + 0));
                var opc = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(bufferOffset + 2));
                var status = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(bufferOffset + 4));

                if (opc == 0x8005) // OP_REQ_DEVLIST
                {
                    bufferOffset += 8; // Move past the header

                    var response = new Protocol.OP_REP_DEVLIST(0, this._virtualUsbDevices);
                    client.Send(response.ToByteArray());
                }
                else if (opc == 0x8003) // OP_REQ_DEVINFO
                {
                    if ((bytesInBuffer - bufferOffset) < 40)
                        return bufferOffset;

                    var txtBusiID = new String(System.Text.Encoding.ASCII.GetString(buffer, bufferOffset + 8, 32).TakeWhile(x => x != '\0').ToArray());
                    bufferOffset += 40; // Move past the header and busid

                    var busNum = int.Parse(txtBusiID.Split('-')[0]);
                    var busId = int.Parse(txtBusiID.Split('-')[1]);

                    var deviceID = busNum << 16 | busId;

                    var device = this._virtualUsbDevices.GetValueOrDefault(deviceID);
                    this.AttachedDevice = device;
                    this.isAttached = device != null;

                    using (var ms = new MemoryStream())
                    using (var bw = new BinaryWriter(ms, System.Text.UTF8Encoding.Default, true))
                    {
                        bw.WriteMSB(version);
                        bw.WriteMSB((ushort)(opc & 0x7fff));
                        bw.WriteMSB(device != null ? 0 : 1); // 0 => OK otherwsie end
                        if (device != null)
                            new UsbDevice(busNum, busId, device).WriteToStream(bw);

                        client.Send(ms.ToArray());
                    }
                }

            }

            return bufferOffset;
        }

        private int HandleDeviceMsg(IPacketSink client, byte[] buffer, int bytesInBuffer)
        {
            var bufferOffset = 0;

            while (bytesInBuffer >= (bufferOffset + DEVICE_PACKET_HEADER_SIZE))
            {
                var packet = USBIP_CMD_SUBMIT.Parse(buffer, bufferOffset);

                if (packet == null)
                    return bufferOffset;
                bufferOffset +=  (packet.Buffer?.Length??0) + DEVICE_PACKET_HEADER_SIZE;

                this.AttachedDevice?.HandleUsbRequest(client, packet);


            }

            return bufferOffset;
        }




    }
}
