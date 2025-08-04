using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;
using VirtualFido.UsbIp.Device;
using VirtualFido.UsbIp.Protocol.Helper;

namespace VirtualFido.UsbIp.Protocol
{

    public enum Direction
    {
        IN = 0,
        OUT = 1
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class UsbIpBasicHeader
    {
        internal const int SIZE = 5*4;

        public int Command;
        public int Seq;
        public int DevID;
        public Direction Direction;
        public int EndPoint;


        public static UsbIpBasicHeader Parse(byte[] buffer, int offset)
        {
            if (buffer == null || buffer.Length < offset + 16)
                throw new ArgumentException("Buffer is too small to contain a UsbIpBasicHeader.");
            UsbIpBasicHeader header = new UsbIpBasicHeader();

            header.Command = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + 0));
            header.Seq = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + 4));
            header.DevID = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + 8));
            header.Direction = (Direction)BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + 12));
            header.EndPoint = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + 16));

            return header;
        }

        internal void WriteToStream(BinaryWriter bw)
        {
            bw.WriteMSB(Command);
            bw.WriteMSB(Seq);
            bw.WriteMSB(DevID);
            bw.WriteMSB((int)Direction);
            bw.WriteMSB(EndPoint);
        }
    }



    public class USBIP_CMD_SUBMIT
    {
        public UsbIpBasicHeader Header; // usbip_header_basic, ‘command’ shall be 0x00000001
        public int TransferFlags;
        public int TransferBufferLength;
        public int StartFrame;
        public int NumberOfPackets;
        public int Interval;
        public long Setup;
        public byte[] Buffer;

        internal UsbSetupData ParseSetupData()
        {
            UsbSetupData usbSetupData = new UsbSetupData();
            usbSetupData.bmRequestType = (byte)(((ulong)this.Setup & 0xFF00000000000000) >> 56);
            usbSetupData.bRequest = (byte)(((ulong)this.Setup & 0x00FF000000000000) >> 48);
            usbSetupData.wValue = (short)((this.Setup & 0x0000FFFF00000000) >> 32);
            usbSetupData.wIndex = IPAddress.NetworkToHostOrder((short)((this.Setup & 0x00000000FFFF0000) >> 16));
            usbSetupData.wLength = IPAddress.NetworkToHostOrder((short)(this.Setup & 0x000000000000FFFF));
            return usbSetupData;

        }

        public static USBIP_CMD_SUBMIT Parse(byte[] buffer, int offset)
        {
            if (buffer == null || buffer.Length < offset + UsbIpBasicHeader.SIZE + 28)
                return null;
            USBIP_CMD_SUBMIT cmd = new USBIP_CMD_SUBMIT();
            cmd.Header = UsbIpBasicHeader.Parse(buffer, offset);
            cmd.TransferFlags = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + UsbIpBasicHeader.SIZE + 0));

            if (cmd.Header.Command != 2)
            {
                cmd.TransferBufferLength = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + UsbIpBasicHeader.SIZE + 4));
                cmd.StartFrame = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + UsbIpBasicHeader.SIZE + 8));
                cmd.NumberOfPackets = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + UsbIpBasicHeader.SIZE + 12));
                cmd.Interval = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(offset + UsbIpBasicHeader.SIZE + 16));
                cmd.Setup = BinaryPrimitives.ReadInt64BigEndian(buffer.AsSpan(offset + UsbIpBasicHeader.SIZE + 20, 8));


                if (cmd.Header.Direction == (Direction)0/*USBIP_DIR_OUT*/)
                {
                    cmd.Buffer = new byte[cmd.TransferBufferLength];
                    if (buffer.Length < offset + UsbIpBasicHeader.SIZE + 28 + cmd.TransferBufferLength)
                        return null; // Not enough data for the transfer buffer
                    Array.Copy(buffer, offset + UsbIpBasicHeader.SIZE + 28, cmd.Buffer, 0, cmd.TransferBufferLength);
                }
            }

            return cmd;
        }

        internal void WriteToStream(BinaryWriter bw)
        {
            this.Header.WriteToStream(bw);
            bw.WriteMSB(TransferFlags);
            bw.WriteMSB(TransferBufferLength);
            bw.WriteMSB(StartFrame);
            bw.WriteMSB(NumberOfPackets);
            bw.WriteMSB(Interval);
            bw.WriteMSB(Setup);
            if (Buffer != null && Buffer.Length > 0)
            {
                bw.Write(Buffer);
            }

        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct UsbSetupData
    {

        public byte bmRequestType;
        public byte bRequest;
        public short wValue;
        public short wIndex;
        public short wLength;

        public override string ToString()
        {
            return $"T:{bmRequestType:X2} R:{bRequest:X2} W:{wValue:X4} I:{wIndex:X4} L:{wLength:X4}";
        }
    }

    public class USBIP_RET_SUBMIT
    {
        public USBIP_RET_SUBMIT(USBIP_CMD_SUBMIT req, byte[] bytes, int status)
        {
            this.Header = new UsbIpBasicHeader()
            {
                Command = req.Header.Command == 1 ?   0x03: 0x04 ,
                DevID = 0,//for server (response), this shall be set to 0,
                Direction = 0, // only used by client, for server this shall be 0
                EndPoint = 0,//ep: endpoint number only used by client, for server this shall be 0; for UNLINK, this shall be 0
                Seq = req.Header.Seq
            };
            this.Status = status;
            this.ActualLength = bytes.Length;
            this.StartFrame = 0; //  start_frame: use URB start_frame; initial frame for ISO transfer; shall be set to 0 if not ISO transfer
            this.NumberOfPackets = 0xffffffff; //number_of_packets: number of ISO packets; shall be set to 0xffffffff if not ISO transfer
            this.ErrorCount = 0;
            this.Padding = 0;
            this.Buffer = bytes;
        }
        public UsbIpBasicHeader Header; //  usbip_header_basic, ‘command’ shall be 0x00000003
        public int Status;
        public int ActualLength;
        public uint StartFrame;
        public uint NumberOfPackets;
        public uint ErrorCount;
        public long Padding;
        public byte[] Buffer;

        internal void WriteToStream(BinaryWriter bw)
        {
            this.Header.WriteToStream(bw);
            bw.WriteMSB(Status);
            bw.WriteMSB(ActualLength);
            bw.WriteMSB(StartFrame);
            bw.WriteMSB(NumberOfPackets);
            bw.WriteMSB(ErrorCount);
            bw.WriteMSB(Padding);
            if (Buffer != null && Buffer.Length > 0)
            {
                bw.Write(Buffer);
            }
       
        }
    }

    internal class USBIP_CMD_UNLINK
    {
        // usbip_header_basic, ‘command’ shall be 0x00000002
        int unlink_seqnum;
        byte[] padding = new byte[24];
    }

    internal class USBIP_RET_UNLINK
    {
        // usbip_header_basic, ‘command’ shall be 0x00000004
        int Status;
        byte[] padding = new byte[24];
    }
}
