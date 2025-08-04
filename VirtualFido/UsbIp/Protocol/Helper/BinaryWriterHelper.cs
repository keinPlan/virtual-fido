using System.IO;


namespace VirtualFido.UsbIp.Protocol.Helper
{
    public static class BinaryWriterHelper
    {
        public static void WriteMSB(this BinaryWriter binaryWriter, Int64 value)
        {
            binaryWriter.Write((byte)(value >> 56 & 0xff));
            binaryWriter.Write((byte)(value >> 48 & 0xff));
            binaryWriter.Write((byte)(value >> 40 & 0xff));
            binaryWriter.Write((byte)(value >> 32 & 0xff));
            binaryWriter.Write((byte)(value >> 24 & 0xff));
            binaryWriter.Write((byte)(value >> 16 & 0xff));
            binaryWriter.Write((byte)(value >> 8 & 0xff));
            binaryWriter.Write((byte)(value >> 0 & 0xff));
        }
        public static void WriteMSB(this BinaryWriter binaryWriter, UInt64 value)
        {
            binaryWriter.Write((byte)(value >> 56 & 0xff));
            binaryWriter.Write((byte)(value >> 48 & 0xff));
            binaryWriter.Write((byte)(value >> 40 & 0xff));
            binaryWriter.Write((byte)(value >> 32 & 0xff));
            binaryWriter.Write((byte)(value >> 24 & 0xff));
            binaryWriter.Write((byte)(value >> 16 & 0xff));
            binaryWriter.Write((byte)(value >> 8 & 0xff));
            binaryWriter.Write((byte)(value >> 0 & 0xff));
        }

        public static void WriteMSB(this BinaryWriter binaryWriter, int value)
        {
            binaryWriter.Write((byte)(value >> 24 & 0xff));
            binaryWriter.Write((byte)(value >> 16 & 0xff));
            binaryWriter.Write((byte)(value >> 8 & 0xff));
            binaryWriter.Write((byte)(value >> 0 & 0xff));
        }

        public static void WriteMSB(this BinaryWriter binaryWriter, uint value)
        {
            binaryWriter.Write((byte)(value >> 24 & 0xff));
            binaryWriter.Write((byte)(value >> 16 & 0xff));
            binaryWriter.Write((byte)(value >> 8 & 0xff));
            binaryWriter.Write((byte)(value >> 0 & 0xff));
        }
        public static void WriteMSB(this BinaryWriter binaryWriter, short value)
        {
            binaryWriter.Write((byte)(value >> 8 & 0xff));
            binaryWriter.Write((byte)(value >> 0 & 0xff));
        }
        public static void WriteMSB(this BinaryWriter binaryWriter, ushort value)
        {
            binaryWriter.Write((byte)(value >> 8 & 0xff));
            binaryWriter.Write((byte)(value >> 0 & 0xff));
        }
    }
}

