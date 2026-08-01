namespace VFido.Core.Protocol.Helper
{
    /// <summary>
    /// Abstracts "write these bytes back to whoever sent the request" so that
    /// protocol/device logic can be unit tested without a real TcpClient/socket.
    /// </summary>
    public interface IPacketSink
    {
        void Send(byte[] data);
    }
}
