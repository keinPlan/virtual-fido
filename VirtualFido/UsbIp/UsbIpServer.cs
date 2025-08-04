using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Controls;
using VirtualFido.UsbIp.Device;

namespace VirtualFido.UsbIp
{
    internal class UsbIpServer : IDisposable
    {
        public Dictionary<int, VirtualUsbDevice> VirtualUsbDevices { get; set; } = new();


        private readonly TcpListener _listener;
        private bool _isRunning;

        public UsbIpServer(string ip, int port)
        {
            _listener = new TcpListener(IPAddress.Parse(ip), port);
        }

        public void Start()
        {
            _isRunning = true;
            _listener.Start();
            AcceptClientsAsync();
        }

        private async void AcceptClientsAsync()
        {
            while (_isRunning)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    _ = Task.Run(() => HandleClientAsync(client));
                }
                catch (ObjectDisposedException)
                {
                    // Listener wurde gestoppt
                    break;
                }
                catch (Exception ex)
                {
                    // Optional: Logging
                    Console.WriteLine($"Fehler beim Annehmen eines Clients: {ex.Message}");
                }
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            var usbIpMessageHandler = new UsbIpPacketHandler(VirtualUsbDevices);

            using (client)
            using (var stream = client.GetStream())
            {
                var buffer = new byte[4096];
                var bufferOffset = 0;

                try
                {
                    while (client.Connected)
                    {
                        int bytesInBuffer = await stream.ReadAsync(buffer, bufferOffset, buffer.Length - bufferOffset).ConfigureAwait(false);
                        if (bytesInBuffer == 0)
                        {
                            throw new Exception("Connection lost");
                        }
                        
                        bytesInBuffer += bufferOffset;
                        bufferOffset = usbIpMessageHandler.HandleIncommingData(client, buffer, bytesInBuffer);

                        if ((bytesInBuffer - bufferOffset) != 0)
                        {
                            if (bufferOffset != 0)
                                Buffer.BlockCopy(buffer, bufferOffset, buffer, 0, bytesInBuffer - bufferOffset);
                            bufferOffset = bytesInBuffer - bufferOffset;
                        }
                        else 
                        {
                            bufferOffset = 0;
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Optional: Logging
                    Console.WriteLine($"Client-Fehler: {ex.Message}");
                }
            }
        }

      

        public void Stop()
        {
            _isRunning = false;
            _listener.Stop();
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
