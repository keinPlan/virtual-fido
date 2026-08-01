using System;
using System.Buffers.Binary;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using VFido.Core;
using VFido.Core.Device;
using VFido.Core.Device.UsbTypes;
using VFido.Core.Device.UsbTypes;
using VFido.Core.Protocol;
using VFido.Core.Vhci;
using VirtualFido.UserPresence;
namespace VirtualFido
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            // "172.19.224.1"
            const string host = "127.0.0.1";
            const int port = 3240;
            UsbIpServer server = new UsbIpServer(host, port);
            var vhci = new VhciAttacher();

            var devices = new List<FidoUsbStick>();
            foreach (var deviceId in new[] { 0x00010001,/* 0x00010002, 0x00010003, 0x00010004 */})
            {
                var gate = new WpfUserPresenceGate($"VFIDO-{deviceId:X8}", Dispatcher);
                var device = new FidoUsbStick(deviceId, gate);
                server.VirtualUsbDevices.Add(deviceId, device);
                devices.Add(device);
            }

            server.Start();

            foreach (var device in devices)
            {
                var busid = $"{device.DeviceBusNum}-{device.DeviceBusID}";
                if (!vhci.TryAttach(host, port.ToString(), busid, out _, out var error))
                    MessageBox.Show($"Failed to attach device {busid}: {error}", "VirtualFido", MessageBoxButton.OK, MessageBoxImage.Warning);
            }



        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var vhci = new VhciAttacher();
            var busid = "1-1";
            var host = "127.0.0.1";
            var port = 3240;
            if (!vhci.TryAttach(host, port.ToString(), busid, out _, out var error))
                MessageBox.Show($"Failed to attach device {busid}: {error}", "VirtualFido", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}