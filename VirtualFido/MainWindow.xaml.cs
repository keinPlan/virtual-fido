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

using VirtualFido.UsbIp;
using VirtualFido.UsbIp.Device;
using VirtualFido.UsbIp.Device.UsbTypes;
using VirtualFido.UsbIp.Protocol;

using VirtualFido.UsbIp.Device.UsbTypes;
using System.Buffers.Binary;
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
            UsbIpServer server = new UsbIpServer("127.0.0.1", 3240);

            server.VirtualUsbDevices.Add(0x00010001, new FidoUsbStick(0x00010001));
            server.VirtualUsbDevices.Add(0x00010002, new FidoUsbStick(0x00010002));
            server.VirtualUsbDevices.Add(0x00010003, new FidoUsbStick(0x00010003));
            server.VirtualUsbDevices.Add(0x00010004, new FidoUsbStick(0x00010004));
            server.Start();



        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
        
        }
    }
}