using System;
using System.Windows;
using System.Windows.Threading;

namespace VirtualFido.UserPresence
{
    public partial class ApprovalWindow : Window
    {
        private const int TimeoutSeconds = 30;
        private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
        private int _secondsLeft = TimeoutSeconds;

        public ApprovalWindow(string deviceLabel, string operation, string rpId)
        {
            InitializeComponent();

            DeviceText.Text = deviceLabel;
            OperationText.Text = operation;
            RpText.Text = rpId;

            _timer.Tick += (_, _) =>
            {
                _secondsLeft--;
                CountdownText.Text = $"Expires in {_secondsLeft}s";
                if (_secondsLeft <= 0)
                {
                    _timer.Stop();
                    DialogResult = false;
                }
            };
            CountdownText.Text = $"Expires in {_secondsLeft}s";
            _timer.Start();
        }

        private void Approve_Click(object sender, RoutedEventArgs e)
        {
            _timer.Stop();
            DialogResult = true;
        }

        private void Deny_Click(object sender, RoutedEventArgs e)
        {
            _timer.Stop();
            DialogResult = false;
        }
    }
}
