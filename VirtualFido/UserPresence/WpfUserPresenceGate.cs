using System.Windows;
using System.Windows.Threading;
using VFido.Core.Device.Ctap2.Authenticator;

namespace VirtualFido.UserPresence
{
    /// <summary>
    /// Blocks the calling (background) thread until the user approves or denies the request in a
    /// popup, giving multiple attached virtual keys the same "pick by tapping one" behavior real
    /// hardware has.
    /// </summary>
    public sealed class WpfUserPresenceGate : IUserPresenceGate
    {
        private readonly string _deviceLabel;
        private readonly Dispatcher _dispatcher;

        public WpfUserPresenceGate(string deviceLabel, Dispatcher dispatcher)
        {
            _deviceLabel = deviceLabel;
            _dispatcher = dispatcher;
        }

        public bool RequestApproval(string operation, string rpId)
        {
            return _dispatcher.Invoke(() =>
            {
                var window = new ApprovalWindow(_deviceLabel, operation, rpId);
                if (Application.Current?.MainWindow != null && Application.Current.MainWindow.IsLoaded)
                    window.Owner = Application.Current.MainWindow;

                return window.ShowDialog() == true;
            });
        }
    }
}
