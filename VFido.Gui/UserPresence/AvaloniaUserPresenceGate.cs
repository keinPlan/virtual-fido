using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using VFido.Core.Device.Ctap2.Authenticator;

namespace VFido.Gui.UserPresence;

/// <summary>
/// Blocks the calling (background) thread until the user approves or denies the request in a
/// popup, giving multiple attached virtual keys the same "pick by tapping one" behavior real
/// hardware has.
/// </summary>
public sealed class AvaloniaUserPresenceGate : IUserPresenceGate
{
    private readonly string _deviceLabel;

    public AvaloniaUserPresenceGate(string deviceLabel)
    {
        _deviceLabel = deviceLabel;
    }

    public bool RequestApproval(string operation, string rpId)
    {
        return Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var window = new ApprovalWindow(_deviceLabel, operation, rpId);

            // A dialog owned by a *hidden* window (e.g. the main window minimized to the tray)
            // is not reliably surfaced/activated by the OS - the owner isn't part of the visible
            // z-order, so the popup can end up created but never actually shown/focused, hanging
            // this call forever and, from Windows' side, timing out the whole CTAP2 exchange
            // (which looks like the native "Create a PIN" dialog endlessly looping). Only parent
            // to the main window when it's actually visible; otherwise show the approval popup as
            // its own independent, topmost, activated window instead.
            var owner = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
            if (owner is { IsVisible: true })
                return await window.ShowDialog<bool>(owner);

            return await ShowStandaloneAsync(window);
        }).GetAwaiter().GetResult();
    }

    private static Task<bool> ShowStandaloneAsync(ApprovalWindow window)
    {
        var tcs = new TaskCompletionSource<bool>();
        window.Closed += (_, _) => tcs.TrySetResult(window.Result);
        window.Show();
        window.Activate();
        return tcs.Task;
    }
}
