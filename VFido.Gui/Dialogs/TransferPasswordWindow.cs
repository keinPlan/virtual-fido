using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace VFido.Gui.Dialogs;

internal sealed class TransferPasswordWindow : Window
{
    private TransferPasswordWindow() { }

    public static Task<string?> ShowAsync(Window owner, bool creating, bool masterRecovery = false)
    {
        var window = new TransferPasswordWindow
        {
            Title = masterRecovery ? "Protect TPM recovery master" : creating ? "Protect transfer private key" : "Unlock transfer private key",
            Width = 440, SizeToContent = SizeToContent.Height, CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false,
        };
        var password = new TextBox { PasswordChar = '*', Watermark = "PFX password" };
        var confirmation = new TextBox { PasswordChar = '*', Watermark = "Repeat password", IsVisible = creating };
        var error = new TextBlock { Foreground = Brushes.Red, TextWrapping = TextWrapping.Wrap };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        var accept = new Button { Content = creating ? "Create" : "Unlock", IsDefault = true };
        cancel.Click += (_, _) => window.Close(null);
        accept.Click += (_, _) =>
        {
            if (creating && (string.IsNullOrWhiteSpace(password.Text) || password.Text != confirmation.Text))
            {
                error.Text = "Enter a non-empty password and repeat it exactly.";
                return;
            }
            var result = password.Text ?? string.Empty;
            password.Text = confirmation.Text = string.Empty;
            window.Close(result);
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Spacing = 8 };
        buttons.Children.Add(cancel);
        buttons.Children.Add(accept);
        var panel = new StackPanel { Margin = new Thickness(20), Spacing = 12 };
        panel.Children.Add(new TextBlock
        {
            Text = masterRecovery
                ? "Save the recovery PFX privately and keep its password. It protects every credential under this master. Keep a separate backup of the stick folder and its metadata password."
                : creating
                ? "Save the PFX privately and keep its password. Both are required to restore backups. Share only the public CER file."
                : "Enter the password for the PFX file containing the recipient's private key.",
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(password);
        panel.Children.Add(confirmation);
        panel.Children.Add(error);
        panel.Children.Add(buttons);
        window.Content = panel;
        return window.ShowDialog<string?>(owner);
    }
}
