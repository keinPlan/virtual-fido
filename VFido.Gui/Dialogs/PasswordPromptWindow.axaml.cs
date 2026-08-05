using Avalonia.Controls;
using Avalonia.Interactivity;

namespace VFido.Gui.Dialogs;

public partial class PasswordPromptWindow : Window
{
    private bool _confirmed;

    public PasswordPromptWindow()
    {
        InitializeComponent();
    }

    public PasswordPromptWindow(string stickName, bool requireUsername, string? prefilledUsername) : this()
    {
        Title = $"Connect \"{stickName}\"";
        PromptText.Text = $"\"{stickName}\" needs credentials to unlock its stored keys.";
        UsernamePanel.IsVisible = requireUsername;
        UsernameBox.Text = prefilledUsername;
    }

    public static async Task<(string Username, string Password)?> ShowAsync(Window owner, string stickName, bool requireUsername, string? prefilledUsername)
    {
        var window = new PasswordPromptWindow(stickName, requireUsername, prefilledUsername);
        await window.ShowDialog(owner);
        return window._confirmed ? (window.UsernameBox.Text ?? string.Empty, window.PasswordBox.Text ?? string.Empty) : null;
    }

    private void Connect_Click(object? sender, RoutedEventArgs e)
    {
        _confirmed = true;
        Close();
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e) => Close();
}
