using Avalonia.Controls;
using Avalonia.Interactivity;

namespace VFido.Gui.Dialogs;

public partial class ConfirmWindow : Window
{
    private bool _confirmed;

    public ConfirmWindow()
    {
        InitializeComponent();
    }

    public ConfirmWindow(string title, string message, string confirmText) : this()
    {
        Title = title;
        MessageText.Text = message;
        ConfirmButton.Content = confirmText;
    }

    public static async Task<bool> ShowAsync(Window owner, string title, string message, string confirmText = "Delete")
    {
        var window = new ConfirmWindow(title, message, confirmText);
        await window.ShowDialog(owner);
        return window._confirmed;
    }

    private void Confirm_Click(object? sender, RoutedEventArgs e)
    {
        _confirmed = true;
        Close();
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e) => Close();
}
