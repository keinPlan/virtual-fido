using Avalonia.Controls;
using Avalonia.Interactivity;

namespace VFido.Gui.Dialogs;

public partial class MessageWindow : Window
{
    public MessageWindow()
    {
        InitializeComponent();
    }

    public MessageWindow(string title, string message) : this()
    {
        Title = title;
        MessageText.Text = message;
    }

    public static Task ShowAsync(Window owner, string title, string message) =>
        new MessageWindow(title, message).ShowDialog(owner);

    private void Ok_Click(object? sender, RoutedEventArgs e) => Close();
}
