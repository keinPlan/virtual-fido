using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using VFido.Gui.Dialogs;
using VFido.Gui.Services;

namespace VFido.Gui;

public partial class MainWindow : Window
{
    private readonly IStickManager _stickManager;

    private bool _allowClose;

    public MainWindow(IStickManager stickManager)
    {
        _stickManager = stickManager;

        InitializeComponent();
        Opened += async (_, _) => await OnOpenedAsync();
        Closing += MainWindow_Closing;
    }

    /// <summary>
    /// The X button minimizes to the tray instead of exiting, so the running virtual keys
    /// aren't torn down by an accidental close. Only the tray "Exit" menu item goes through
    /// <see cref="ForceClose"/> to actually shut the app down.
    /// </summary>
    private void MainWindow_Closing(object? sender, WindowClosingEventArgs e)
    {
        if (_allowClose)
            return;

        e.Cancel = true;
        Hide();
    }

    public void ForceClose()
    {
        _allowClose = true;
        Close();
    }

    private void TitleBar_PointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            return;
        }

        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            BeginMoveDrag(e);
    }

    private async Task OnOpenedAsync()
    {
        var results = await _stickManager.StartAsync();
        foreach (var result in results)
            await ReportAttachResultAsync(result);
    }

    private async void Attach_Click(object? sender, RoutedEventArgs e)
    {
        var result = await _stickManager.AttachAsync("1-1");
        await ReportAttachResultAsync(result);
    }

    private async Task ReportAttachResultAsync(StickAttachResult result)
    {
        switch (result.Outcome)
        {
            case StickAttachOutcome.Success:
                break;
            case StickAttachOutcome.UnsupportedPlatform:
                StatusText.Text = result.Error;
                break;
            case StickAttachOutcome.Failed:
                await MessageWindow.ShowAsync(this, "VirtualFido", $"Failed to attach device {result.Busid}: {result.Error}");
                break;
        }
    }
}
