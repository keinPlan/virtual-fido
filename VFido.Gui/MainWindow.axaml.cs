using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using VFido.Gui.Configuration;
using VFido.Gui.Dialogs;
using VFido.Gui.Services;

namespace VFido.Gui;

public partial class MainWindow : Window
{
    private readonly IStickManager _stickManager;
    private readonly IStickConfigStore _configStore;
    private readonly Dictionary<string, string> _pendingOperations = new();

    private bool _allowClose;

    public MainWindow(IStickManager stickManager, IStickConfigStore configStore)
    {
        _stickManager = stickManager;
        _configStore = configStore;

        InitializeComponent();
        Opened += (_, _) => RefreshStickList();
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

    private void RefreshStickList()
    {
        StickListPanel.Children.Clear();

        var sticks = _stickManager.GetConfiguredSticks();
        if (sticks.Count == 0)
        {
            StickListPanel.Children.Add(new TextBlock
            {
                Text = "No sticks configured yet. Click \"+ Add stick\" to create one.",
                Foreground = Brushes.Gray,
            });
            return;
        }

        foreach (var stick in sticks)
            StickListPanel.Children.Add(BuildStickCard(stick));
    }

    private Control BuildStickCard(StickConfig stick)
    {
        var connected = _stickManager.IsConnected(stick.Name);
        var busy = _pendingOperations.TryGetValue(stick.Name, out var operation);

        var statusDot = new Avalonia.Controls.Shapes.Ellipse
        {
            Width = 10,
            Height = 10,
            Fill = connected ? Brushes.LimeGreen : Brushes.DimGray,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Avalonia.Thickness(0, 0, 8, 0),
        };

        var namePanel = new StackPanel { Orientation = Orientation.Horizontal };
        namePanel.Children.Add(statusDot);
        namePanel.Children.Add(new TextBlock { Text = stick.Name, FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center });

        var infoPanel = new StackPanel { Spacing = 2 };
        infoPanel.Children.Add(namePanel);
        infoPanel.Children.Add(new TextBlock
        {
            Text = $"{stick.SerialNumberIdentifier}  ·  {stick.SecretManager.GetType().Name.Replace("SecretManagerConfig", string.Empty)}  ·  {(busy ? operation : connected ? "Connected" : "Disconnected")}",
            Foreground = Brushes.Gray,
            FontSize = 12,
        });

        if (busy)
        {
            infoPanel.Children.Add(new ProgressBar
            {
                IsIndeterminate = true,
                Height = 4,
                Margin = new Avalonia.Thickness(0, 6, 12, 0),
                HorizontalAlignment = HorizontalAlignment.Stretch,
            });
            infoPanel.Children.Add(new TextBlock
            {
                Text = "Please wait. This can take a while.",
                Foreground = Brushes.Gray,
                FontSize = 12,
            });
        }

        var editButton = new Button { Content = "Edit", Margin = new Avalonia.Thickness(0, 0, 8, 0), IsEnabled = !busy };
        editButton.Click += async (_, _) => await EditStickAsync(stick);

        var credentialsButton = new Button { Content = "Credentials", Margin = new Avalonia.Thickness(0, 0, 8, 0), IsEnabled = connected && !busy };
        credentialsButton.Click += async (_, _) => await CredentialsWindow.ShowAsync(this, _stickManager, stick);

        var connectButton = new Button { Content = busy ? operation : connected ? "Disconnect" : "Connect", MinWidth = 100, IsEnabled = !busy };
        connectButton.Click += async (_, _) => await ToggleConnectAsync(stick, connected);

        var buttonsPanel = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        buttonsPanel.Children.Add(editButton);
        buttonsPanel.Children.Add(credentialsButton);
        buttonsPanel.Children.Add(connectButton);

        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        Grid.SetColumn(infoPanel, 0);
        Grid.SetColumn(buttonsPanel, 1);
        grid.Children.Add(infoPanel);
        grid.Children.Add(buttonsPanel);

        return new Border
        {
            Padding = new Avalonia.Thickness(12),
            CornerRadius = new Avalonia.CornerRadius(6),
            BorderBrush = Brushes.Gray,
            BorderThickness = new Avalonia.Thickness(1),
            Child = grid,
        };
    }

    private async void AddStick_Click(object? sender, RoutedEventArgs e)
    {
        var created = await AddStickWindow.ShowAsync(this, _configStore);
        if (created != null)
            RefreshStickList();
    }

    private async Task EditStickAsync(StickConfig stick)
    {
        var (edited, deleted) = await AddStickWindow.EditAsync(this, _configStore, _stickManager, stick);
        if (edited != null || deleted)
            RefreshStickList();
    }

    private async Task ToggleConnectAsync(StickConfig stick, bool wasConnected)
    {
        if (!_pendingOperations.TryAdd(stick.Name, wasConnected ? "Disconnecting..." : "Connecting...")) return;
        RefreshStickList();
        StickAttachResult result;
        try
        {
            result = wasConnected
                ? await _stickManager.DisconnectAsync(stick.Name)
                : await _stickManager.ConnectAsync(stick.Name);
        }
        catch (Exception ex)
        {
            result = new StickAttachResult(StickAttachOutcome.Failed, string.Empty, ex.Message);
        }
        finally
        {
            _pendingOperations.Remove(stick.Name);
            RefreshStickList();
        }

        await ReportAttachResultAsync(result);
    }

    private async Task ReportAttachResultAsync(StickAttachResult result)
    {
        switch (result.Outcome)
        {
            case StickAttachOutcome.Success:
            case StickAttachOutcome.Cancelled:
                break;
            case StickAttachOutcome.UnsupportedPlatform:
            case StickAttachOutcome.Failed:
                await MessageWindow.ShowAsync(this, "VirtualFido", result.Error ?? "The operation failed.");
                break;
        }
    }
}
