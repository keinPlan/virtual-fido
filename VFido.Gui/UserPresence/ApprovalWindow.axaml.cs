using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace VFido.Gui.UserPresence;

public partial class ApprovalWindow : Window
{
    private const int TimeoutSeconds = 30;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private int _secondsLeft = TimeoutSeconds;
    private bool _resultSet;

    public bool Result { get; private set; }

    public ApprovalWindow()
    {
        InitializeComponent();
        PointerPressed += (_, e) =>
        {
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
                BeginMoveDrag(e);
        };
    }

    public ApprovalWindow(string deviceLabel, string operation, string rpId) : this()
    {
        DeviceText.Text = deviceLabel;
        OperationText.Text = operation;
        RpText.Text = rpId;

        CountdownBar.Maximum = TimeoutSeconds;
        CountdownBar.Value = _secondsLeft;

        _timer.Tick += (_, _) =>
        {
            _secondsLeft--;
            CountdownBar.Value = _secondsLeft;
            CountdownText.Text = $"Auto-deny in {_secondsLeft}s";
            if (_secondsLeft <= 0)
            {
                _timer.Stop();
                CloseWithResult(false);
            }
        };
        CountdownText.Text = $"Auto-deny in {_secondsLeft}s";
        _timer.Start();
    }

    private void Approve_Click(object? sender, RoutedEventArgs e)
    {
        _timer.Stop();
        CloseWithResult(true);
    }

    private void Deny_Click(object? sender, RoutedEventArgs e)
    {
        _timer.Stop();
        CloseWithResult(false);
    }

    private void CloseWithResult(bool approved)
    {
        if (_resultSet)
            return;

        _resultSet = true;
        Result = approved;
        Close(approved);
    }
}
