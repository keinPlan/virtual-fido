using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using VFido.Gui.Configuration;
using VFido.Gui.Services;
using VFido.SecretManager;

namespace VFido.Gui.Dialogs;

/// <summary>
/// Read-only, metadata-only view of the credentials stored on a connected stick, with the
/// ability to delete a credential. Only ever displays <see cref="CredentialInfo"/> - it never
/// touches a key handle or private key material, so there is nothing sensitive to leak here.
/// </summary>
public partial class CredentialsWindow : Window
{
    private IStickManager? _stickManager;
    private StickConfig? _stick;

    public CredentialsWindow()
    {
        InitializeComponent();
    }

    public static async Task ShowAsync(Window owner, IStickManager stickManager, StickConfig stick)
    {
        var window = new CredentialsWindow
        {
            Title = $"Credentials - {stick.Name}",
            _stickManager = stickManager,
            _stick = stick,
        };
        await window.RefreshAsync();
        await window.ShowDialog(owner);
    }

    private async Task RefreshAsync()
    {
        CredentialListPanel.Children.Clear();

        IReadOnlyList<CredentialInfo> credentials;
        try
        {
            credentials = await _stickManager!.GetCredentialsAsync(_stick!.Name);
        }
        catch (Exception ex)
        {
            SubtitleText.Text = $"Failed to load credentials: {ex.Message}";
            return;
        }

        SubtitleText.Text = credentials.Count == 0
            ? "No credentials stored on this stick yet."
            : $"{credentials.Count} credential(s) stored on this stick.";

        foreach (var credential in credentials)
            CredentialListPanel.Children.Add(BuildCredentialCard(credential));
    }

    private Control BuildCredentialCard(CredentialInfo credential)
    {
        var infoPanel = new StackPanel { Spacing = 2 };
        infoPanel.Children.Add(new TextBlock { Text = credential.RpId, FontWeight = FontWeight.SemiBold });
        infoPanel.Children.Add(new TextBlock
        {
            Text = string.IsNullOrEmpty(credential.UserDisplayName) ? credential.UserName : $"{credential.UserDisplayName} ({credential.UserName})",
            Foreground = Brushes.Gray,
            FontSize = 12,
        });
        infoPanel.Children.Add(new TextBlock
        {
            Text = $"{(credential.IsResident ? "Resident" : "Non-resident")}  ·  sign count {credential.SignCount}  ·  credProtect {credential.CredProtect}",
            Foreground = Brushes.Gray,
            FontSize = 11,
        });

        var deleteButton = new Button { Content = "Delete" };
        deleteButton.Click += async (_, _) => await DeleteCredentialAsync(credential);

        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        Grid.SetColumn(infoPanel, 0);
        Grid.SetColumn(deleteButton, 1);
        infoPanel.VerticalAlignment = VerticalAlignment.Center;
        deleteButton.VerticalAlignment = VerticalAlignment.Center;
        grid.Children.Add(infoPanel);
        grid.Children.Add(deleteButton);

        return new Border
        {
            Padding = new Avalonia.Thickness(12),
            CornerRadius = new Avalonia.CornerRadius(6),
            BorderBrush = Brushes.Gray,
            BorderThickness = new Avalonia.Thickness(1),
            Child = grid,
        };
    }

    private async Task DeleteCredentialAsync(CredentialInfo credential)
    {
        var confirmed = await ConfirmWindow.ShowAsync(
            this,
            "Delete credential",
            $"Delete the credential for \"{credential.RpId}\" ({credential.UserName})? This cannot be undone.");
        if (!confirmed)
            return;

        try
        {
            await _stickManager!.DeleteCredentialAsync(_stick!.Name, credential.CredentialId);
        }
        catch (Exception ex)
        {
            await MessageWindow.ShowAsync(this, "VirtualFido", $"Failed to delete credential: {ex.Message}");
            return;
        }

        await RefreshAsync();
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();
}
