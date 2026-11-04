using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Avalonia.Platform.Storage;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using VFido.Gui.Configuration;
using VFido.Gui.Services;
using VFido.SecretManager;

namespace VFido.Gui.Dialogs;

/// <summary>Credential management and explicit certificate-encrypted backup actions.</summary>
public partial class CredentialsWindow : Window
{
    private IStickManager? _stickManager;
    private StickConfig? _stick;
    private readonly List<(byte[] Id, CheckBox Selection)> _selections = new();
    private bool _transferBusy;

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
        _selections.Clear();
        var supportsExport = _stickManager!.SupportsPasskeyBackup(_stick!.Name);
        var supportsImport = _stickManager.SupportsPasskeyImport(_stick.Name);
        ExportButton.IsEnabled = supportsExport;
        ImportButton.IsEnabled = supportsImport;
        TransferHint.Text = supportsExport
            ? "Encrypted VirtualFido backup: export with a public CER; restore with its private PFX. Keep the PFX and password safe."
            : supportsImport
                ? "Passkey import is available. TPM private keys cannot be exported. To recover this stick, keep its master recovery PFX, stick folder, and metadata password."
                : "This backend does not support passkey backup or import.";
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
            Text = $"{(credential.IsResident ? "Resident" : "Non-resident")}  Â·  sign count {credential.SignCount}  Â·  credProtect {credential.CredProtect}",
            Foreground = Brushes.Gray,
            FontSize = 11,
        });

        var deleteButton = new Button { Content = "Delete" };
        deleteButton.Click += async (_, _) => await DeleteCredentialAsync(credential);

        var selection = new CheckBox { IsChecked = true, IsVisible = ExportButton.IsEnabled, VerticalAlignment = VerticalAlignment.Center };
        _selections.Add((credential.CredentialId, selection));
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto") };
        Grid.SetColumn(selection, 0);
        grid.Children.Add(selection);
        Grid.SetColumn(infoPanel, 1);
        Grid.SetColumn(deleteButton, 2);
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

    private async void CreateTransferCertificate_Click(object? sender, RoutedEventArgs e) =>
        await RunTransferActionAsync(CreateTransferCertificateAsync);

    private async void ExportPasskeys_Click(object? sender, RoutedEventArgs e) =>
        await RunTransferActionAsync(ExportPasskeysAsync);

    private async void ImportPasskeys_Click(object? sender, RoutedEventArgs e) =>
        await RunTransferActionAsync(ImportPasskeysAsync);

    private async Task RunTransferActionAsync(Func<Task> action)
    {
        if (_transferBusy) return;
        _transferBusy = true;
        TransferActions.IsEnabled = CredentialListPanel.IsEnabled = false;
        try { await action(); }
        catch (Exception ex)
        {
            await MessageWindow.ShowAsync(this, "Passkey backup", ex is CryptographicException
                ? "Unable to unlock the private key or decrypt the backup. Check the PFX password, recipient certificate, and file integrity."
                : ex.Message);
        }
        finally
        {
            _transferBusy = false;
            TransferActions.IsEnabled = CredentialListPanel.IsEnabled = true;
        }
    }

    private async Task CreateTransferCertificateAsync()
    {
        var password = await TransferPasswordWindow.ShowAsync(this, creating: true);
        if (password == null) return;
        var pfx = await SaveFileAsync("Save private key (keep private)", "transfer-private.pfx", "pfx");
        if (pfx == null) return;
        var cer = await SaveFileAsync("Save public recipient certificate", "transfer-public.cer", "cer");
        if (cer == null) return;
        if (SameFile(pfx, cer)) throw new InvalidOperationException("Choose separate files for the public certificate and private key.");
        var identity = await Task.Run(() => PasskeyBackup.CreateIdentity(password));
        try
        {
            await WriteFileAsync(pfx, identity.PasswordProtectedPfx);
            await WriteFileAsync(cer, identity.Certificate);
            await MessageWindow.ShowAsync(this, "Transfer certificate created",
                $"Saved the public CER and password-protected private PFX. Share only the CER.\n\nSHA-256 fingerprint:\n{identity.Fingerprint}");
        }
        finally { CryptographicOperations.ZeroMemory(identity.PasswordProtectedPfx); }
    }

    private async Task ExportPasskeysAsync()
    {
        var ids = _selections.Where(s => s.Selection.IsChecked == true).Select(s => s.Id).ToList();
        if (ids.Count == 0) throw new InvalidOperationException("Select at least one passkey to export.");
        var file = await OpenFileAsync("Select recipient public certificate", "cer", "crt");
        if (file == null) return;
        using var certificate = new X509Certificate2(await ReadFileAsync(file, 1024 * 1024));
        PasskeyBackup.ValidateRecipient(certificate);
        if (!await ConfirmWindow.ShowAsync(this, "Export passkeys",
            $"Encrypt {ids.Count} selected passkey(s) for this certificate? Verify its fingerprint with the recipient.\n\nSHA-256:\n{PasskeyBackup.Fingerprint(certificate)}\n\nSource passkeys will remain on this stick. Counters are preserved; using multiple restored copies may cause sign-in failures.", confirmText: "Export")) return;
        var destination = await SaveFileAsync("Save encrypted passkey backup", "passkeys.vfidobackup", "vfidobackup");
        if (destination == null) return;
        var backup = await _stickManager!.ExportPasskeysAsync(_stick!.Name, ids, certificate);
        await WriteFileAsync(destination, backup);
        await MessageWindow.ShowAsync(this, "Export complete", $"Exported {ids.Count} passkey(s). Restore using the matching PFX and its password.");
    }

    private async Task ImportPasskeysAsync()
    {
        var source = await OpenFileAsync("Select encrypted VirtualFido backup", "vfidobackup");
        if (source == null) return;
        var privateFile = await OpenFileAsync("Select recipient private key", "pfx", "p12");
        if (privateFile == null) return;
        var password = await TransferPasswordWindow.ShowAsync(this, creating: false);
        if (password == null) return;
        var backup = await ReadFileAsync(source, PasskeyBackup.MaximumFileSize);
        var pfx = await ReadFileAsync(privateFile, 1024 * 1024);
        try
        {
            using var certificate = new X509Certificate2(pfx, password, X509KeyStorageFlags.EphemeralKeySet);
            var preview = await _stickManager!.PreviewPasskeyImportAsync(_stick!.Name, backup, certificate);
            var accounts = string.Join("\n", preview.Credentials.Take(15).Select(c => $"{c.RpId}: {c.UserName}"));
            if (preview.Credentials.Count > 15) accounts += $"\n...and {preview.Credentials.Count - 15} more";
            if (!await ConfirmWindow.ShowAsync(this, "Import passkeys",
                $"Import {preview.Credentials.Count - preview.AlreadyPresent} passkey(s) into \"{_stick!.Name}\"? {preview.AlreadyPresent} identical existing passkey(s) will be skipped.\n\n{accounts}\n\nOld backups and concurrent use of restored copies may cause counter-related sign-in failures.", confirmText: "Import")) return;
            var result = await _stickManager!.ImportPasskeysAsync(_stick!.Name, backup, certificate);
            await RefreshAsync();
            await MessageWindow.ShowAsync(this, "Import complete", $"Imported {result.Imported} passkey(s); skipped {result.Skipped} existing passkey(s).");
        }
        finally { CryptographicOperations.ZeroMemory(pfx); }
    }

    private async Task<IStorageFile?> OpenFileAsync(string title, params string[] extensions)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title, AllowMultiple = false,
            FileTypeFilter = new[] { new FilePickerFileType(title) { Patterns = extensions.Select(e => "*." + e).ToArray() } },
        });
        return files.FirstOrDefault();
    }

    private Task<IStorageFile?> SaveFileAsync(string title, string filename, string extension) =>
        StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title, SuggestedFileName = filename, DefaultExtension = extension, ShowOverwritePrompt = true,
            FileTypeChoices = new[] { new FilePickerFileType(title) { Patterns = new[] { "*." + extension } } },
        });

    private static async Task<byte[]> ReadFileAsync(IStorageFile file, int maximumSize)
    {
        await using var stream = await file.OpenReadAsync();
        using var result = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(buffer)) != 0)
        {
            if (result.Length + read > maximumSize) throw new InvalidDataException("The selected file exceeds the size limit.");
            await result.WriteAsync(buffer.AsMemory(0, read));
        }
        return result.ToArray();
    }

    private static bool SameFile(IStorageFile first, IStorageFile second)
    {
        var firstPath = first.TryGetLocalPath();
        var secondPath = second.TryGetLocalPath();
        if (firstPath != null && secondPath != null)
            return string.Equals(Path.GetFullPath(firstPath), Path.GetFullPath(secondPath),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        return first.Path == second.Path;
    }

    private static async Task WriteFileAsync(IStorageFile file, byte[] data)
    {
        await using var stream = await file.OpenWriteAsync();
        stream.SetLength(0);
        await stream.WriteAsync(data);
        await stream.FlushAsync();
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();
}
