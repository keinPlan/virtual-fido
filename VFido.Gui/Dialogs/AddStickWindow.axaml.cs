using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using VFido.Gui.Configuration;
using VFido.Gui.Services;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreClient;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VFido.Gui.Dialogs;

public partial class AddStickWindow : Window
{
    private IStickConfigStore? _configStore;
    private IStickManager? _stickManager;
    private StickConfig? _existing;
    private StickConfig? _result;
    private bool _busy;

    /// <summary>Set once the stick has been deleted, so the caller knows to refresh even though <see cref="_result"/> is null.</summary>
    public bool Deleted { get; private set; }

    public AddStickWindow()
    {
        InitializeComponent();
        Closing += (_, e) => { if (_busy) e.Cancel = true; };
        Closed += (_, _) => ClearTpmPasswords();
        NameBox.Text = "VFido-FileBased";
        SerialNumberBox.Text = "VFIDO-" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        SecretManagerTypeBox.SelectedIndex = 1;
    }

    public static async Task<StickConfig?> ShowAsync(Window owner, IStickConfigStore configStore)
    {
        var window = new AddStickWindow { _configStore = configStore };
        await window.ShowDialog(owner);
        return window._result;
    }

    /// <summary>
    /// Edit mode only touches SerialNumberIdentifier - Name is fixed at creation time (it's the
    /// stick's folder name) and the secret manager backend is fixed too, to avoid orphaning
    /// already-created key/credential files.
    /// </summary>
    public static async Task<(StickConfig? Result, bool Deleted)> EditAsync(Window owner, IStickConfigStore configStore, IStickManager stickManager, StickConfig existing)
    {
        var window = new AddStickWindow
        {
            _configStore = configStore,
            _stickManager = stickManager,
            _existing = existing,
            Title = "Edit stick",
        };
        window.NameBox.Text = existing.Name;
        window.NameBox.IsEnabled = false; // the name is this stick's folder - not renameable after creation
        window.SerialNumberBox.Text = existing.SerialNumberIdentifier;
        window.SecretManagerSection.IsVisible = false;
        window.FilePanel.IsVisible = false;
        window.MtlsPanel.IsVisible = false;
        window.TpmPanel.IsVisible = existing.SecretManager is TpmSecretManagerConfig;
        window.TpmMetadataPanel.IsVisible = existing.SecretManager is TpmSecretManagerConfig;
        if (existing.SecretManager is TpmSecretManagerConfig tpmSettings)
        {
            window.TpmUsernameBox.Text = tpmSettings.Username;
            window.TpmUsernameBox.IsReadOnly = true;
        }
        window.TpmCreateMasterButton.IsVisible = false;
        window.TpmRestoreButton.IsVisible = existing.SecretManager is TpmSecretManagerConfig;
        window.TpmRestoreButton.IsEnabled = !stickManager.IsConnected(existing.Name);
        window.TpmDeletePrimaryButton.IsVisible = existing.SecretManager is TpmSecretManagerConfig;
        window.TpmProvisionHint.Text = stickManager.IsConnected(existing.Name)
            ? "Disconnect this stick before restoring its master."
            : "After moving this stick folder to another computer or resetting the TPM, select its original recovery PFX to restore access. Existing credentials are checked before the local master is replaced.";
        window.CreateButton.Content = "Save";
        window.DeleteButton.IsVisible = true;

        await window.ShowDialog(owner);
        return (window._result, window.Deleted);
    }

    private void SecretManagerType_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (FilePanel == null || MtlsPanel == null || TpmPanel == null)
            return;

        FilePanel.IsVisible = SecretManagerTypeBox.SelectedIndex == 1;
        MtlsPanel.IsVisible = SecretManagerTypeBox.SelectedIndex == 2;
        TpmPanel.IsVisible = SecretManagerTypeBox.SelectedIndex == 3;
    }

    private async void BrowseTpmPfx_Click(object? sender, RoutedEventArgs e) => await BrowseForCertAsync(TpmPfxPathBox);

    private async void BrowseClientCert_Click(object? sender, RoutedEventArgs e) => await BrowseForCertAsync(MtlsClientCertPathBox);

    private async void BrowseServerCaCert_Click(object? sender, RoutedEventArgs e) => await BrowseForCertAsync(MtlsServerCaCertPathBox);

    private async Task BrowseForCertAsync(TextBox target)
    {
        var storageProvider = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (storageProvider == null)
            return;

        var files = await storageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { AllowMultiple = false });
        if (files.Count > 0 && files[0].TryGetLocalPath() is { } path)
            target.Text = path;
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e) => Close();

    private async void Delete_Click(object? sender, RoutedEventArgs e)
    {
        var confirmed = await ConfirmWindow.ShowAsync(this, "Delete stick",
            $"Delete stick \"{_existing!.Name}\"? Its keys and credentials will be permanently lost. This cannot be undone.");
        if (!confirmed)
            return;

        if (_stickManager!.IsConnected(_existing.Name))
            await _stickManager.DisconnectAsync(_existing.Name);

        try
        {
            _configStore!.Delete(_existing.Name);
        }
        catch (Exception ex)
        {
            ShowError($"Failed to delete stick: {ex.Message}");
            return;
        }

        Deleted = true;
        Close();
    }

    private async void Create_Click(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (_existing == null && !StickConfigStore.IsValidStickName(NameBox.Text))
        {
            ShowError("Name must be 1-32 characters, letters/digits/'.'/'_'/'-' only, no spaces - it also becomes the stick's folder name.");
            return;
        }

        if (_existing != null)
        {
            _existing.SerialNumberIdentifier = SerialNumberBox.Text!;

            try
            {
                _configStore!.Save(_existing);
            }
            catch (Exception ex)
            {
                ShowError($"Failed to save stick config: {ex.Message}");
                return;
            }

            _result = _existing;
            Close();
            return;
        }

        if (SecretManagerTypeBox.SelectedIndex == 3)
        {
            await CreateTpmStickAsync();
            return;
        }

        SecretManagerConfig secretManager;
        string? filePassword = null;
        string? mtlsClientCertSourcePath = null;
        string? mtlsServerCaCertSourcePath = null;

        switch (SecretManagerTypeBox.SelectedIndex)
        {
            case 0:
                secretManager = new MemorySecretManagerConfig();
                break;

            case 1:
                if (string.IsNullOrWhiteSpace(FileUsernameBox.Text) || string.IsNullOrEmpty(FilePasswordBox.Text))
                {
                    ShowError("Username and password are required for a file-based secret manager.");
                    return;
                }
                secretManager = new FileSecretManagerConfig { Username = FileUsernameBox.Text };
                filePassword = FilePasswordBox.Text;
                break;

            case 2:
                if (string.IsNullOrWhiteSpace(MtlsServerAddressBox.Text) || !Uri.TryCreate(MtlsServerAddressBox.Text, UriKind.Absolute, out var serverAddress))
                {
                    ShowError("A valid server base address is required.");
                    return;
                }
                if (string.IsNullOrWhiteSpace(MtlsClientCertPathBox.Text) || string.IsNullOrWhiteSpace(MtlsServerCaCertPathBox.Text))
                {
                    ShowError("Client certificate and server CA certificate are required.");
                    return;
                }

                mtlsClientCertSourcePath = MtlsClientCertPathBox.Text;
                mtlsServerCaCertSourcePath = MtlsServerCaCertPathBox.Text;
                var mtlsClientCertPassword = string.IsNullOrEmpty(MtlsClientCertPasswordBox.Text) ? null : MtlsClientCertPasswordBox.Text;
                // Leave blank for a passwordless server-side identity - the mTLS certificate alone
                // authenticates it, and the server rejects a login attempt outright either way.
                var mtlsLoginPassword = string.IsNullOrEmpty(MtlsLoginPasswordBox.Text) ? null : MtlsLoginPasswordBox.Text;

                CreateButton.IsEnabled = false;
                ErrorText.IsVisible = false;
                try
                {
                    // Tested against the originally picked paths, before anything is copied or
                    // persisted - a bad cert/password/unreachable server leaves the dialog exactly
                    // as the user left it, with nothing created.
                    await TestMtlsConnectionAsync(serverAddress, mtlsLoginPassword,
                        mtlsClientCertSourcePath, mtlsClientCertPassword, mtlsServerCaCertSourcePath);
                }
                catch (Exception ex)
                {
                    ShowError($"Could not connect: {ex.Message}");
                    return;
                }
                finally
                {
                    CreateButton.IsEnabled = true;
                }

                secretManager = new MtlsSecretManagerConfig
                {
                    ServerBaseAddress = serverAddress,
                    ClientCertificatePath = "certs/client.pfx",
                    ClientCertificatePassword = mtlsClientCertPassword,
                    ServerCaCertificatePath = "certs/ca.crt",
                    RequiresLoginPassword = mtlsLoginPassword != null,
                };
                break;

            default:
                ShowError("Select a secret manager.");
                return;
        }

        try
        {
            _result = _configStore!.Create(NameBox.Text!, SerialNumberBox.Text!, secretManager);

            // Eagerly initialize the encrypted store now, while the password is still on screen,
            // instead of waiting for the first Connect - it's never written to config.json either
            // way, so this is purely about not losing the moment the user has it in mind.
            if (filePassword != null)
            {
                _ = new FileBasedSecretStore(_configStore.GetKeyStoreDirectory(_result.Name), FileUsernameBox.Text!, filePassword, _configStore.GetAttestationCertificateDirectory(_result.Name), _configStore.GetStickDirectory(_result.Name));
                _ = new FileBasedCredentialStore(_configStore.GetCredentialStoreDirectory(_result.Name), FileUsernameBox.Text!, filePassword, _configStore.GetStickDirectory(_result.Name));
            }

            // Now that the connection has already been verified against these exact files, copy
            // them into the stick's own folder so it stays self-contained (same as the file-based
            // backend) instead of depending on wherever the originals happen to live on disk.
            if (mtlsClientCertSourcePath != null)
            {
                var certsDirectory = _configStore.GetAttestationCertificateDirectory(_result.Name);
                Directory.CreateDirectory(certsDirectory);
                File.Copy(mtlsClientCertSourcePath, Path.Combine(certsDirectory, "client.pfx"), overwrite: true);
                File.Copy(mtlsServerCaCertSourcePath!, Path.Combine(certsDirectory, "ca.crt"), overwrite: true);
            }
        }
        catch (Exception ex)
        {
            ShowError($"Failed to save stick config: {ex.Message}");
            return;
        }

        Close();
    }

    /// <summary>Exercises cert loading, the TLS handshake/CA trust, and login in one call - <see cref="MtlsBasedSecretStoreClient"/> logs in transparently on its first request.</summary>
    private static async Task TestMtlsConnectionAsync(Uri serverAddress, string? password, string clientCertPath, string? clientCertPassword, string serverCaCertPath)
    {
        using var clientCertificate = new X509Certificate2(clientCertPath, clientCertPassword);
        using var serverCaCertificate = new X509Certificate2(serverCaCertPath);

        using var client = new MtlsBasedSecretStoreClient(new MtlsBasedSecretStoreClientOptions
        {
            ServerBaseAddress = serverAddress,
            ClientCertificate = clientCertificate,
            ServerCaCertificate = serverCaCertificate,
            Password = password,
        });

        var timeout = Task.Delay(TimeSpan.FromSeconds(10));
        var attempt = client.GetAaguidAsync();
        if (await Task.WhenAny(attempt, timeout) == timeout)
            throw new TimeoutException("The server did not respond within 10 seconds.");

        await attempt; // observe/rethrow any failure now that we know it already completed
    }

    private async Task CreateTpmStickAsync()
    {
        if (string.IsNullOrWhiteSpace(TpmUsernameBox.Text) || string.IsNullOrWhiteSpace(TpmMetadataPasswordBox.Text) ||
            string.IsNullOrWhiteSpace(TpmPfxPathBox.Text) || string.IsNullOrWhiteSpace(TpmPfxPasswordBox.Text))
        {
            ShowError("Enter a username, metadata password, master recovery PFX, and its password.");
            return;
        }
        var name = NameBox.Text!;
        var serial = SerialNumberBox.Text ?? string.Empty;
        var username = TpmUsernameBox.Text;
        var metadataPassword = TpmMetadataPasswordBox.Text;
        var pfxPath = TpmPfxPathBox.Text;
        var pfxPassword = TpmPfxPasswordBox.Text;
        SetTpmBusy(true, "Provisioning and testing TPM signing...");
        try
        {
            _result = await Task.Run(() => TpmStickProvisioning.Create(_configStore!, name, serial, username, metadataPassword, pfxPath, pfxPassword));
        }
        catch (Exception ex) { ShowError($"TPM setup failed: {ex.Message}"); }
        finally { SetTpmBusy(false); }
        if (_result != null) Close();
    }

    private async void CreateTpmMaster_Click(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var password = await TransferPasswordWindow.ShowAsync(this, creating: true, masterRecovery: true);
        if (password == null) return;
        var destination = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save TPM master recovery PFX", SuggestedFileName = "vfido-tpm-recovery.pfx", DefaultExtension = "pfx",
            ShowOverwritePrompt = true,
            FileTypeChoices = new[] { new FilePickerFileType("Recovery PFX") { Patterns = new[] { "*.pfx" } } },
        });
        if (destination == null) return;
        if (destination.TryGetLocalPath() is not { } path)
        {
            ShowError("Choose a local path for the recovery PFX.");
            return;
        }
        SetTpmBusy(true, "Creating encrypted recovery PFX...");
        try
        {
            await Task.Run(() =>
            {
                using var master = TpmMasterKey.Generate();
                var pfx = master.ExportPfx(password);
                try
                {
                    // Never overwrite another master recovery package.
                    using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    stream.Write(pfx);
                    stream.Flush(flushToDisk: true);
                }
                finally { CryptographicOperations.ZeroMemory(pfx); }
            });
            TpmPfxPathBox.Text = path;
            TpmPfxPasswordBox.Text = password;
        }
        catch (Exception ex) { ShowError($"Could not create recovery PFX: {ex.Message}"); }
        finally { SetTpmBusy(false); }
    }

    private async void RestoreTpmMaster_Click(object? sender, RoutedEventArgs e)
    {
        if (_busy || _existing == null) return;
        if (_stickManager!.IsConnected(_existing.Name))
        {
            ShowError("Disconnect this stick before restoring its master.");
            return;
        }
        if (string.IsNullOrWhiteSpace(TpmPfxPathBox.Text) || string.IsNullOrWhiteSpace(TpmPfxPasswordBox.Text))
        {
            ShowError("Select this stick's original recovery PFX and enter its password.");
            return;
        }
        if (string.IsNullOrWhiteSpace(TpmMetadataPasswordBox.Text))
        {
            ShowError("Enter your original metadata password to protect the restored master.");
            return;
        }
        var path = TpmPfxPathBox.Text;
        var password = TpmPfxPasswordBox.Text;
        var metadataPassword = TpmMetadataPasswordBox.Text;
        SetTpmBusy(true, "Restoring master and checking existing credentials...");
        try
        {
            await Task.Run(() => TpmStickProvisioning.Restore(_configStore!, _existing, path, password, metadataPassword));
            ClearTpmPasswords();
            TpmProvisionHint.Text = "Master restored. Connect using your original metadata username and password.";
        }
        catch (Exception ex) { ShowError($"TPM recovery failed: {ex.Message}"); }
        finally { SetTpmBusy(false); }
    }

    private async void DeleteTpmPrimary_Click(object? sender, RoutedEventArgs e)
    {
        if (_busy || _existing == null) return;
        if (_stickManager!.GetConfiguredSticks().Any(stick =>
            stick.SecretManager is TpmSecretManagerConfig && _stickManager.IsConnected(stick.Name)))
        {
            ShowError("Disconnect all TPM sticks before deleting the shared primary cache.");
            return;
        }
        var confirmed = await ConfirmWindow.ShowAsync(this, "Delete cached TPM primary",
            "Delete the shared TPM primary at 0x81015646? Credential files remain intact. " +
            "Other VFido TPM stores share this cache. The next connection can recreate the same primary " +
            "and may be slow. This does not revoke existing credentials or backups.");
        if (!confirmed) return;
        SetTpmBusy(true, "Deleting cached TPM primary...");
        try
        {
            await Task.Run(() => TpmBasedSecretStore.DeleteCachedPrimary(_configStore!.GetKeyStoreDirectory(_existing.Name)));
            TpmProvisionHint.Text = "Cached primary deleted. The next connection will recreate it and may be slow.";
        }
        catch (Exception ex)
        {
            ShowError($"Could not delete cached TPM primary: {ex.Message}. Windows may require administrator rights and TPM owner authorization.");
        }
        finally { SetTpmBusy(false); }
    }

    private void SetTpmBusy(bool busy, string message = "")
    {
        _busy = busy;
        ((Control)Content!).IsEnabled = !busy;
        ProgressText.Text = message;
        ProgressText.IsVisible = busy;
        if (busy) ErrorText.IsVisible = false;
    }

    private void ClearTpmPasswords()
    {
        TpmPfxPasswordBox.Text = string.Empty;
        TpmMetadataPasswordBox.Text = string.Empty;
    }
    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.IsVisible = true;
    }
}
