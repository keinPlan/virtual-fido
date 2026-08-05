using System.Security.Cryptography.X509Certificates;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using VFido.Gui.Configuration;
using VFido.Gui.Services;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreClient;

namespace VFido.Gui.Dialogs;

public partial class AddStickWindow : Window
{
    private IStickConfigStore? _configStore;
    private IStickManager? _stickManager;
    private StickConfig? _existing;
    private StickConfig? _result;

    /// <summary>Set once the stick has been deleted, so the caller knows to refresh even though <see cref="_result"/> is null.</summary>
    public bool Deleted { get; private set; }

    public AddStickWindow()
    {
        InitializeComponent();
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
        window.CreateButton.Content = "Save";
        window.DeleteButton.IsVisible = true;

        await window.ShowDialog(owner);
        return (window._result, window.Deleted);
    }

    private void SecretManagerType_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (FilePanel == null || MtlsPanel == null)
            return;

        FilePanel.IsVisible = SecretManagerTypeBox.SelectedIndex == 1;
        MtlsPanel.IsVisible = SecretManagerTypeBox.SelectedIndex == 2;
    }

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
                if (string.IsNullOrWhiteSpace(MtlsUsernameBox.Text) || string.IsNullOrEmpty(MtlsLoginPasswordBox.Text)
                    || string.IsNullOrWhiteSpace(MtlsClientCertPathBox.Text) || string.IsNullOrWhiteSpace(MtlsServerCaCertPathBox.Text))
                {
                    ShowError("Username, login password, client certificate and server CA certificate are required.");
                    return;
                }

                mtlsClientCertSourcePath = MtlsClientCertPathBox.Text;
                mtlsServerCaCertSourcePath = MtlsServerCaCertPathBox.Text;
                var mtlsClientCertPassword = string.IsNullOrEmpty(MtlsClientCertPasswordBox.Text) ? null : MtlsClientCertPasswordBox.Text;

                CreateButton.IsEnabled = false;
                ErrorText.IsVisible = false;
                try
                {
                    // Tested against the originally picked paths, before anything is copied or
                    // persisted - a bad cert/password/unreachable server leaves the dialog exactly
                    // as the user left it, with nothing created.
                    await TestMtlsConnectionAsync(serverAddress, MtlsLoginPasswordBox.Text!,
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
                    Username = MtlsUsernameBox.Text,
                    ClientCertificatePath = "certs/client.pfx",
                    ClientCertificatePassword = mtlsClientCertPassword,
                    ServerCaCertificatePath = "certs/ca.crt",
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
    private static async Task TestMtlsConnectionAsync(Uri serverAddress, string password, string clientCertPath, string? clientCertPassword, string serverCaCertPath)
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

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.IsVisible = true;
    }
}
