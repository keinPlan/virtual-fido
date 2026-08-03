using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using VFido.Gui.Configuration;
using VFido.SecretManager.FileBasedSecretStore;

namespace VFido.Gui.Dialogs;

public partial class AddStickWindow : Window
{
    private IStickConfigStore? _configStore;
    private StickConfig? _existing;
    private StickConfig? _result;

    public AddStickWindow()
    {
        InitializeComponent();
        SerialNumberBox.Text = "VFIDO-" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        SecretManagerTypeBox.SelectedIndex = 0;
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
    public static async Task<StickConfig?> EditAsync(Window owner, IStickConfigStore configStore, StickConfig existing)
    {
        var window = new AddStickWindow
        {
            _configStore = configStore,
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

        await window.ShowDialog(owner);
        return window._result;
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

    private void Create_Click(object? sender, RoutedEventArgs e)
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
                if (string.IsNullOrWhiteSpace(MtlsUsernameBox.Text) || string.IsNullOrWhiteSpace(MtlsClientCertPathBox.Text) || string.IsNullOrWhiteSpace(MtlsServerCaCertPathBox.Text))
                {
                    ShowError("Username, client certificate and server CA certificate are required.");
                    return;
                }
                secretManager = new MtlsSecretManagerConfig
                {
                    ServerBaseAddress = serverAddress,
                    Username = MtlsUsernameBox.Text,
                    ClientCertificatePath = MtlsClientCertPathBox.Text,
                    ClientCertificatePassword = string.IsNullOrEmpty(MtlsClientCertPasswordBox.Text) ? null : MtlsClientCertPasswordBox.Text,
                    ServerCaCertificatePath = MtlsServerCaCertPathBox.Text,
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
                _ = new FileBasedSecretStore(_configStore.GetKeyStoreDirectory(_result.Name), FileUsernameBox.Text!, filePassword);
                _ = new FileBasedCredentialStore(_configStore.GetCredentialStoreDirectory(_result.Name), FileUsernameBox.Text!, filePassword);
            }
        }
        catch (Exception ex)
        {
            ShowError($"Failed to save stick config: {ex.Message}");
            return;
        }

        Close();
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.IsVisible = true;
    }
}
