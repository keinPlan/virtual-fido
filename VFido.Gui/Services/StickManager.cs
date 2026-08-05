using System.Security.Cryptography.X509Certificates;
using NLog;
using VFido.Core;
using VFido.Core.Device;
using VFido.Core.Vhci;
using VFido.Gui.Configuration;
using VFido.Gui.UserPresence;
using VFido.SecretManager;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MemoryBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreClient;

namespace VFido.Gui.Services;

public sealed class StickManager : IStickManager
{
    private const string UnsupportedPlatformMessage =
        "Automatic device attach is only supported on Windows for now. Use a platform-specific usbip client to attach manually.";

    private const string Host = "127.0.0.1";
    private const int Port = 3240;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private readonly IStickConfigStore _configStore;
    private readonly ICredentialPrompt _credentialPrompt;
    private readonly UsbIpServer _server = new(Host, Port);
    private readonly Dictionary<string, ConnectedStick> _connected = new();

    private bool _serverStarted;
    private int _nextDeviceSlot = 1;

    public StickManager(IStickConfigStore configStore, ICredentialPrompt credentialPrompt)
    {
        _configStore = configStore;
        _credentialPrompt = credentialPrompt;
    }

    public IReadOnlyList<StickConfig> GetConfiguredSticks() => _configStore.LoadAll();

    public bool IsConnected(string stickName) => _connected.ContainsKey(stickName);

    public async Task<StickAttachResult> ConnectAsync(string stickName)
    {
        if (_connected.ContainsKey(stickName))
            return new StickAttachResult(StickAttachOutcome.Success, string.Empty, null);

        // Only one stick may be attached at a time - connecting a new one disconnects whatever
        // else is currently attached first, so the host never sees more than one virtual key.
        foreach (var otherStickName in _connected.Keys.Where(name => name != stickName).ToList())
            await DisconnectAsync(otherStickName);

        var config = _configStore.LoadAll().FirstOrDefault(c => c.Name == stickName);
        if (config == null)
            return new StickAttachResult(StickAttachOutcome.Failed, string.Empty, $"No stored config for stick {stickName}.");

        IFido2SecretManager secretManager;
        try
        {
            var built = await BuildSecretManagerAsync(config);
            if (built == null)
                return new StickAttachResult(StickAttachOutcome.Cancelled, string.Empty, null);

            secretManager = built;
        }
        catch (Exception ex)
        {
            Logger.Warn(ex, () => $"Failed to build secret manager for stick {stickName}: {ex.Message}");
            return new StickAttachResult(StickAttachOutcome.Failed, string.Empty, ex.Message);
        }

        var aaguid = await secretManager.GetAaguidAsync();

        var deviceId = (0x0001 << 16) | _nextDeviceSlot++;
        var device = new FidoUsbStick(
            deviceId,
            config.SerialNumberIdentifier,
            aaguid,
            new AvaloniaUserPresenceGate(config.Name),
            secretManager);

        _server.VirtualUsbDevices.Add(deviceId, device);

        if (!_serverStarted)
        {
            _server.Start();
            _serverStarted = true;
        }

        var busid = $"{device.DeviceBusNum}-{device.DeviceBusID}";
        var result = await AttachAsync(busid);

        if (!result.Success)
        {
            _server.VirtualUsbDevices.Remove(deviceId);
            (secretManager as IDisposable)?.Dispose();
            return result;
        }

        _connected[stickName] = new ConnectedStick(device, deviceId, result.Port, secretManager);
        return result;
    }

    public Task<StickAttachResult> DisconnectAsync(string stickName)
    {
        if (!_connected.TryGetValue(stickName, out var connectedStick))
            return Task.FromResult(new StickAttachResult(StickAttachOutcome.Success, string.Empty, null));

        var vhci = new VhciAttacher();
        var busid = $"{connectedStick.Device.DeviceBusNum}-{connectedStick.Device.DeviceBusID}";

        StickAttachResult result;
        if (connectedStick.Port is { } port && !vhci.TryDetach(port, out var error))
        {
            Logger.Warn($"Failed to detach busid={busid} port={port}: {error}");
            result = new StickAttachResult(StickAttachOutcome.Failed, busid, error);
        }
        else
        {
            result = new StickAttachResult(StickAttachOutcome.Success, busid, null);
        }

        _server.VirtualUsbDevices.Remove(connectedStick.DeviceId);
        (connectedStick.SecretManager as IDisposable)?.Dispose();
        _connected.Remove(stickName);

        return Task.FromResult(result);
    }

    public Task<IReadOnlyList<CredentialInfo>> GetCredentialsAsync(string stickName) =>
        RequireConnected(stickName).SecretManager.FindAllCredentialsAsync();

    public Task DeleteCredentialAsync(string stickName, byte[] credentialId) =>
        RequireConnected(stickName).SecretManager.DeleteCredentialAsync(credentialId);

    private ConnectedStick RequireConnected(string stickName) =>
        _connected.TryGetValue(stickName, out var connectedStick)
            ? connectedStick
            : throw new InvalidOperationException($"Stick {stickName} is not connected.");

    private async Task<IFido2SecretManager?> BuildSecretManagerAsync(StickConfig config)
    {
        switch (config.SecretManager)
        {
            case MemorySecretManagerConfig:
                return new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore());

            case FileSecretManagerConfig fileConfig:
            {
                var credentials = await _credentialPrompt.RequestCredentialsAsync(config.Name, fileConfig.Username);
                if (credentials == null)
                    return null;

                var (username, password) = credentials.Value;
                // FileBasedSecretStore also implements IPinStateStore, persisting the PIN hash and
                // retry counter alongside the signing keys it already protects in the same directory -
                // Fido2SecretManager detects and forwards to it automatically.
                var keyStore = new SecretManager.FileBasedSecretStore.FileBasedSecretStore(_configStore.GetKeyStoreDirectory(config.Name), username, password, _configStore.GetAttestationCertificateDirectory(config.Name), _configStore.GetStickDirectory(config.Name));
                var credentialStore = new FileBasedCredentialStore(_configStore.GetCredentialStoreDirectory(config.Name), username, password, _configStore.GetStickDirectory(config.Name));
                return new Fido2SecretManager(keyStore, credentialStore);
            }

            case MtlsSecretManagerConfig mtlsConfig:
            {
                var credentials = await _credentialPrompt.RequestCredentialsAsync(config.Name, mtlsConfig.Username);
                if (credentials == null)
                    return null;

                var (username, password) = credentials.Value;
                var stickDirectory = _configStore.GetStickDirectory(config.Name);
                var clientCertificate = new X509Certificate2(
                    ResolvePath(stickDirectory, mtlsConfig.ClientCertificatePath), mtlsConfig.ClientCertificatePassword);
                var serverCaCertificate = new X509Certificate2(ResolvePath(stickDirectory, mtlsConfig.ServerCaCertificatePath));

                return new MtlsBasedSecretStoreClient(new MtlsBasedSecretStoreClientOptions
                {
                    ServerBaseAddress = mtlsConfig.ServerBaseAddress,
                    ClientCertificate = clientCertificate,
                    ServerCaCertificate = serverCaCertificate,
                    Username = username,
                    Password = password,
                });
            }

            default:
                throw new NotSupportedException($"Unsupported secret manager config: {config.SecretManager.GetType().Name}");
        }
    }

    private static string ResolvePath(string stickDirectory, string path) =>
        Path.IsPathRooted(path) ? path : Path.Combine(stickDirectory, path);

    private Task<StickAttachResult> AttachAsync(string busid)
    {
        if (!OperatingSystem.IsWindows())
        {
            Logger.Warn($"Skipping attach of busid={busid}: {UnsupportedPlatformMessage}");
            return Task.FromResult(new StickAttachResult(StickAttachOutcome.UnsupportedPlatform, busid, UnsupportedPlatformMessage));
        }

        var vhci = new VhciAttacher();
        if (!vhci.TryAttach(Host, Port.ToString(), busid, out var port, out var error))
        {
            Logger.Warn($"Failed to attach busid={busid}: {error}");
            return Task.FromResult(new StickAttachResult(StickAttachOutcome.Failed, busid, error));
        }

        return Task.FromResult(new StickAttachResult(StickAttachOutcome.Success, busid, null) { Port = port });
    }

    private sealed record ConnectedStick(FidoUsbStick Device, int DeviceId, int? Port, IFido2SecretManager SecretManager);
}
