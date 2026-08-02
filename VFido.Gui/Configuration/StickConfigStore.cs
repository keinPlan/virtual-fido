using System.Text.Json;
using System.Text.Json.Serialization;
using NLog;
using VFido.Core.Device.Ctap2.Authenticator.Pin;

namespace VFido.Gui.Configuration;

/// <summary>
/// Persists stick configs under &lt;root&gt;/{Id}/config.json - portable, next to the exe by
/// default (AppContext.BaseDirectory/VFido), not AppData. A corrupt or partially-written
/// config.json in one stick's folder is logged and skipped rather than failing LoadAll for every
/// other stick.
/// </summary>
public sealed class StickConfigStore : IStickConfigStore
{
    private const string ConfigFileName = "config.json";
    private const string KeysFolderName = "keys";
    private const string CredentialsFolderName = "credentials";

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _rootDirectory;

    public StickConfigStore(string? rootDirectory = null)
    {
        _rootDirectory = rootDirectory ?? Path.Combine(AppContext.BaseDirectory, "VFido");
    }

    public IReadOnlyList<StickConfig> LoadAll()
    {
        if (!Directory.Exists(_rootDirectory))
            return Array.Empty<StickConfig>();

        var configs = new List<StickConfig>();
        foreach (var stickDirectory in Directory.EnumerateDirectories(_rootDirectory))
        {
            var configPath = Path.Combine(stickDirectory, ConfigFileName);
            if (!File.Exists(configPath))
                continue;

            try
            {
                var json = File.ReadAllText(configPath);
                var config = JsonSerializer.Deserialize<StickConfig>(json, JsonOptions);
                if (config != null)
                    configs.Add(config);
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, () => $"Skipping unreadable stick config at {configPath}");
            }
        }

        return configs;
    }

    public StickConfig Create(string name, Guid aaguid, string serialNumber, SecretManagerConfig secretManager, PinUsagePreference pinUsage)
    {
        var config = new StickConfig
        {
            Id = Guid.NewGuid(),
            Name = name,
            SerialNumberIdentifier = serialNumber,
            Aaguid = aaguid,
            PinUsage = pinUsage,
            SecretManager = secretManager,
        };

        Save(config);
        return config;
    }

    public void Save(StickConfig config)
    {
        var stickDirectory = GetStickDirectory(config.Id);
        Directory.CreateDirectory(stickDirectory);

        var json = JsonSerializer.Serialize(config, JsonOptions);
        File.WriteAllText(Path.Combine(stickDirectory, ConfigFileName), json);
    }

    public void Delete(Guid id)
    {
        var stickDirectory = GetStickDirectory(id);
        if (Directory.Exists(stickDirectory))
            Directory.Delete(stickDirectory, recursive: true);
    }

    public string GetStickDirectory(Guid id) => Path.Combine(_rootDirectory, id.ToString());

    public string GetKeyStoreDirectory(Guid id) => Path.Combine(GetStickDirectory(id), KeysFolderName);

    public string GetCredentialStoreDirectory(Guid id) => Path.Combine(GetStickDirectory(id), CredentialsFolderName);
}
