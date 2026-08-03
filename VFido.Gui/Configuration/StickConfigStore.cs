using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using NLog;

namespace VFido.Gui.Configuration;

/// <summary>
/// Persists stick configs under &lt;root&gt;/{Name}/config.json - portable, next to the exe by
/// default (AppContext.BaseDirectory/VFido), not AppData. A corrupt or partially-written
/// config.json in one stick's folder is logged and skipped rather than failing LoadAll for every
/// other stick.
/// </summary>
public sealed class StickConfigStore : IStickConfigStore
{
    private const string ConfigFileName = "config.json";
    private const string KeysFolderName = "keys";
    private const string CredentialsFolderName = "credentials";
    private const string CertsFolderName = "certs";
    private const int MaxNameLength = 32;

    // Deliberately conservative rather than merely "whatever Windows/Linux allow": letters,
    // digits, dot, underscore and hyphen only, no spaces - safe as a folder name on every
    // platform this runs on, with no reserved-device-name (CON/PRN/...) or path-separator footguns.
    private static readonly Regex ValidNamePattern = new(@"^[A-Za-z0-9._-]+$", RegexOptions.Compiled);

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

    public StickConfig Create(string name, string serialNumber, SecretManagerConfig secretManager)
    {
        if (!IsValidStickName(name))
            throw new ArgumentException($"\"{name}\" is not a valid stick name: use up to {MaxNameLength} letters, digits, '.', '_' or '-', no spaces.", nameof(name));

        var stickDirectory = GetStickDirectory(name);
        if (Directory.Exists(stickDirectory))
            throw new ArgumentException($"A stick named \"{name}\" already exists.", nameof(name));

        var config = new StickConfig
        {
            Name = name,
            SerialNumberIdentifier = serialNumber,
            SecretManager = secretManager,
        };

        Save(config);
        return config;
    }

    public void Save(StickConfig config)
    {
        var stickDirectory = GetStickDirectory(config.Name);
        Directory.CreateDirectory(stickDirectory);

        var json = JsonSerializer.Serialize(config, JsonOptions);
        File.WriteAllText(Path.Combine(stickDirectory, ConfigFileName), json);
    }

    public void Delete(string name)
    {
        var stickDirectory = GetStickDirectory(name);
        if (Directory.Exists(stickDirectory))
            Directory.Delete(stickDirectory, recursive: true);
    }

    public string GetStickDirectory(string name) => Path.Combine(_rootDirectory, name);

    public string GetKeyStoreDirectory(string name) => Path.Combine(GetStickDirectory(name), KeysFolderName);

    public string GetCredentialStoreDirectory(string name) => Path.Combine(GetStickDirectory(name), CredentialsFolderName);

    public string GetAttestationCertificateDirectory(string name) => Path.Combine(GetStickDirectory(name), CertsFolderName);

    /// <summary>True if <paramref name="name"/> is safe to use verbatim as a stick's folder name: non-empty, at most <see cref="MaxNameLength"/> characters, no spaces or path-unsafe characters.</summary>
    public static bool IsValidStickName(string? name) =>
        !string.IsNullOrEmpty(name) && name.Length <= MaxNameLength && ValidNamePattern.IsMatch(name);
}
