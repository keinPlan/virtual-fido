namespace VFido.Gui.Configuration;

/// <summary>Reads/writes per-stick config.json files under a VFido root directory, one subfolder per stick, named after <see cref="StickConfig.Name"/>.</summary>
public interface IStickConfigStore
{
    IReadOnlyList<StickConfig> LoadAll();

    /// <summary>Throws <see cref="ArgumentException"/> if <paramref name="name"/> isn't a valid stick name, or one is already in use.</summary>
    StickConfig Create(string name, string serialNumber, SecretManagerConfig secretManager);

    void Save(StickConfig config);

    void Delete(string name);

    string GetStickDirectory(string name);

    string GetKeyStoreDirectory(string name);

    string GetCredentialStoreDirectory(string name);
}
