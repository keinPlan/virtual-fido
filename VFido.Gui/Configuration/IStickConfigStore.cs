using VFido.Core.Device.Ctap2.Authenticator.Pin;

namespace VFido.Gui.Configuration;

/// <summary>Reads/writes per-stick config.json files under a VFido root directory, one subfolder per stick.</summary>
public interface IStickConfigStore
{
    IReadOnlyList<StickConfig> LoadAll();

    StickConfig Create(string name, Guid aaguid, string serialNumber, SecretManagerConfig secretManager, PinUsagePreference pinUsage);

    void Save(StickConfig config);

    void Delete(Guid id);

    string GetStickDirectory(Guid id);

    string GetKeyStoreDirectory(Guid id);

    string GetCredentialStoreDirectory(Guid id);
}
