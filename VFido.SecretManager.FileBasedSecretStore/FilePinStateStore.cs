using System.Text.Json;

namespace VFido.SecretManager.FileBasedSecretStore;

public sealed class FilePinStateStore : IPinStateStore
{
    private readonly string _path;
    private readonly IFileStorage _files;
    public FilePinStateStore(string directory, IFileStorage files)
    {
        if (!files.Encrypted) throw new ArgumentException("PIN state requires protected storage.", nameof(files));
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "pin.bin");
        _files = files;
    }
    public PinState? Load() => File.Exists(_path) ? JsonSerializer.Deserialize<PinState>(_files.Read(_path)) : null;
    public void Save(PinState state) => _files.Write(_path, JsonSerializer.SerializeToUtf8Bytes(state));
}
