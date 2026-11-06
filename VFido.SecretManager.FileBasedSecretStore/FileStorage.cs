using VFido.SecretManager.Protection;

namespace VFido.SecretManager.FileBasedSecretStore;

/// <summary>Payload persistence. Paths and serialization belong to the domain store.</summary>
public interface IFileStorage
{
    bool Encrypted { get; }
    byte[] Read(string path);
    void Write(string path, byte[] payload);
}

public sealed class PlainFileStorage : IFileStorage
{
    public bool Encrypted => false;
    public byte[] Read(string path) => File.ReadAllBytes(path);
    public void Write(string path, byte[] payload) => AtomicFile.Write(path, payload);
}

public sealed class EncryptedFileStorage(IPayloadProtector protector) : IFileStorage
{
    public bool Encrypted => true;
    public byte[] Read(string path) => protector.Unprotect(File.ReadAllBytes(path));
    public void Write(string path, byte[] payload)
    {
        var encrypted = protector.Protect(payload);
        AtomicFile.Write(path, encrypted);
    }
}

internal static class AtomicFile
{
    public static void Write(string path, byte[] payload)
    {
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(payload);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
        }
        finally { File.Delete(temp); }
    }
}
