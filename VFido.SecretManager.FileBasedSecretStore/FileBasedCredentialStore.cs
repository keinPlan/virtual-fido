using System.Text.Json;
using VFido.SecretManager.Protection;

namespace VFido.SecretManager.FileBasedSecretStore;

/// <summary>Credential serialization and lookup; payload protection is supplied independently.</summary>
public class FileBasedCredentialStore : ICredentialStore, IDisposable
{
    private const string FormatFile = "credential-format.json";
    private readonly string _directory;
    private readonly IFileStorage _files;
    private IDisposable? _ownedProtection;

    public FileBasedCredentialStore(string directory, IFileStorage files)
    {
        _directory = directory;
        _files = files;
        Directory.CreateDirectory(directory);
        var marker = Path.Combine(directory, FormatFile);
        if (File.Exists(marker))
        {
            var format = JsonSerializer.Deserialize<CredentialFormat>(File.ReadAllBytes(marker));
            if (format is null || format.Version != 1 || format.Encrypted != files.Encrypted)
                throw new InvalidDataException("Credential file format does not match configuration. Convert the credential directory explicitly before changing EncryptCredentialFiles.");
        }
        else
        {
            // Unmarked directories containing .cred files are the legacy encrypted format.
            if (!files.Encrypted && Directory.EnumerateFiles(directory, "*.cred").Any())
                throw new InvalidDataException("Existing credential files require explicit conversion to plaintext.");
            if (Directory.EnumerateFiles(directory, "*.cred").Any()) return;
            AtomicFile.Write(marker, JsonSerializer.SerializeToUtf8Bytes(new CredentialFormat(1, files.Encrypted)));
        }
    }

    // Source-compatible adapters; new callers unlock once and inject storage.
    public FileBasedCredentialStore(string directory, string username, string password, string? authDirectory = null)
        : this(directory, PasswordStorageProtection.OpenOrCreate(authDirectory ?? directory, username, password)) { }
    public FileBasedCredentialStore(string directory, byte[] aesKey, string? authDirectory = null)
        : this(directory, new AesPayloadProtector(aesKey)) { }
    private FileBasedCredentialStore(string directory, AesPayloadProtector protector)
        : this(directory, new EncryptedFileStorage(protector)) => _ownedProtection = protector;

    public void Save(StoredCredential credential) =>
        _files.Write(CredentialFilePath(credential.CredentialId), JsonSerializer.SerializeToUtf8Bytes(credential));
    public StoredCredential? Find(byte[] credentialId)
    {
        var path = CredentialFilePath(credentialId);
        return File.Exists(path) ? Decode(path) : null;
    }
    public IReadOnlyList<StoredCredential> FindByRp(string rpId) => FindAll().Where(c => c.RpId == rpId).ToList();
    public IReadOnlyList<StoredCredential> FindAll() => Directory.EnumerateFiles(_directory, "*.cred").Select(Decode).ToList();
    public void Delete(byte[] credentialId) => File.Delete(CredentialFilePath(credentialId));
    private StoredCredential Decode(string path)
    {
        var credential = JsonSerializer.Deserialize<StoredCredential>(_files.Read(path))
            ?? throw new InvalidDataException("Corrupt credential file: empty payload.");
        if (credential.CredentialId is null || !string.Equals(Path.GetFileName(path),
            Path.GetFileName(CredentialFilePath(credential.CredentialId)), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Credential ID does not match its filename.");
        return credential;
    }
    private string CredentialFilePath(byte[] credentialId) => Path.Combine(_directory, Convert.ToHexString(credentialId) + ".cred");
    public void Dispose() => _ownedProtection?.Dispose();
    private sealed record CredentialFormat(int Version, bool Encrypted);

    /// <summary>Exports a converted directory. The source is never replaced or modified.</summary>
    public void ExportConverted(string destination, IFileStorage targetStorage)
    {
        destination = Path.GetFullPath(destination);
        var sourceDirectory = Path.GetFullPath(_directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if ((destination + Path.DirectorySeparatorChar).StartsWith(sourceDirectory, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Conversion destination must be outside the source directory.");
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException("Conversion destination must not exist.");
        var credentials = FindAll(); // Validate the complete source before writing anything.
        var staging = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using var target = new FileBasedCredentialStore(staging, targetStorage);
            foreach (var credential in credentials) target.Save(credential);
            if (target.FindAll().Count != credentials.Count) throw new InvalidDataException("Incomplete conversion.");
            Directory.Move(staging, destination);
        }
        finally
        {
            if (Directory.Exists(staging))
            {
                foreach (var file in Directory.EnumerateFiles(staging)) File.Delete(file);
                Directory.Delete(staging);
            }
        }
    }
}
