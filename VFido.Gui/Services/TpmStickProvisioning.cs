using System.Security.Cryptography;
using System.IO.Compression;
using VFido.Gui.Configuration;
using VFido.SecretManager;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VFido.Gui.Services;

/// <summary>GUI-independent provisioning, recovery, and ownership of local TPM stores.</summary>
public static class TpmStickProvisioning
{
    /// <summary>Copies wrapped keys and encrypted state, excluding the TPM-local master. Caller must pause writes.</summary>
    public static byte[] ExportBackup(IStickConfigStore configs, StickConfig config)
    {
        if (config.SecretManager is not TpmSecretManagerConfig)
            throw new ArgumentException("Expected TPM configuration.", nameof(config));
        if (!StickConfigStore.IsValidStickName(config.Name))
            throw new ArgumentException("Invalid stick name.", nameof(config));
        var directory = configs.GetStickDirectory(config.Name);
        foreach (var required in new[] { "config.json", "salt.bin", "verifier.bin" })
            if (!File.Exists(Path.Combine(directory, required)))
                throw new InvalidDataException($"Cannot export an incomplete stick: {required} is missing.");

        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            AddDirectory(directory);
            var instructions = archive.CreateEntry("RESTORE.txt");
            using var writer = new StreamWriter(instructions.Open());
            writer.Write($"""
                VFido TPM stick backup: {config.Name}

                Extract the {config.Name} folder into your configured VFido directory while the stick is disconnected.
                Keep the folder name and all files together. Avoid overwriting a newer stick: counters and PIN retry state reflect the time of this backup.
                Connect using the original metadata username and password. This ZIP has no additional password; stored keys remain TPM-wrapped and metadata remains encrypted.

                master.json is deliberately excluded. Before connecting, use Edit > Restore master on this TPM with the original recovery PFX, its password, and the original metadata password, even on the original TPM.
                The recovery PFX is stored separately and is not included by this export.
                """);

            void AddDirectory(string path)
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("TPM backup cannot include symbolic links or junctions.");
                foreach (var file in Directory.EnumerateFileSystemEntries(path))
                {
                    if (string.Equals(Path.GetFileName(file), "master.json", StringComparison.OrdinalIgnoreCase)) continue;
                    var attributes = File.GetAttributes(file);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("TPM backup cannot include symbolic links or junctions.");
                    if ((attributes & FileAttributes.Directory) != 0) AddDirectory(file);
                    else archive.CreateEntryFromFile(file, config.Name + "/" + Path.GetRelativePath(directory, file).Replace('\\', '/'));
                }
            }
        }
        return output.ToArray();
    }

    public static StickConfig Create(IStickConfigStore configs, string name, string serial,
        string username, string metadataPassword, string pfxPath, string pfxPassword)
    {
        EnsureWindows();
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(metadataPassword);
        using var master = ReadMaster(pfxPath, pfxPassword);
        var config = configs.Create(name, serial, new TpmSecretManagerConfig
        { Username = username, MasterName = Convert.ToHexString(master.Name) });
        try
        {
            TpmBasedSecretStore.Provision(configs.GetKeyStoreDirectory(name), master, masterPassword: metadataPassword);
            using var manager = OpenCore(configs, config, username, metadataPassword, initializeMetadata: true);
            // Verify this TPM can import and sign P-256 before publishing a usable stick.
            var probe = manager.CreateCredentialAsync("vfido-provisioning.invalid", Array.Empty<byte>(), "probe", "probe", false, 1).GetAwaiter().GetResult();
            try { _ = manager.SignAsync(probe.CredentialId, RandomNumberGenerator.GetBytes(32)).GetAwaiter().GetResult(); }
            finally { manager.DeleteCredentialAsync(probe.CredentialId).GetAwaiter().GetResult(); }
            return config;
        }
        catch (Exception failure)
        {
            // Create succeeded, so this call owns exactly this newly created stick directory.
            try { configs.Delete(config.Name); }
            catch (Exception cleanup) { throw new AggregateException("TPM setup failed and cleanup was incomplete.", failure, cleanup); }
            throw;
        }
    }

    public static Fido2SecretManager Open(IStickConfigStore configs, StickConfig config, string username, string password) =>
        OpenCore(configs, config, username, password, initializeMetadata: false);

    private static Fido2SecretManager OpenCore(IStickConfigStore configs, StickConfig config, string username, string password, bool initializeMetadata)
    {
        EnsureWindows();
        var settings = config.SecretManager as TpmSecretManagerConfig ?? throw new ArgumentException("Expected TPM configuration.");
        var authDirectory = configs.GetStickDirectory(config.Name);
        if (!initializeMetadata && (!File.Exists(Path.Combine(authDirectory, "salt.bin")) || !File.Exists(Path.Combine(authDirectory, "verifier.bin"))))
            throw new InvalidDataException("Metadata authentication files are missing. Restore the complete stick folder before connecting.");
        // Check the metadata password before allocating TPM resources.
        var credentials = new TpmBasedCredentialStore(configs.GetCredentialStoreDirectory(config.Name), username, password, authDirectory);
        var pin = new FileBasedSecretStore(Path.Combine(authDirectory, "state"), username, password, authDirectory: authDirectory);
        var keys = new TpmBasedSecretStore(configs.GetKeyStoreDirectory(config.Name), masterPassword: password);
        try
        {
            if (!string.Equals(Convert.ToHexString(keys.MasterName), settings.MasterName, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("The local TPM master does not match this stick. Restore its original recovery PFX from Edit.");
            return new Fido2SecretManager(keys, credentials, pinState: pin, ownsKeyStore: true);
        }
        catch { keys.Dispose(); throw; }
    }

    /// <summary>Stage and validate every existing child before atomically replacing the local master.</summary>
    public static void Restore(IStickConfigStore configs, StickConfig config, string pfxPath, string password,
        string metadataPassword)
    {
        EnsureWindows();
        var settings = config.SecretManager as TpmSecretManagerConfig ?? throw new ArgumentException("Expected TPM configuration.");
        using var master = ReadMaster(pfxPath, password);
        if (!string.Equals(Convert.ToHexString(master.Name), settings.MasterName, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("This recovery PFX belongs to a different master.");
        var authDirectory = configs.GetStickDirectory(config.Name);
        if (!File.Exists(Path.Combine(authDirectory, "salt.bin")) || !File.Exists(Path.Combine(authDirectory, "verifier.bin")))
            throw new InvalidDataException("Metadata authentication files are missing. Restore the complete stick folder first.");
        // Validate the original password before wrapping a replacement master with it.
        _ = new TpmBasedCredentialStore(configs.GetCredentialStoreDirectory(config.Name), settings.Username,
            metadataPassword, authDirectory);
        var keys = Path.GetFullPath(configs.GetKeyStoreDirectory(config.Name));
        Directory.CreateDirectory(keys);
        var staging = Path.Combine(keys, ".restore-" + Guid.NewGuid().ToString("N"));
        try
        {
            TpmBasedSecretStore.Provision(staging, master, masterPassword: metadataPassword);
            using (var candidate = new TpmBasedSecretStore(staging, masterPassword: metadataPassword))
                foreach (var file in Directory.EnumerateFiles(keys, "*.tpmkey"))
                {
                    if (new FileInfo(file).Length > 16384) throw new InvalidDataException("A wrapped credential is too large.");
                    candidate.ImportWrappedKey(File.ReadAllBytes(file));
                }
            File.Move(Path.Combine(staging, "master.json"), Path.Combine(keys, "master.json"), overwrite: true);
        }
        finally { if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true); }
    }

    private static TpmMasterKey ReadMaster(string path, string password)
    {
        if (new FileInfo(path).Length > 1_048_576) throw new InvalidDataException("Recovery PFX is too large.");
        var bytes = File.ReadAllBytes(path);
        try { return TpmMasterKey.ImportPfx(bytes, password); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The GUI TPM backend requires Windows TPM 2.0.");
    }
}
