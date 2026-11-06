using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using VFido.SecretManager.TpmBasedSecretStore;
using TpmStore = VFido.SecretManager.TpmBasedSecretStore.TpmBasedSecretStore;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;

/// <summary>One recoverable TPM parent, copied into otherwise independent per-user stores.</summary>
public static class ServerTpmMaster
{
    public static string DirectoryPath(MtlsBasedSecretStoreServerOptions options) => Path.Combine(options.PkiRootPath, "tpm");
    public static string RecoveryPath(MtlsBasedSecretStoreServerOptions options) => Path.Combine(DirectoryPath(options), "vfido-tpm-recovery.pfx");

    public static void Create(MtlsBasedSecretStoreServerOptions options, byte[] recoveryPfx, string recoveryPassword)
    {
        using var master = TpmMasterKey.ImportPfx(recoveryPfx, recoveryPassword);
        var directory = DirectoryPath(options);
        if (File.Exists(Path.Combine(directory, "master.json")))
            throw new IOException("A server TPM master already exists.");
        Directory.CreateDirectory(directory);
        using var certificate = new X509Certificate2(Path.Combine(options.PkiRootPath, "master-protection.pfx"),
            (string?)null, X509KeyStorageFlags.EphemeralKeySet);
        var provider = DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(options.PkiRootPath, "keyring")),
            builder => builder.SetApplicationName("VFido.Server").ProtectKeysWithCertificate(certificate));
        var authorization = new UserKeyProtector(provider).GetOrCreateKey(directory);
        try
        {
            TpmStore.Provision(directory, master, masterPassword: Convert.ToBase64String(authorization));
            using var opened = new TpmStore(directory, masterPassword: Convert.ToBase64String(authorization));
            using var file = new FileStream(RecoveryPath(options), FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(recoveryPfx);
        }
        finally { CryptographicOperations.ZeroMemory(authorization); }
    }

    public static void CopyToUser(MtlsBasedSecretStoreServerOptions options, string userDirectory)
    {
        if (options.StorageProvider != ServerStorageProvider.Tpm) return;
        var source = DirectoryPath(options);
        if (!File.Exists(Path.Combine(source, "master.json")) || !File.Exists(Path.Combine(source, "wrapped.key")))
            throw new InvalidOperationException("Server TPM master is not configured. Complete TPM setup before creating users.");
        var legacy = Path.Combine(userDirectory, "tpm");
        if (Directory.Exists(legacy) && Directory.EnumerateFileSystemEntries(legacy).Any())
            throw new InvalidOperationException("This user has the old tpm folder layout. Migrate its keys and credentials before opening the flat user store.");
        var destination = Path.Combine(userDirectory, "keys");
        Directory.CreateDirectory(destination);
        foreach (var name in new[] { "master.json" })
        {
            var sourcePath = Path.Combine(source, name);
            var destinationPath = Path.Combine(destination, name);
            if (File.Exists(destinationPath))
            {
                if (!File.ReadAllBytes(sourcePath).AsSpan().SequenceEqual(File.ReadAllBytes(destinationPath)))
                    throw new InvalidOperationException("User TPM master differs from the server template. Existing keys require migration; no master has been overwritten.");
            }
        }
        foreach (var name in new[] { "master.json" })
            if (!File.Exists(Path.Combine(destination, name)))
                File.Copy(Path.Combine(source, name), Path.Combine(destination, name), overwrite: false);
    }

    public static string GetAuthorization(MtlsBasedSecretStoreServerOptions options)
    {
        // Use the same explicit application identity as setup; independent of the host's content root.
        using var certificate = new X509Certificate2(Path.Combine(options.PkiRootPath, "master-protection.pfx"),
            (string?)null, X509KeyStorageFlags.EphemeralKeySet);
        var provider = DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(options.PkiRootPath, "keyring")),
            builder => builder.SetApplicationName("VFido.Server").ProtectKeysWithCertificate(certificate));
        var directory = DirectoryPath(options);
        if (!UserKeyProtector.HasWrappedKey(directory))
            throw new InvalidOperationException("The server TPM authorization is missing. Restore the server PKI backup.");
        var key = new UserKeyProtector(provider).GetOrCreateKey(directory);
        try { return Convert.ToBase64String(key); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    /// <summary>Delete only the server's temporary recovery export, never user-downloaded backups.</summary>
    public static void DeleteRecoveryExport(MtlsBasedSecretStoreServerOptions options) => File.Delete(RecoveryPath(options));
}
