using System.Security.Cryptography;

namespace VFido.SecretManager.Protection;

/// <summary>Password authentication and storage unlocking, independent of the domain stores.</summary>
public static class PasswordStorageProtection
{
    public static AesPayloadProtector Create(string directory, string username, string password)
    {
        Directory.CreateDirectory(directory);
        var saltPath = Path.Combine(directory, "salt.bin");
        if (File.Exists(saltPath) || File.Exists(Path.Combine(directory, "verifier.bin")))
            throw new InvalidOperationException("Password storage is already initialized.");
        var salt = RandomNumberGenerator.GetBytes(16);
        using (var file = new FileStream(saltPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            file.Write(salt);
        var key = AesKeyProtector.DeriveKey(username, password, salt);
        try
        {
            PasswordVerifier.EnsureOrVerify(directory, key, isNewStore: true);
            return new AesPayloadProtector(key);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public static AesPayloadProtector Open(string directory, string username, string password)
    {
        var saltPath = Path.Combine(directory, "salt.bin");
        if (!File.Exists(saltPath) || !File.Exists(Path.Combine(directory, "verifier.bin")))
            throw new InvalidDataException("Storage authentication files are missing. Restore the complete storage backup.");
        var salt = File.ReadAllBytes(saltPath);
        if (salt.Length != 16) throw new InvalidDataException("Invalid storage salt.");
        var key = AesKeyProtector.DeriveKey(username, password, salt);
        try
        {
            PasswordVerifier.EnsureOrVerify(directory, key, isNewStore: false);
            return new AesPayloadProtector(key);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    /// <summary>Compatibility entry point for old constructors. Existing payloads never initialize new keys.</summary>
    public static AesPayloadProtector OpenOrCreate(string directory, string username, string password)
    {
        directory = Path.GetFullPath(directory);
        if (Directory.Exists(directory) && Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Any(p => (Path.GetDirectoryName(p) == Path.GetFullPath(directory) && Path.GetFileName(p) is "salt.bin" or "verifier.bin" or "wrapped.key") || Path.GetFileName(p) == "pin.bin"
                || Path.GetExtension(p) is ".key" or ".cred"))
            return Open(directory, username, password);
        return Create(directory, username, password);
    }
}
