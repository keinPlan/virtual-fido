using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using VFido.SecretManager;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;
using VFido.SecretManager.Protection;

namespace VirtualFido.Tests;

public sealed class StorageProtectionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "vfido-protection-" + Guid.NewGuid());
    private string Sub(string name) => Path.Combine(_root, name);
    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }

    [Fact]
    public void LegacyPayloadAndPasswordFilesRemainReadable()
    {
        Directory.CreateDirectory(_root);
        var salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("alice_password"), salt, 100_000, HashAlgorithmName.SHA256, 32);
        File.WriteAllBytes(Sub("salt.bin"), salt);
        File.WriteAllBytes(Sub("verifier.bin"), LegacyEncrypt(key, Encoding.UTF8.GetBytes("VFIDO-VERIFY")));
        var credential = Credential();
        Directory.CreateDirectory(Sub("credentials"));
        File.WriteAllBytes(Path.Combine(Sub("credentials"), "010203.cred"), LegacyEncrypt(key, JsonSerializer.SerializeToUtf8Bytes(credential)));
        using var protection = PasswordStorageProtection.Open(_root, "alice", "password");
        using var store = new FileBasedCredentialStore(Sub("credentials"), new EncryptedFileStorage(protection));
        Assert.Equal("example.com", store.Find([1, 2, 3])!.RpId);
        Assert.False(File.Exists(Path.Combine(Sub("credentials"), "credential-format.json")));
        Assert.Throws<InvalidCredentialsException>(() => PasswordStorageProtection.Open(_root, "alice", "wrong"));
    }

    private static byte[] LegacyEncrypt(byte[] key, byte[] payload)
    {
        var result = new byte[28 + payload.Length];
        RandomNumberGenerator.Fill(result.AsSpan(0, 12));
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(result.AsSpan(0, 12), payload, result.AsSpan(28), result.AsSpan(12, 16));
        return result;
    }

    [Fact]
    public void ConversionRoundTripsAndRetainsSource()
    {
        using var protection = new AesPayloadProtector(RandomNumberGenerator.GetBytes(32));
        var encrypted = new EncryptedFileStorage(protection);
        using var original = new FileBasedCredentialStore(Sub("encrypted"), encrypted);
        original.Save(Credential());
        var source = File.ReadAllBytes(Path.Combine(Sub("encrypted"), "010203.cred"));
        original.ExportConverted(Sub("plain"), new PlainFileStorage());
        using var plain = new FileBasedCredentialStore(Sub("plain"), new PlainFileStorage());
        Assert.Equal("example.com", JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Sub("plain"), "010203.cred"))).RootElement.GetProperty("RpId").GetString());
        Assert.Equal(source, File.ReadAllBytes(Path.Combine(Sub("encrypted"), "010203.cred")));
        Assert.Throws<InvalidDataException>(() => new FileBasedCredentialStore(Sub("plain"), encrypted));
        Assert.Throws<InvalidDataException>(() => new FileBasedCredentialStore(Sub("encrypted"), new PlainFileStorage()));
        plain.ExportConverted(Sub("reencrypted"), encrypted);
        using var reopened = new FileBasedCredentialStore(Sub("reencrypted"), encrypted);
        Assert.Equal(JsonSerializer.Serialize(Credential()), JsonSerializer.Serialize(reopened.Find([1, 2, 3])));
        Assert.Throws<IOException>(() => plain.ExportConverted(Sub("reencrypted"), encrypted));
    }

    [Fact]
    public void TamperingAndTruncationNeverFallBackToPlaintext()
    {
        using var protection = new AesPayloadProtector(RandomNumberGenerator.GetBytes(32));
        using var store = new FileBasedCredentialStore(Sub("credentials"), new EncryptedFileStorage(protection));
        store.Save(Credential());
        var path = Path.Combine(Sub("credentials"), "010203.cred");
        var bytes = File.ReadAllBytes(path);
        bytes[^1] ^= 1;
        File.WriteAllBytes(path, bytes);
        Assert.ThrowsAny<CryptographicException>(() => store.FindAll());
        Assert.ThrowsAny<CryptographicException>(() => store.ExportConverted(Sub("converted"), new PlainFileStorage()));
        Assert.False(Directory.Exists(Sub("converted")));
        File.WriteAllBytes(path, [1]);
        Assert.ThrowsAny<CryptographicException>(() => store.FindAll());
        File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(Credential()));
        Assert.ThrowsAny<CryptographicException>(() => store.FindAll());
    }

    [Fact]
    public void MissingAuthenticationFilesCannotInitializeReplacementKeys()
    {
        using (PasswordStorageProtection.Create(_root, "alice", "password")) { }
        File.Delete(Sub("verifier.bin"));
        Assert.Throws<InvalidDataException>(() => PasswordStorageProtection.Open(_root, "alice", "password"));
        Assert.Throws<InvalidDataException>(() => PasswordStorageProtection.OpenOrCreate(_root, "alice", "password"));
        Assert.False(File.Exists(Sub("verifier.bin")));
        Assert.Throws<ArgumentException>(() => new FilePinStateStore(_root, new PlainFileStorage()));
        Assert.Throws<ArgumentException>(() => new FileBasedSecretStore(_root, new PlainFileStorage()));
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task ServerCredentialModeDoesNotChangeSigningPinProtectionOrAuthentication(bool encrypt, bool passwordless)
    {
        var options = new MtlsBasedSecretStoreServerOptions { SecretsRootPath = Sub("users"), EncryptCredentialFiles = encrypt };
        var userDirectory = Path.Combine(options.SecretsRootPath, "alice");
        if (!passwordless) using (PasswordStorageProtection.Create(userDirectory, "alice", "password")) { }
        var protector = new UserKeyProtector(new EphemeralDataProtectionProvider());
        byte[] id;
        using (var resolver = new UserDirectoryResolver(options, protector))
        {
            var manager = passwordless ? resolver.BuildPasswordlessManager("alice") : resolver.BuildManagerFromPassword("alice", "password");
            await manager.SavePinStateAsync(new PinState([7, 8, 9], 0));
            Assert.DoesNotContain("PinHash", Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(userDirectory, "pin.bin"))));
            id = (await manager.CreateCredentialAsync("example.com", [1], "alice", "Alice", true, 1)).CredentialId;
            Assert.NotEmpty(await manager.SignAsync(id, [1, 2]));
            if (!passwordless) Assert.Throws<InvalidCredentialsException>(() => resolver.BuildManagerFromPassword("alice", "wrong"));
            var bytes = File.ReadAllBytes(Directory.GetFiles(Path.Combine(userDirectory, "credentials"), "*.cred").Single());
            Assert.Equal(!encrypt, Encoding.UTF8.GetString(bytes).Contains("example.com"));
        }
        using var reopened = new UserDirectoryResolver(options, protector);
        var restored = passwordless ? reopened.BuildPasswordlessManager("alice") : reopened.BuildManagerFromPassword("alice", "password");
        Assert.Equal(0, (await restored.LoadPinStateAsync())!.Retries);
        Assert.Equal(new byte[] { 7, 8, 9 }, (await restored.LoadPinStateAsync())!.PinHash);
        Assert.True(await restored.CredentialExistsAsync(id, "example.com"));
        Assert.NotEmpty(await restored.SignAsync(id, [3, 4]));
        var keys = Directory.GetFiles(Path.Combine(userDirectory, "keys"), "*.key");
        Assert.Single(keys);
        using var ecdsa = ECDsa.Create();
        Assert.ThrowsAny<CryptographicException>(() => ecdsa.ImportPkcs8PrivateKey(File.ReadAllBytes(keys[0]), out _));
    }

    private static StoredCredential Credential() => new()
    {
        CredentialId = [1, 2, 3], RpId = "example.com", UserId = [4], UserName = "alice",
        UserDisplayName = "Alice", KeyHandle = [5], IsResident = true, SignCount = 17, CredProtect = 1
    };
}
