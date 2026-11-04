using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using VFido.SecretManager;
using VFido.SecretManager.Crypto;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MemoryBasedSecretStore;

namespace VirtualFido.Tests;

public sealed class BackupIdentityFixture : IDisposable
{
    public const string Password = "test transfer password";
    public TransferIdentity Identity { get; } = PasskeyBackup.CreateIdentity(Password);
    public X509Certificate2 Public { get; }
    public X509Certificate2 Private { get; }

    public BackupIdentityFixture()
    {
        Public = new X509Certificate2(Identity.Certificate);
        Private = new X509Certificate2(Identity.PasswordProtectedPfx, Password, X509KeyStorageFlags.EphemeralKeySet);
    }

    public void Dispose()
    {
        Public.Dispose();
        Private.Dispose();
        CryptographicOperations.ZeroMemory(Identity.PasswordProtectedPfx);
    }
}

public sealed class PasskeyBackupTests : IClassFixture<BackupIdentityFixture>, IDisposable
{
    private readonly BackupIdentityFixture _identity;
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "vfido-backup-tests-" + Guid.NewGuid());
    public PasskeyBackupTests(BackupIdentityFixture identity) => _identity = identity;
    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }

    private static Fido2SecretManager MemoryManager() => new(new MemoryBasedSecretStore(), new InMemoryCredentialStore());
    private static Task<CredentialRegistration> Register(Fido2SecretManager manager, string rp = "example.com", bool resident = true) =>
        manager.CreateCredentialAsync(rp, new byte[] { 1, 2, 3 }, "alice", "Alice Example", resident, 3);

    private Fido2SecretManager FileManager() => new(
        new FileBasedSecretStore(Path.Combine(_directory, "keys"), "alice", "local password", authDirectory: _directory),
        new FileBasedCredentialStore(Path.Combine(_directory, "credentials"), "alice", "local password", _directory));

    [Fact]
    public void Identity_HasPublicCertificateAndPasswordProtectedPrivateKey()
    {
        Assert.False(_identity.Public.HasPrivateKey);
        Assert.True(_identity.Private.HasPrivateKey);
        Assert.Equal(PasskeyBackup.Fingerprint(_identity.Public), PasskeyBackup.Fingerprint(_identity.Private));
        Assert.ThrowsAny<CryptographicException>(() => new X509Certificate2(
            _identity.Identity.PasswordProtectedPfx, "wrong password", X509KeyStorageFlags.EphemeralKeySet));
        Assert.Throws<ArgumentException>(() => PasskeyBackup.CreateIdentity(" "));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MemoryToFile_RestartPreservesIdentityProtectionCounterAndSigningKey(bool resident)
    {
        var source = MemoryManager();
        var registration = await Register(source, resident: resident);
        await source.IncrementSignCountAsync(registration.CredentialId);
        await source.IncrementSignCountAsync(registration.CredentialId);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        Assert.DoesNotContain("example.com", Encoding.UTF8.GetString(backup));
        Assert.DoesNotContain("Alice Example", Encoding.UTF8.GetString(backup));
        var destination = FileManager();
        var preview = await destination.PreviewPasskeyImportAsync(backup, _identity.Private);
        Assert.Single(preview.Credentials);
        Assert.Empty(await destination.FindAllCredentialsAsync());
        Assert.Equal(new PasskeyImportResult(1, 0), await destination.ImportPasskeysAsync(backup, _identity.Private));
        destination = FileManager();
        var restored = await destination.FindCredentialAsync(registration.CredentialId, "example.com");
        Assert.NotNull(restored);
        Assert.Equal(new byte[] { 1, 2, 3 }, restored.UserId);
        Assert.Equal("alice", restored.UserName);
        Assert.Equal("Alice Example", restored.UserDisplayName);
        Assert.Equal(resident, restored.IsResident);
        Assert.Equal(3, restored.CredProtect);
        Assert.Equal(2u, restored.SignCount);
        Assert.Null(await destination.FindCredentialAsync(registration.CredentialId, "other.example"));
        var data = RandomNumberGenerator.GetBytes(64);
        var signature = await destination.SignAsync(registration.CredentialId, data);
        using var publicKey = ECDsa.Create(CoseKeyDecoder.DecodePublicKey(new CborReader(registration.CosePublicKey)));
        Assert.True(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        Assert.True(await source.CredentialExistsAsync(registration.CredentialId, "example.com"));
        // File-backed keys also export portably rather than leaking their local GUID handle.
        var secondBackup = await destination.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var memoryDestination = MemoryManager();
        await memoryDestination.ImportPasskeysAsync(secondBackup, _identity.Private);
        var secondSignature = await memoryDestination.SignAsync(registration.CredentialId, data);
        Assert.True(publicKey.VerifyData(data, secondSignature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public async Task Export_OnlyIncludesSelectedCredentialsAndUsesFreshEncryption()
    {
        var source = MemoryManager();
        var selected = await Register(source);
        await Register(source, "other.example");
        var first = await source.ExportPasskeysAsync(new[] { selected.CredentialId }, _identity.Public);
        var second = await source.ExportPasskeysAsync(new[] { selected.CredentialId }, _identity.Public);
        Assert.False(first.SequenceEqual(second));
        var destination = MemoryManager();
        await destination.ImportPasskeysAsync(first, _identity.Private);
        Assert.Equal(selected.CredentialId, Assert.Single(await destination.FindAllCredentialsAsync()).CredentialId);
    }

    [Theory]
    [InlineData("ciphertext")]
    [InlineData("tag")]
    [InlineData("nonce")]
    [InlineData("wrappedKey")]
    public async Task TamperedBackup_IsRejectedBeforeAnyDestinationWrites(string field)
    {
        var source = MemoryManager();
        var registration = await Register(source);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var envelope = JsonNode.Parse(backup)!;
        var bytes = Convert.FromBase64String(envelope[field]!.GetValue<string>());
        bytes[0] ^= 1;
        envelope[field] = Convert.ToBase64String(bytes);
        var destination = MemoryManager();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => destination.ImportPasskeysAsync(
            Encoding.UTF8.GetBytes(envelope.ToJsonString()), _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    [Fact]
    public async Task PublicOnlyOrDifferentPrivateKey_CannotRestore()
    {
        var source = MemoryManager();
        var registration = await Register(source);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var destination = MemoryManager();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => destination.ImportPasskeysAsync(backup, _identity.Public));
        var other = PasskeyBackup.CreateIdentity("other password");
        using var otherPrivate = new X509Certificate2(other.PasswordProtectedPfx, "other password", X509KeyStorageFlags.EphemeralKeySet);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => destination.ImportPasskeysAsync(backup, otherPrivate));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    [Fact]
    public async Task DuplicateImport_DoesNotOverwriteDestinationOrLowerItsCounter()
    {
        var source = MemoryManager();
        var registration = await Register(source);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var destination = MemoryManager();
        await destination.ImportPasskeysAsync(backup, _identity.Private);
        await destination.IncrementSignCountAsync(registration.CredentialId);
        Assert.Equal(1, (await destination.PreviewPasskeyImportAsync(backup, _identity.Private)).AlreadyPresent);
        Assert.Equal(new PasskeyImportResult(0, 1), await destination.ImportPasskeysAsync(backup, _identity.Private));
        Assert.Equal(1u, (await destination.FindCredentialAsync(registration.CredentialId, "example.com"))!.SignCount);
    }

    [Fact]
    public async Task ConflictingCredentialId_RejectsWholeBatchBeforeWriting()
    {
        var source = MemoryManager();
        var first = await Register(source);
        var second = await Register(source, "second.example");
        var backup = await source.ExportPasskeysAsync(new[] { first.CredentialId, second.CredentialId }, _identity.Public);
        var keys = new MemoryBasedSecretStore();
        var credentials = new InMemoryCredentialStore();
        credentials.Save(new StoredCredential
        {
            CredentialId = second.CredentialId, RpId = "second.example", UserId = new byte[] { 1, 2, 3 },
            KeyHandle = keys.CreateEs256Key().ExportHandle(), IsResident = true, CredProtect = 3,
        });
        var destination = new Fido2SecretManager(keys, credentials);
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.PreviewPasskeyImportAsync(backup, _identity.Private));
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.ImportPasskeysAsync(backup, _identity.Private));
        Assert.Equal(second.CredentialId, Assert.Single(await destination.FindAllCredentialsAsync()).CredentialId);
    }

    [Fact]
    public async Task FailedMetadataWrite_RollsBackAllNewMetadataAndFileKeys()
    {
        var source = MemoryManager();
        var first = await Register(source);
        var second = await Register(source, "second.example");
        var backup = await source.ExportPasskeysAsync(new[] { first.CredentialId, second.CredentialId }, _identity.Public);
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var keysDirectory = Path.Combine(_directory, "keys");
        var credentials = new FailSecondSave(new FileBasedCredentialStore(Path.Combine(_directory, "credentials"), aesKey));
        var destination = new Fido2SecretManager(new FileBasedSecretStore(keysDirectory, aesKey), credentials);
        await Assert.ThrowsAsync<IOException>(() => destination.ImportPasskeysAsync(backup, _identity.Private));
        Assert.Empty(credentials.FindAll());
        Assert.Empty(Directory.EnumerateFiles(keysDirectory));
    }

    [Theory]
    [InlineData("version", "2")]
    [InlineData("format", "\"Other.Format\"")]
    [InlineData("algorithm", "\"Other.Algorithm\"")]
    [InlineData("nonce", "null")]
    public async Task UnsupportedOrMalformedEnvelope_IsRejected(string field, string json)
    {
        var source = MemoryManager();
        var registration = await Register(source);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var envelope = JsonNode.Parse(backup)!;
        envelope[field] = JsonNode.Parse(json);
        var destination = MemoryManager();
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.ImportPasskeysAsync(
            Encoding.UTF8.GetBytes(envelope.ToJsonString()), _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    [Theory]
    [InlineData("protection")]
    [InlineData("userHandle")]
    [InlineData("credentialId")]
    [InlineData("privateKey")]
    [InlineData("duplicate")]
    [InlineData("version")]
    public async Task AuthenticatedButInvalidPayload_IsRejectedBeforeWrites(string invalidField)
    {
        var source = MemoryManager();
        var registration = await Register(source);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var malformed = RewritePayload(backup, payload =>
        {
            var credentials = payload["credentials"]!.AsArray();
            var entry = credentials[0]!;
            switch (invalidField)
            {
                case "protection": entry["metadata"]!["credProtect"] = 0; break;
                case "userHandle": entry["metadata"]!["userId"] = Convert.ToBase64String(new byte[65]); break;
                case "credentialId": entry["metadata"]!["credentialId"] = ""; break;
                case "privateKey":
                    using (var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384))
                        entry["privateKeyPkcs8"] = Convert.ToBase64String(wrongCurve.ExportPkcs8PrivateKey());
                    break;
                case "duplicate": credentials.Add(entry.DeepClone()); break;
                case "version": payload["version"] = 2; break;
            }
        });
        var destination = MemoryManager();
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.ImportPasskeysAsync(malformed, _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    // Construct an authenticated, deliberately invalid payload as any holder of the public
    // recipient certificate could do. Payload validation must be independent of encryption.
    private byte[] RewritePayload(byte[] backup, Action<JsonNode> change)
    {
        var envelope = JsonNode.Parse(backup)!;
        using var rsa = _identity.Private.GetRSAPrivateKey()!;
        var key = rsa.Decrypt(Convert.FromBase64String(envelope["wrappedKey"]!.GetValue<string>()), RSAEncryptionPadding.OaepSHA256);
        var ciphertext = Convert.FromBase64String(envelope["ciphertext"]!.GetValue<string>());
        var plaintext = new byte[ciphertext.Length];
        var aad = Encoding.UTF8.GetBytes(string.Join("\n", new[]
        {
            envelope["format"]!.GetValue<string>(), envelope["version"]!.GetValue<int>().ToString(),
            envelope["algorithm"]!.GetValue<string>(), envelope["recipient"]!.GetValue<string>(),
            envelope["wrappedKey"]!.GetValue<string>(),
        }));
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(Convert.FromBase64String(envelope["nonce"]!.GetValue<string>()), ciphertext,
            Convert.FromBase64String(envelope["tag"]!.GetValue<string>()), plaintext, aad);
        var payload = JsonNode.Parse(plaintext)!;
        change(payload);
        var changed = Encoding.UTF8.GetBytes(payload.ToJsonString());
        var nonce = RandomNumberGenerator.GetBytes(12);
        ciphertext = new byte[changed.Length];
        var tag = new byte[16];
        aes.Encrypt(nonce, changed, ciphertext, tag, aad);
        envelope["nonce"] = Convert.ToBase64String(nonce);
        envelope["ciphertext"] = Convert.ToBase64String(ciphertext);
        envelope["tag"] = Convert.ToBase64String(tag);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(changed);
        return Encoding.UTF8.GetBytes(envelope.ToJsonString());
    }

    private sealed class FailSecondSave(ICredentialStore inner) : ICredentialStore
    {
        private int _writes;
        public void Save(StoredCredential credential)
        {
            inner.Save(credential);
            if (++_writes == 2) throw new IOException("Injected failure after writing metadata.");
        }
        public StoredCredential? Find(byte[] id) => inner.Find(id);
        public IReadOnlyList<StoredCredential> FindByRp(string rp) => inner.FindByRp(rp);
        public IReadOnlyList<StoredCredential> FindAll() => inner.FindAll();
        public void Delete(byte[] id) => inner.Delete(id);
    }
}
