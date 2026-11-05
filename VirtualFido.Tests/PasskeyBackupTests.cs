using System.IO.Compression;
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
        using var publicKey = _identity.Public.GetECDiffieHellmanPublicKey();
        Assert.NotNull(publicKey);
        Assert.Equal("1.2.840.10045.3.1.7", publicKey.ExportParameters(false).Curve.Oid.Value);
        Assert.Equal(X509KeyUsageFlags.KeyAgreement,
            Assert.Single(_identity.Public.Extensions.OfType<X509KeyUsageExtension>()).KeyUsages);
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
    [InlineData("hpkeKey")]
    [InlineData("header")]
    public async Task TamperedBackup_IsRejectedBeforeAnyDestinationWrites(string field)
    {
        var source = MemoryManager();
        var registration = await Register(source);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var envelope = JsonNode.Parse(backup)!;
        var parts = ReadJwe(envelope).Split('.');
        var index = field switch { "ciphertext" => 3, "tag" => 4, "nonce" => 2, _ => 0 };
        if (field == "hpkeKey")
        {
            using var other = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var point = other.ExportParameters(false).Q;
            envelope["hpke"]!["key"]!["x"] = Base64Url(point.X!);
            envelope["hpke"]!["key"]!["y"] = Base64Url(point.Y!);
        }
        else if (field == "header")
        {
            var header = JsonNode.Parse(CxpTransport.Decode(parts[0]))!;
            header["kid"] = new string('0', 64);
            parts[0] = Base64Url(Encoding.UTF8.GetBytes(header.ToJsonString()));
            ReplaceJwe(envelope, string.Join('.', parts));
        }
        else
        {
            var data = CxpTransport.Decode(parts[index]);
            data[0] ^= 1;
            parts[index] = Base64Url(data);
            ReplaceJwe(envelope, string.Join('.', parts));
        }
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
    [InlineData("archive", "\"other\"")]
    [InlineData("hpke", "null")]
    [InlineData("payload", "null")]
    [InlineData("payload", "\"AQ==\"")]
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
    [InlineData("counterPolicy")]
    [InlineData("negativeCounter")]
    [InlineData("metadataId")]
    [InlineData("duplicateMetadata")]
    [InlineData("base64url")]
    [InlineData("fidoExtension")]
    public async Task AuthenticatedButInvalidPayload_IsRejectedBeforeWrites(string invalidField)
    {
        var source = MemoryManager();
        var registration = await Register(source);
        var backup = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var malformed = RewritePayload(backup, payload =>
        {
            var item = payload["accounts"]![0]!["items"]![0]!;
            var credentials = item["credentials"]!.AsArray();
            var entry = credentials[0]!;
            switch (invalidField)
            {
                case "protection": item["extensions"]![0]!["credProtect"] = 0; break;
                case "userHandle": entry["userHandle"] = Base64Url(new byte[65]); break;
                case "credentialId": entry["credentialId"] = ""; break;
                case "privateKey":
                    using (var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384))
                        entry["key"] = Base64Url(wrongCurve.ExportPkcs8PrivateKey());
                    break;
                case "duplicate": credentials.Add(entry.DeepClone()); break;
                case "version": payload["version"]!["major"] = 2; break;
                case "counterPolicy":
                    item["extensions"]![0]!["signCount"] = 1;
                    item["extensions"]![0]!["disableSignCount"] = true;
                    break;
                case "negativeCounter": item["extensions"]![0]!["signCount"] = -1; break;
                case "metadataId": item["extensions"]![0]!["credentialId"] = "AQ"; break;
                case "duplicateMetadata": item["extensions"]!.AsArray().Add(item["extensions"]![0]!.DeepClone()); break;
                case "base64url": entry["userHandle"] = "AQID="; break;
                case "fidoExtension": entry["fido2Extensions"] = new JsonObject { ["credBlob"] = "AQID" }; break;
            }
        });
        var destination = MemoryManager();
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.ImportPasskeysAsync(malformed, _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    [Fact]
    public async Task Export_UsesCxfStructureAndPreservesNonzeroCounterInNamedExtension()
    {
        using var source = MemoryManager();
        var registration = await Register(source, resident: false);
        await source.IncrementSignCountAsync(registration.CredentialId);
        var encrypted = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var response = JsonNode.Parse(encrypted)!;
        Assert.Equal(new[] { "version", "hpke", "archive", "exporter", "payload" }, response.AsObject().Select(p => p.Key));
        Assert.Equal(0, response["version"]!.GetValue<int>());
        Assert.Equal("base", response["hpke"]!["mode"]!.GetValue<string>());
        Assert.Equal(16, response["hpke"]!["kem"]!.GetValue<int>());
        Assert.Equal(1, response["hpke"]!["kdf"]!.GetValue<int>());
        Assert.Equal(1, response["hpke"]!["aead"]!.GetValue<int>());
        Assert.Equal("deflate", response["archive"]!.GetValue<string>());
        Assert.Equal("P-256", response["hpke"]!["key"]!["crv"]!.GetValue<string>());
        Assert.Equal(5, ReadJwe(response).Split('.').Length);
        RewritePayload(encrypted, payload =>
        {
            Assert.Equal(1, payload["version"]!["major"]!.GetValue<int>());
            Assert.Equal(0, payload["version"]!["minor"]!.GetValue<int>());
            Assert.Equal("VirtualFido", payload["exporterDisplayName"]!.GetValue<string>());
            var account = payload["accounts"]![0]!;
            Assert.Empty(account["collections"]!.AsArray());
            var item = account["items"]![0]!;
            var passkey = item["credentials"]![0]!;
            Assert.Equal("passkey", passkey["type"]!.GetValue<string>());
            Assert.Equal(Base64Url(registration.CredentialId), passkey["credentialId"]!.GetValue<string>());
            Assert.Equal("AQID", passkey["userHandle"]!.GetValue<string>());
            Assert.DoesNotContain("=", passkey["key"]!.GetValue<string>());
            var metadata = item["extensions"]![0]!;
            Assert.Equal(payload["exporterRpId"]!.GetValue<string>() + "/CredentialMetadata", metadata["name"]!.GetValue<string>());
            Assert.Equal(1u, metadata["signCount"]!.GetValue<uint>());
            Assert.False(metadata["isResident"]!.GetValue<bool>());
        });
        using var destination = MemoryManager();
        await destination.ImportPasskeysAsync(encrypted, _identity.Private);
        Assert.Equal(1u, (await destination.FindCredentialAsync(registration.CredentialId, "example.com"))!.SignCount);
        Assert.Equal(2u, await destination.IncrementSignCountAsync(registration.CredentialId));
    }

    [Fact]
    public async Task CxfWithoutVirtualFidoMetadata_KeepsZeroCounterAcrossRestartAndReexport()
    {
        using var source = MemoryManager();
        var registration = await Register(source);
        var encrypted = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var standardPayload = RewritePayload(encrypted, payload =>
        {
            var item = payload["accounts"]![0]!["items"]![0]!.AsObject();
            item.Remove("extensions");
            item["credentials"]!.AsArray().Add(new JsonObject { ["type"] = "future-credential" });
            payload["futureField"] = "ignored";
        });
        using (var destination = FileManager())
            await destination.ImportPasskeysAsync(standardPayload, _identity.Private);
        using (var restarted = FileManager())
        {
            var restored = (await restarted.FindCredentialAsync(registration.CredentialId, "example.com"))!;
            Assert.True(restored.IsResident);
            Assert.Equal(1, restored.CredProtect);
            Assert.Equal(0u, await restarted.IncrementSignCountAsync(registration.CredentialId));
            var reexported = await restarted.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
            using var second = MemoryManager();
            await second.ImportPasskeysAsync(reexported, _identity.Private);
            Assert.Equal(0u, await second.IncrementSignCountAsync(registration.CredentialId));
        }
        using var final = FileManager();
        Assert.Equal(0u, await final.IncrementSignCountAsync(registration.CredentialId));
    }

    [Fact]
    public async Task LegacyFormat_IsRejected()
    {
        using var source = MemoryManager();
        var registration = await Register(source);
        var encrypted = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var envelope = JsonNode.Parse(encrypted)!;
        envelope = new JsonObject { ["format"] = "VirtualFido.PasskeyBackup", ["version"] = 1 };
        using var destination = MemoryManager();
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.ImportPasskeysAsync(
            Encoding.UTF8.GetBytes(envelope.ToJsonString()), _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task ChangedExporter_IsRejectedByHpkeMetadataBinding()
    {
        using var source = MemoryManager();
        var registration = await Register(source);
        var encrypted = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var response = JsonNode.Parse(encrypted)!;
        response["exporter"] = "other.example";
        using var destination = MemoryManager();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => destination.ImportPasskeysAsync(
            Encoding.UTF8.GetBytes(response.ToJsonString()), _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    [Theory]
    [InlineData("mode", "\"auth\"")]
    [InlineData("kem", "32")]
    [InlineData("kdf", "2")]
    [InlineData("aead", "2")]
    [InlineData("key", "null")]
    public async Task UnsupportedHpkeParameters_AreRejected(string field, string json)
    {
        using var source = MemoryManager();
        var registration = await Register(source);
        var encrypted = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var response = JsonNode.Parse(encrypted)!;
        response["hpke"]![field] = JsonNode.Parse(json);
        using var destination = MemoryManager();
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.ImportPasskeysAsync(
            Encoding.UTF8.GetBytes(response.ToJsonString()), _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnexpectedArchiveEntries_AreRejected(bool duplicateIndex)
    {
        using var source = MemoryManager();
        var registration = await Register(source);
        var encrypted = await source.ExportPasskeysAsync(new[] { registration.CredentialId }, _identity.Public);
        var response = JsonNode.Parse(encrypted)!;
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, true))
        {
            using (var index = archive.CreateEntry("CXP-Export/index.jwe").Open())
                index.Write(Encoding.ASCII.GetBytes(ReadJwe(response)));
            archive.CreateEntry(duplicateIndex ? "CXP-Export/index.jwe" : "../unexpected.jwe");
        }
        response["payload"] = Base64Url(buffer.ToArray());
        using var destination = MemoryManager();
        await Assert.ThrowsAsync<InvalidDataException>(() => destination.ImportPasskeysAsync(
            Encoding.UTF8.GetBytes(response.ToJsonString()), _identity.Private));
        Assert.Empty(await destination.FindAllCredentialsAsync());
    }

    [Fact]
    public void RsaRecipient_IsRejectedWithReplacementGuidance()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Old transfer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        Assert.Contains("Create a new transfer certificate", Assert.Throws<InvalidOperationException>(() =>
            PasskeyBackup.ValidateRecipient(certificate)).Message);
    }

    // Construct an authenticated, deliberately invalid payload as any holder of the public
    // recipient certificate could do. Payload validation must be independent of encryption.
    private byte[] RewritePayload(byte[] backup, Action<JsonNode> change)
    {
        var plaintext = CxpTransport.DecryptPayload(backup, _identity.Private);
        byte[] changed = [];
        try
        {
            var payload = JsonNode.Parse(plaintext)!;
            change(payload);
            changed = Encoding.UTF8.GetBytes(payload.ToJsonString());
            return CxpTransport.EncryptPayload(changed, _identity.Public);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(changed);
        }
    }

    private static string ReadJwe(JsonNode response)
    {
        using var buffer = new MemoryStream(CxpTransport.Decode(response["payload"]!.GetValue<string>()));
        using var archive = new ZipArchive(buffer, ZipArchiveMode.Read);
        var entry = Assert.Single(archive.Entries);
        Assert.Equal("CXP-Export/index.jwe", entry.FullName);
        using var reader = new StreamReader(entry.Open(), Encoding.ASCII);
        return reader.ReadToEnd();
    }

    private static void ReplaceJwe(JsonNode response, string jwe)
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, true))
        {
            using var stream = archive.CreateEntry("CXP-Export/index.jwe", CompressionLevel.Optimal).Open();
            stream.Write(Encoding.ASCII.GetBytes(jwe));
        }
        response["payload"] = Base64Url(buffer.ToArray());
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
