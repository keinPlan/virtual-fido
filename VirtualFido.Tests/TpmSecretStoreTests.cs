using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tpm2Lib;
using VFido.SecretManager;
using VFido.SecretManager.MemoryBasedSecretStore;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VirtualFido.Tests;

public sealed class TpmMasterFixture : IDisposable
{
    public const string Password = "portable master test password";
    public RSA Rsa { get; } = RSA.Create(2048);
    public byte[] Seed { get; } = RandomNumberGenerator.GetBytes(32);
    public TpmMasterKey Master { get; }
    public byte[] Pfx { get; }
    public TpmMasterFixture()
    {
        Master = TpmMasterKey.FromExternal(Rsa, Seed);
        Pfx = Master.ExportPfx(Password);
    }
    public void Dispose() { Master.Dispose(); Rsa.Dispose(); CryptographicOperations.ZeroMemory(Seed); }
}

public sealed class TpmMasterKeyTests : IClassFixture<TpmMasterFixture>
{
    private readonly TpmMasterFixture _fixture;
    public TpmMasterKeyTests(TpmMasterFixture fixture) => _fixture = fixture;

    [Fact]
    public void Pfx_RoundTripPreservesMasterIdentityAndSeed()
    {
        using var restored = TpmMasterKey.ImportPfx(_fixture.Pfx, TpmMasterFixture.Password);
        Assert.Equal(_fixture.Master.PublicArea, restored.PublicArea);
        Assert.Equal(_fixture.Master.Name, restored.Name);
        var info = Pkcs12Info.Decode(_fixture.Pfx, out var consumed);
        Assert.Equal(_fixture.Pfx.Length, consumed);
        Assert.True(info.VerifyMac(TpmMasterFixture.Password));
        var safe = Assert.Single(info.AuthenticatedSafe);
        Assert.Equal(Pkcs12ConfidentialityMode.Password, safe.ConfidentialityMode);
        safe.Decrypt(TpmMasterFixture.Password);
        var bags = safe.GetBags().ToList();
        Assert.Single(bags.OfType<Pkcs12ShroudedKeyBag>());
        var secret = Assert.Single(bags.OfType<Pkcs12SecretBag>());
        var reader = new AsnReader(secret.SecretValue, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        Assert.Equal(1, sequence.ReadInteger());
        Assert.Equal(_fixture.Seed, sequence.ReadOctetString());
        Assert.Equal(_fixture.Master.PublicArea, sequence.ReadOctetString());
        sequence.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
        using var cert = Assert.Single(bags.OfType<Pkcs12CertBag>()).GetCertificate();
        Assert.DoesNotContain(cert.Extensions.Cast<X509Extension>(), e => e.RawData.AsSpan().IndexOf(_fixture.Seed) >= 0);
        Assert.Equal(-1, _fixture.Pfx.AsSpan().IndexOf(_fixture.Seed));
    }

    [Fact]
    public void Pfx_RejectsWrongPasswordAndTampering()
    {
        Assert.Throws<CryptographicException>(() => TpmMasterKey.ImportPfx(_fixture.Pfx, "wrong"));
        var altered = _fixture.Pfx.ToArray();
        altered[altered.Length / 2] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => TpmMasterKey.ImportPfx(altered, TpmMasterFixture.Password));
    }

    [Fact]
    public void Pfx_RejectsTrailingData()
    {
        Assert.Throws<CryptographicException>(() => TpmMasterKey.ImportPfx(_fixture.Pfx.Concat(new byte[] { 0 }).ToArray(), TpmMasterFixture.Password));
    }

    [Fact]
    public void Pfx_RejectsOrdinaryPfxWithoutSeedAndTemplate()
    {
        var request = new CertificateRequest("CN=ordinary", _fixture.Rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var contents = new Pkcs12SafeContents();
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000);
        contents.AddCertificate(cert);
        contents.AddShroudedKey(_fixture.Rsa, TpmMasterFixture.Password, pbe);
        var builder = new Pkcs12Builder();
        builder.AddSafeContentsEncrypted(contents, TpmMasterFixture.Password, pbe);
        builder.SealWithMac(TpmMasterFixture.Password, HashAlgorithmName.SHA256, 1000);
        Assert.Throws<InvalidDataException>(() => TpmMasterKey.ImportPfx(builder.Encode(), TpmMasterFixture.Password));
    }

    [Theory]
    [InlineData(0)] [InlineData(16)] [InlineData(31)] [InlineData(33)]
    public void ExternalMaster_RequiresSha256SizedSeed(int size) =>
        Assert.Throws<ArgumentException>(() => TpmMasterKey.FromExternal(_fixture.Rsa, new byte[size]));

    [Fact]
    public void ExternalMaster_CopiesCallerSecrets()
    {
        var seed = _fixture.Seed.ToArray();
        using var master = TpmMasterKey.FromExternal(_fixture.Rsa, seed);
        CryptographicOperations.ZeroMemory(seed);
        using var restored = TpmMasterKey.ImportPfx(master.ExportPfx(TpmMasterFixture.Password), TpmMasterFixture.Password);
        Assert.Equal(_fixture.Master.PublicArea, restored.PublicArea);
        Assert.Equal(_fixture.Master.Name, restored.Name);
        // Caller RSA is still usable after the copied master is disposed.
        master.Dispose();
        Assert.NotEmpty(_fixture.Rsa.SignData(new byte[] { 1 }, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ObjectDisposedException>(() => master.ExportPfx(TpmMasterFixture.Password));
    }

    [Theory]
    [InlineData("")] [InlineData(" ")]
    public void Pfx_RequiresPassword(string password) =>
        Assert.ThrowsAny<ArgumentException>(() => _fixture.Master.ExportPfx(password));

    [Fact]
    public async Task ImportOnlyCapability_DoesNotPermitPrivateKeyExport()
    {
        var keys = new ImportOnlyStore();
        var manager = new Fido2SecretManager(keys, new InMemoryCredentialStore());
        Assert.False(manager.SupportsPasskeyBackup);
        Assert.True(manager.SupportsPasskeyImport);
        var identity = PasskeyBackup.CreateIdentity(TpmMasterFixture.Password);
        using var cert = new X509Certificate2(identity.PasswordProtectedPfx, TpmMasterFixture.Password, X509KeyStorageFlags.EphemeralKeySet);
        var source = new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore());
        var credential = await source.CreateCredentialAsync("example.com", new byte[] { 1 }, "alice", "Alice", true, 1);
        var backup = await source.ExportPasskeysAsync(new[] { credential.CredentialId }, cert);
        Assert.Equal(0, (await manager.PreviewPasskeyImportAsync(backup, cert)).AlreadyPresent);
        Assert.Equal(1, (await manager.ImportPasskeysAsync(backup, cert)).Imported);
        await Assert.ThrowsAsync<NotSupportedException>(() => manager.ExportPasskeysAsync(new[] { credential.CredentialId }, cert));
    }

    private sealed class ImportOnlyStore : IKeyStore, ICredentialKeyImporter
    {
        private readonly MemoryBasedSecretStore _inner = new();
        public byte[] Aaguid => _inner.Aaguid;
        public ISigningKey CreateEs256Key() => _inner.CreateEs256Key();
        public ISigningKey LoadKey(byte[] handle) => _inner.LoadKey(handle);
        public void DeleteKey(byte[] handle) => _inner.DeleteKey(handle);
        public AttestationCertificate GetOrCreateAttestationCertificate() => _inner.GetOrCreateAttestationCertificate();
        public byte[] ImportPkcs8(byte[] privateKey) => _inner.ImportPkcs8(privateKey);
    }
}

public sealed class TpmIntegrationFactAttribute : FactAttribute
{
    public TpmIntegrationFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("VFIDO_TEST_TPM") != "1")
            Skip = "Set VFIDO_TEST_TPM=1 to provision transient objects and test the local Windows TPM.";
    }
}

public sealed class TpmSecretStoreIntegrationTests
{
    [TpmIntegrationFact]
    public void ImportedKey_SignsReloadsAndRecoversUnderRestoredMaster()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vfido-tpm-test-" + Guid.NewGuid());
        var second = Path.Combine(directory, "restored");
        var wrong = Path.Combine(directory, "wrong-seed");
        try
        {
            using var rsa = RSA.Create(2048);
            var seed = RandomNumberGenerator.GetBytes(32);
            using var master = TpmMasterKey.FromExternal(rsa, seed);
            using var restored = TpmMasterKey.ImportPfx(master.ExportPfx("test recovery password"), "test recovery password");
            using var credential = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var pkcs8 = credential.ExportPkcs8PrivateKey();
            var data = Encoding.UTF8.GetBytes("TPM-only signing test");
            byte[] handle, wrapped;
            TpmBasedSecretStore.Provision(directory, master);
            Assert.Throws<IOException>(() => TpmBasedSecretStore.Provision(directory, master));
            using (var store = new TpmBasedSecretStore(directory))
            {
                handle = store.ImportPkcs8(pkcs8);
                wrapped = store.ExportWrappedKey(handle);
                Assert.Equal(-1, wrapped.AsSpan().IndexOf(pkcs8));
                Assert.True(credential.VerifyData(data, store.LoadKey(handle).Sign(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
                Assert.Throws<InvalidDataException>(() => store.LoadKey(new byte[1]));
                using var invalid = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                Assert.Throws<InvalidDataException>(() => store.ImportPkcs8(invalid.ExportPkcs8PrivateKey()));
                var attestation = store.GetOrCreateAttestationCertificate();
                using var leaf = new X509Certificate2(attestation.CertificateChainDer[0]);
                using var leafKey = leaf.GetECDsaPublicKey()!;
                Assert.True(leafKey.VerifyData(data, store.LoadKey(attestation.KeyHandle).Sign(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
            }
            using (var reopened = new TpmBasedSecretStore(directory))
                Assert.True(credential.VerifyData(data, reopened.LoadKey(handle).Sign(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
            AssertDuplicationDenied(directory, wrapped);
            TpmBasedSecretStore.Provision(second, restored);
            using (var recovered = new TpmBasedSecretStore(second))
            {
                var imported = recovered.ImportWrappedKey(wrapped);
                Assert.Equal(wrapped, recovered.ExportWrappedKey(imported));
                Assert.True(credential.VerifyData(data, recovered.LoadKey(imported).Sign(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
                var altered = JsonNode.Parse(wrapped)!.AsObject();
                var privateBlob = Convert.FromBase64String(altered["Private"]!.GetValue<string>());
                privateBlob[^1] ^= 1;
                altered["Private"] = Convert.ToBase64String(privateBlob);
                Assert.Throws<TpmException>(() => recovered.ImportWrappedKey(JsonSerializer.SerializeToUtf8Bytes(altered)));
                recovered.DeleteKey(imported);
                Assert.Throws<FileNotFoundException>(() => recovered.LoadKey(imported));
            }
            // Same public RSA identity, different storage seed: child blobs must fail integrity.
            seed[0] ^= 1;
            using var wrongMaster = TpmMasterKey.FromExternal(rsa, seed);
            TpmBasedSecretStore.Provision(wrong, wrongMaster);
            using var wrongStore = new TpmBasedSecretStore(wrong);
            Assert.Throws<TpmException>(() => wrongStore.ImportWrappedKey(wrapped));
            CryptographicOperations.ZeroMemory(pkcs8);
            CryptographicOperations.ZeroMemory(seed);
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }
    [TpmIntegrationFact]
    public void GeneratedKey_SignsReloadsAndRecoversUnderRestoredMaster()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vfido-generated-tpm-" + Guid.NewGuid());
        var restoredDirectory = Path.Combine(directory, "restored");
        try
        {
            using var master = TpmMasterKey.Generate();
            using var restored = TpmMasterKey.ImportPfx(master.ExportPfx("test recovery password"), "test recovery password");
            TpmBasedSecretStore.Provision(directory, master);
            var data = Encoding.UTF8.GetBytes("TPM-generated credential");
            byte[] handle, wrapped;
            ECParameters parameters;
            using (var store = new TpmBasedSecretStore(directory))
            {
                var key = store.CreateEs256Key();
                handle = key.ExportHandle();
                wrapped = store.ExportWrappedKey(handle);
                using var json = JsonDocument.Parse(wrapped);
                var pub = Marshaller.FromTpmRepresentation<TpmPublic>(json.RootElement.GetProperty("Public").GetBytesFromBase64());
                Assert.True(pub.objectAttributes.HasFlag(ObjectAttr.SensitiveDataOrigin));
                Assert.Equal((ObjectAttr)0, pub.objectAttributes & (ObjectAttr.FixedTPM | ObjectAttr.FixedParent));
                var point = (EccPoint)pub.unique;
                parameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = PadCoordinate(point.x), Y = PadCoordinate(point.y) }
                };
                using var verifier = ECDsa.Create(parameters);
                Assert.True(verifier.VerifyData(data, key.Sign(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
            }
            using var publicKey = ECDsa.Create(parameters);
            using (var reopened = new TpmBasedSecretStore(directory))
                Assert.True(publicKey.VerifyData(data, reopened.LoadKey(handle).Sign(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
            AssertDuplicationDenied(directory, wrapped);
            TpmBasedSecretStore.Provision(restoredDirectory, restored);
            using var recovered = new TpmBasedSecretStore(restoredDirectory);
            var recoveredHandle = recovered.ImportWrappedKey(wrapped);
            Assert.True(publicKey.VerifyData(data, recovered.LoadKey(recoveredHandle).Sign(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }

    private static byte[] PadCoordinate(byte[] coordinate)
    {
        var padded = new byte[32];
        coordinate.CopyTo(padded, 32 - coordinate.Length);
        return padded;
    }
    private static void AssertDuplicationDenied(string directory, byte[] wrapped)
    {
        using var local = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(directory, "master.json")));
        using var child = JsonDocument.Parse(wrapped);
        var masterPublic = Marshaller.FromTpmRepresentation<TpmPublic>(local.RootElement.GetProperty("Public").GetBytesFromBase64());
        var template = masterPublic.Copy();
        template.objectAttributes |= ObjectAttr.FixedTPM | ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin;
        template.unique = new Tpm2bPublicKeyRsa(Array.Empty<byte>());
        var device = new TbsDevice();
        device.Connect();
        using var tpm = new Tpm2(device);
        var primary = tpm.CreatePrimary(new TpmHandle(TpmRh.Owner), new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
            template, Array.Empty<byte>(), Array.Empty<PcrSelection>(), out _, out _, out _, out _);
        try
        {
            var master = tpm.Load(primary, new TpmPrivate(local.RootElement.GetProperty("Private").GetBytesFromBase64()), masterPublic);
            try
            {
                var credential = tpm.Load(master, new TpmPrivate(child.RootElement.GetProperty("Private").GetBytesFromBase64()),
                    Marshaller.FromTpmRepresentation<TpmPublic>(child.RootElement.GetProperty("Public").GetBytesFromBase64()));
                try
                {
                    // Neither object permits password authorization for the ADMIN role.
                    Assert.Throws<TpmException>(() => tpm.Duplicate(credential, new TpmHandle(TpmRh.Null), Array.Empty<byte>(), new SymDefObject(), out _, out _));
                    Assert.Throws<TpmException>(() => tpm.Duplicate(master, new TpmHandle(TpmRh.Null), Array.Empty<byte>(), new SymDefObject(), out _, out _));
                }
                finally { tpm.FlushContext(credential); }
            }
            finally { tpm.FlushContext(master); }
        }
        finally { tpm.FlushContext(primary); }
    }}


