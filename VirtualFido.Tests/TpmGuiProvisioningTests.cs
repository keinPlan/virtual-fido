using System.Security.Cryptography;
using System.Text;
using VFido.Gui.Configuration;
using VFido.Gui.Services;
using VFido.SecretManager;
using VFido.SecretManager.MemoryBasedSecretStore;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VirtualFido.Tests;

public sealed class TpmGuiProvisioningTests : IClassFixture<TpmMasterFixture>, IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "vfido-tpm-gui-tests-" + Guid.NewGuid().ToString("N"));
    private readonly TpmMasterFixture _fixture;
    public TpmGuiProvisioningTests(TpmMasterFixture fixture) { _fixture = fixture; Directory.CreateDirectory(_root); }
    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
    private string WriteRecovery()
    {
        var path = Path.Combine(_root, "master.pfx");
        File.WriteAllBytes(path, _fixture.Pfx);
        return path;
    }

    [Fact]
    public void Configuration_RoundTripsOnlyNonSecretTpmSettings()
    {
        var configs = new StickConfigStore(_root);
        configs.Create("TPM", "VFIDO-TPM", new TpmSecretManagerConfig { Username = "alice", MasterName = Convert.ToHexString(_fixture.Master.Name) });
        var loaded = Assert.Single(configs.LoadAll());
        var settings = Assert.IsType<TpmSecretManagerConfig>(loaded.SecretManager);
        Assert.Equal("alice", settings.Username);
        Assert.Equal(Convert.ToHexString(_fixture.Master.Name), settings.MasterName);
        var json = File.ReadAllText(Path.Combine(configs.GetStickDirectory("TPM"), "config.json"));
        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(".pfx", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"tpm\"", json);
    }

    [Fact]
    public void BadRecoveryPassword_DoesNotCreateConfiguration()
    {
        var configs = new StickConfigStore(Path.Combine(_root, "sticks"));
        Assert.Throws<CryptographicException>(() => TpmStickProvisioning.Create(configs, "TPM", "serial", "alice", "metadata password", WriteRecovery(), "wrong password"));
        Assert.Empty(configs.LoadAll());
        Assert.False(Directory.Exists(configs.GetStickDirectory("TPM")));
    }

    [Fact]
    public void IncompleteMetadataBackup_IsRejectedWithoutCreatingNewSalt()
    {
        var configs = new StickConfigStore(Path.Combine(_root, "sticks"));
        var config = configs.Create("TPM", "serial", new TpmSecretManagerConfig
        { Username = "alice", MasterName = Convert.ToHexString(_fixture.Master.Name) });
        Assert.Throws<InvalidDataException>(() => TpmStickProvisioning.Open(configs, config, "alice", "password"));
        Assert.False(File.Exists(Path.Combine(configs.GetStickDirectory("TPM"), "salt.bin")));
    }
    [TpmIntegrationFact]
    public async Task SetupReconnectAndRecovery_PreserveCredentialsAndLockedPin()
    {
        var configs = new StickConfigStore(Path.Combine(_root, "sticks"));
        var pfx = WriteRecovery();
        var config = TpmStickProvisioning.Create(configs, "TPM", "serial", "alice", "metadata password", pfx, TpmMasterFixture.Password);
        byte[] id;
        var data = Encoding.UTF8.GetBytes("GUI TPM reconnect");
        var hash = RandomNumberGenerator.GetBytes(16);
        using (var manager = TpmStickProvisioning.Open(configs, config, "alice", "metadata password"))
        {
            Assert.True(manager.SupportsPasskeyImport);
            Assert.False(manager.SupportsPasskeyBackup);
            Assert.Empty(await manager.FindAllCredentialsAsync()); // provisioning probe was removed
            var credential = await manager.CreateCredentialAsync("example.com", new byte[] { 1 }, "alice", "Alice", true, 1);
            id = credential.CredentialId;
            Assert.NotEmpty(await manager.SignAsync(id, data));
            Assert.Equal(1u, await manager.IncrementSignCountAsync(id));
            await manager.SavePinStateAsync(new PinState(hash, 0));
        }
        Assert.Throws<VFido.SecretManager.FileBasedSecretStore.InvalidCredentialsException>(() => TpmStickProvisioning.Open(configs, config, "alice", "wrong metadata password"));
        var masterPath = Path.Combine(configs.GetKeyStoreDirectory(config.Name), "master.json");
        var originalMaster = File.ReadAllBytes(masterPath);
        var credentialsBefore = Directory.GetFiles(configs.GetKeyStoreDirectory(config.Name), "*.tpmkey")
            .ToDictionary(path => Path.GetFileName(path)!, File.ReadAllBytes);
        var modifiedSeed = _fixture.Seed.ToArray();
        modifiedSeed[0] ^= 1;
        using (var wrong = TpmMasterKey.FromExternal(_fixture.Rsa, modifiedSeed))
            File.WriteAllBytes(Path.Combine(_root, "wrong-seed.pfx"), wrong.ExportPfx(TpmMasterFixture.Password));
        Assert.Throws<Tpm2Lib.TpmException>(() => TpmStickProvisioning.Restore(configs, config, Path.Combine(_root, "wrong-seed.pfx"), TpmMasterFixture.Password));
        Assert.Equal(originalMaster, File.ReadAllBytes(masterPath));
        Assert.Empty(Directory.GetDirectories(configs.GetKeyStoreDirectory(config.Name), ".restore-*"));
        using (var different = TpmMasterKey.Generate())
            File.WriteAllBytes(Path.Combine(_root, "different.pfx"), different.ExportPfx(TpmMasterFixture.Password));
        Assert.Throws<CryptographicException>(() => TpmStickProvisioning.Restore(configs, config, Path.Combine(_root, "different.pfx"), TpmMasterFixture.Password));
        Assert.Equal(originalMaster, File.ReadAllBytes(masterPath));
        // An unreadable or foreign local master can be replaced without touching credential files.
        File.WriteAllText(masterPath, "broken local master");
        TpmStickProvisioning.Restore(configs, config, pfx, TpmMasterFixture.Password);
        foreach (var (filename, bytes) in credentialsBefore)
            Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(configs.GetKeyStoreDirectory(config.Name), filename!)));
        using (var reopened = TpmStickProvisioning.Open(configs, config, "alice", "metadata password"))
        {
            Assert.Single(await reopened.FindAllCredentialsAsync());
            Assert.Equal(1u, (await reopened.FindAllCredentialsAsync())[0].SignCount);
            var pin = await reopened.LoadPinStateAsync();
            Assert.NotNull(pin);
            Assert.Equal(0, pin.Retries);
            Assert.Equal(hash, pin.PinHash);
            Assert.NotEmpty(await reopened.SignAsync(id, data));
            reopened.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => reopened.SignAsync(id, data));
        }
        Assert.True(File.Exists(pfx));
        Assert.DoesNotContain(Directory.GetFiles(configs.GetStickDirectory(config.Name), "*", SearchOption.AllDirectories), path => path.EndsWith(".pfx"));
    }

    [TpmIntegrationFact]
    public void SetupFailure_RollsBackOnlyNewStickAndPreservesRecovery()
    {
        var configs = new FailingMetadataConfigStore(Path.Combine(_root, "sticks"), Path.Combine(_root, "blocker"));
        File.WriteAllText(configs.Blocker, "keep me");
        var pfx = WriteRecovery();
        Assert.Throws<IOException>(() => TpmStickProvisioning.Create(configs, "TPM", "serial", "alice", "metadata password", pfx, TpmMasterFixture.Password));
        Assert.Empty(configs.LoadAll());
        Assert.False(Directory.Exists(configs.GetStickDirectory("TPM")));
        Assert.Equal("keep me", File.ReadAllText(configs.Blocker));
        Assert.True(File.Exists(pfx));
    }

    private sealed class FailingMetadataConfigStore : IStickConfigStore
    {
        private readonly StickConfigStore _inner;
        public string Blocker { get; }
        public FailingMetadataConfigStore(string root, string blocker) { _inner = new(root); Blocker = blocker; }
        public IReadOnlyList<StickConfig> LoadAll() => _inner.LoadAll();
        public StickConfig Create(string name, string serialNumber, SecretManagerConfig secretManager) => _inner.Create(name, serialNumber, secretManager);
        public void Save(StickConfig config) => _inner.Save(config);
        public void Delete(string name) => _inner.Delete(name);
        public string GetStickDirectory(string name) => _inner.GetStickDirectory(name);
        public string GetKeyStoreDirectory(string name) => _inner.GetKeyStoreDirectory(name);
        public string GetCredentialStoreDirectory(string name) => Blocker;
        public string GetAttestationCertificateDirectory(string name) => _inner.GetAttestationCertificateDirectory(name);
    }
}

public sealed class SecretManagerOwnershipTests
{
    [Fact]
    public async Task OwningManager_DisposesBackendOnceAndRejectsFurtherOperations()
    {
        var keys = new DisposableStore();
        var manager = new Fido2SecretManager(keys, new InMemoryCredentialStore(), ownsKeyStore: true);
        manager.Dispose(); manager.Dispose();
        Assert.Equal(1, keys.DisposeCount);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => manager.FindAllCredentialsAsync());
    }

    [Fact]
    public void DefaultManager_LeavesCallerOwnedBackendAlive()
    {
        var keys = new DisposableStore();
        using (var manager = new Fido2SecretManager(keys, new InMemoryCredentialStore())) { }
        Assert.Equal(0, keys.DisposeCount);
    }

    private sealed class DisposableStore : IKeyStore, IDisposable
    {
        private readonly MemoryBasedSecretStore _inner = new();
        public int DisposeCount { get; private set; }
        public byte[] Aaguid => _inner.Aaguid;
        public ISigningKey CreateEs256Key() => _inner.CreateEs256Key();
        public ISigningKey LoadKey(byte[] handle) => _inner.LoadKey(handle);
        public void DeleteKey(byte[] handle) => _inner.DeleteKey(handle);
        public AttestationCertificate GetOrCreateAttestationCertificate() => _inner.GetOrCreateAttestationCertificate();
        public void Dispose() => DisposeCount++;
    }
}
