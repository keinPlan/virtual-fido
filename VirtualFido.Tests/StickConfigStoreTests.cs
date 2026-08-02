using VFido.Core.Device.Ctap2.Authenticator.Pin;
using VFido.Gui.Configuration;
using Xunit;

namespace VirtualFido.Tests
{
    public class StickConfigStoreTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "vfido-tests-configstore-" + Guid.NewGuid());

        public void Dispose()
        {
            if (Directory.Exists(_root))
                Directory.Delete(_root, recursive: true);
        }

        [Fact]
        public void LoadAll_OnFreshRoot_ReturnsEmptyList()
        {
            var store = new StickConfigStore(_root);

            Assert.Empty(store.LoadAll());
        }

        [Fact]
        public void Create_ThenLoadAll_RoundTripsAMemoryBackedStick()
        {
            var store = new StickConfigStore(_root);

            var created = store.Create("My Stick", Guid.NewGuid(), "VFIDO-0001", new MemorySecretManagerConfig(), PinUsagePreference.Always);

            var loaded = Assert.Single(store.LoadAll());
            Assert.Equal(created.Id, loaded.Id);
            Assert.Equal("My Stick", loaded.Name);
            Assert.Equal("VFIDO-0001", loaded.SerialNumberIdentifier);
            Assert.Equal(created.Aaguid, loaded.Aaguid);
            Assert.Equal(PinUsagePreference.Always, loaded.PinUsage);
            Assert.IsType<MemorySecretManagerConfig>(loaded.SecretManager);
        }

        [Fact]
        public void Create_ThenLoadAll_RoundTripsAFileBackedStickWithoutPersistingAPassword()
        {
            var store = new StickConfigStore(_root);

            store.Create("File stick", Guid.NewGuid(), "VFIDO-0002",
                new FileSecretManagerConfig { Username = "alice" }, PinUsagePreference.Prefer);

            var loaded = Assert.Single(store.LoadAll());
            var fileConfig = Assert.IsType<FileSecretManagerConfig>(loaded.SecretManager);
            Assert.Equal("alice", fileConfig.Username);

            var json = File.ReadAllText(Path.Combine(store.GetStickDirectory(loaded.Id), "config.json"));
            Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Create_ThenLoadAll_RoundTripsAnMtlsBackedStick()
        {
            var store = new StickConfigStore(_root);

            store.Create("Mtls stick", Guid.NewGuid(), "VFIDO-0003", new MtlsSecretManagerConfig
            {
                ServerBaseAddress = new Uri("https://secrets.example.internal:5443"),
                Username = "bob",
                ClientCertificatePath = "client.pfx",
                ServerCaCertificatePath = "ca.crt",
            }, PinUsagePreference.Avoid);

            var loaded = Assert.Single(store.LoadAll());
            var mtlsConfig = Assert.IsType<MtlsSecretManagerConfig>(loaded.SecretManager);
            Assert.Equal("https://secrets.example.internal:5443/", mtlsConfig.ServerBaseAddress.ToString());
            Assert.Equal("bob", mtlsConfig.Username);
            Assert.Equal("client.pfx", mtlsConfig.ClientCertificatePath);
            Assert.Equal("ca.crt", mtlsConfig.ServerCaCertificatePath);
        }

        [Fact]
        public void LoadAll_SkipsACorruptStickFolderButStillReturnsTheOthers()
        {
            var store = new StickConfigStore(_root);
            store.Create("Good stick", Guid.NewGuid(), "VFIDO-0004", new MemorySecretManagerConfig(), PinUsagePreference.Prefer);

            var corruptDir = Path.Combine(_root, Guid.NewGuid().ToString());
            Directory.CreateDirectory(corruptDir);
            File.WriteAllText(Path.Combine(corruptDir, "config.json"), "{ not valid json");

            var loaded = store.LoadAll();

            Assert.Single(loaded);
            Assert.Equal("Good stick", loaded[0].Name);
        }

        [Fact]
        public void GetKeyStoreDirectory_And_GetCredentialStoreDirectory_AreNestedUnderTheStickDirectory()
        {
            var store = new StickConfigStore(_root);
            var id = Guid.NewGuid();

            var stickDir = store.GetStickDirectory(id);
            Assert.StartsWith(stickDir, store.GetKeyStoreDirectory(id));
            Assert.StartsWith(stickDir, store.GetCredentialStoreDirectory(id));
            Assert.NotEqual(store.GetKeyStoreDirectory(id), store.GetCredentialStoreDirectory(id));
        }

        [Fact]
        public void Delete_RemovesTheStickFolder()
        {
            var store = new StickConfigStore(_root);
            var created = store.Create("Doomed stick", Guid.NewGuid(), "VFIDO-0005", new MemorySecretManagerConfig(), PinUsagePreference.Prefer);

            store.Delete(created.Id);

            Assert.Empty(store.LoadAll());
            Assert.False(Directory.Exists(store.GetStickDirectory(created.Id)));
        }
    }
}
