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

            var created = store.Create("MyStick", "VFIDO-0001", new MemorySecretManagerConfig());

            var loaded = Assert.Single(store.LoadAll());
            Assert.Equal(created.Name, loaded.Name);
            Assert.Equal("MyStick", loaded.Name);
            Assert.Equal("VFIDO-0001", loaded.SerialNumberIdentifier);
            Assert.IsType<MemorySecretManagerConfig>(loaded.SecretManager);
        }

        [Fact]
        public void Create_ThenLoadAll_RoundTripsAFileBackedStickWithoutPersistingAPassword()
        {
            var store = new StickConfigStore(_root);

            store.Create("FileStick", "VFIDO-0002",
                new FileSecretManagerConfig { Username = "alice" });

            var loaded = Assert.Single(store.LoadAll());
            var fileConfig = Assert.IsType<FileSecretManagerConfig>(loaded.SecretManager);
            Assert.Equal("alice", fileConfig.Username);

            var json = File.ReadAllText(Path.Combine(store.GetStickDirectory(loaded.Name), "config.json"));
            Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Create_ThenLoadAll_RoundTripsAnMtlsBackedStick()
        {
            var store = new StickConfigStore(_root);

            store.Create("MtlsStick", "VFIDO-0003", new MtlsSecretManagerConfig
            {
                ServerBaseAddress = new Uri("https://secrets.example.internal:5443"),
                Username = "bob",
                ClientCertificatePath = "client.pfx",
                ServerCaCertificatePath = "ca.crt",
            });

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
            store.Create("GoodStick", "VFIDO-0004", new MemorySecretManagerConfig());

            var corruptDir = Path.Combine(_root, Guid.NewGuid().ToString());
            Directory.CreateDirectory(corruptDir);
            File.WriteAllText(Path.Combine(corruptDir, "config.json"), "{ not valid json");

            var loaded = store.LoadAll();

            Assert.Single(loaded);
            Assert.Equal("GoodStick", loaded[0].Name);
        }

        [Fact]
        public void GetKeyStoreDirectory_And_GetCredentialStoreDirectory_AreNestedUnderTheStickDirectory()
        {
            var store = new StickConfigStore(_root);
            const string name = "SomeStick";

            var stickDir = store.GetStickDirectory(name);
            Assert.StartsWith(stickDir, store.GetKeyStoreDirectory(name));
            Assert.StartsWith(stickDir, store.GetCredentialStoreDirectory(name));
            Assert.NotEqual(store.GetKeyStoreDirectory(name), store.GetCredentialStoreDirectory(name));
        }

        [Fact]
        public void Delete_RemovesTheStickFolder()
        {
            var store = new StickConfigStore(_root);
            var created = store.Create("DoomedStick", "VFIDO-0005", new MemorySecretManagerConfig());

            store.Delete(created.Name);

            Assert.Empty(store.LoadAll());
            Assert.False(Directory.Exists(store.GetStickDirectory(created.Name)));
        }

        [Theory]
        [InlineData("")]
        [InlineData("has space")]
        [InlineData("has/slash")]
        [InlineData("has\\backslash")]
        [InlineData("this-name-is-way-too-long-for-a-folder-32")]
        public void Create_RejectsAnInvalidName(string name)
        {
            var store = new StickConfigStore(_root);

            Assert.Throws<ArgumentException>(() => store.Create(name, "VFIDO-0006", new MemorySecretManagerConfig()));
        }

        [Fact]
        public void Create_RejectsADuplicateName()
        {
            var store = new StickConfigStore(_root);
            store.Create("Duplicate", "VFIDO-0007", new MemorySecretManagerConfig());

            Assert.Throws<ArgumentException>(() => store.Create("Duplicate", "VFIDO-0008", new MemorySecretManagerConfig()));
        }

        [Fact]
        public void Create_AcceptsTheMaximumLength32CharacterName()
        {
            var store = new StickConfigStore(_root);
            var name = new string('a', 32);

            var created = store.Create(name, "VFIDO-0009", new MemorySecretManagerConfig());

            Assert.Equal(name, created.Name);
        }
    }
}
