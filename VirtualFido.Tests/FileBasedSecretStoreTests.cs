using VFido.SecretManager.FileBasedSecretStore;
using Xunit;

namespace VirtualFido.Tests
{
    public class FileBasedSecretStoreTests : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "vfido-tests-keystore-" + Guid.NewGuid());

        public void Dispose()
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, recursive: true);
        }

        [Fact]
        public void CreateEs256Key_ThenLoadKey_WithSamePassword_RoundTrips()
        {
            var store = new FileBasedSecretStore(_directory, "user", "pass");
            var key = store.CreateEs256Key();

            var reopened = new FileBasedSecretStore(_directory, "user", "pass");
            var loaded = reopened.LoadKey(key.ExportHandle());

            Assert.Equal(key.ExportCosePublicKey(), loaded.ExportCosePublicKey());
        }

        [Fact]
        public void NewStoreInstance_WithWrongPassword_ThrowsImmediatelyOnConstruction()
        {
            new FileBasedSecretStore(_directory, "user", "pass");

            Assert.Throws<InvalidCredentialsException>(() => new FileBasedSecretStore(_directory, "user", "wrong-pass"));
        }

        [Fact]
        public void NewStoreInstance_WithSamePassword_DoesNotThrow()
        {
            new FileBasedSecretStore(_directory, "user", "pass");

            var exception = Record.Exception(() => new FileBasedSecretStore(_directory, "user", "pass"));

            Assert.Null(exception);
        }
    }
}
