using VFido.SecretManager;
using VFido.SecretManager.FileBasedSecretStore;
using Xunit;

namespace VirtualFido.Tests
{
    public class FileBasedCredentialStoreTests : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "vfido-tests-credstore-" + Guid.NewGuid());

        public void Dispose()
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, recursive: true);
        }

        private static StoredCredential NewCredential(byte[]? credentialId = null) => new()
        {
            CredentialId = credentialId ?? Guid.NewGuid().ToByteArray(),
            RpId = "example.com",
            UserId = new byte[] { 1, 2, 3 },
            KeyHandle = new byte[] { 4, 5, 6 },
            IsResident = true,
            UserName = "alice",
            UserDisplayName = "Alice",
        };

        [Fact]
        public void Save_ThenFind_RoundTripsTheCredential()
        {
            var store = new FileBasedCredentialStore(_directory, "user", "pass");
            var credential = NewCredential();

            store.Save(credential);
            var found = store.Find(credential.CredentialId);

            Assert.NotNull(found);
            Assert.Equal(credential.RpId, found!.RpId);
            Assert.Equal(credential.UserId, found.UserId);
            Assert.Equal(credential.UserName, found.UserName);
            Assert.True(found.IsResident);
        }

        [Fact]
        public void Find_UnknownCredentialId_ReturnsNull()
        {
            var store = new FileBasedCredentialStore(_directory, "user", "pass");

            Assert.Null(store.Find(Guid.NewGuid().ToByteArray()));
        }

        [Fact]
        public void FindByRp_ReturnsOnlyMatchingCredentials()
        {
            var store = new FileBasedCredentialStore(_directory, "user", "pass");
            var forExampleCom = NewCredential();
            var forOther = new StoredCredential
            {
                CredentialId = Guid.NewGuid().ToByteArray(),
                RpId = "other.com",
                UserId = new byte[] { 9 },
                KeyHandle = new byte[] { 9 },
            };

            store.Save(forExampleCom);
            store.Save(forOther);

            var results = store.FindByRp("example.com");

            Assert.Single(results);
            Assert.Equal(forExampleCom.CredentialId, results[0].CredentialId);
        }

        [Fact]
        public void NewStoreInstance_WithSameCredentials_CanStillDecryptPreviouslySavedCredential()
        {
            var credential = NewCredential();
            new FileBasedCredentialStore(_directory, "user", "pass").Save(credential);

            var reopened = new FileBasedCredentialStore(_directory, "user", "pass");
            var found = reopened.Find(credential.CredentialId);

            Assert.NotNull(found);
            Assert.Equal(credential.RpId, found!.RpId);
        }

        [Fact]
        public void NewStoreInstance_WithWrongPassword_ThrowsImmediatelyOnConstruction()
        {
            var credential = NewCredential();
            new FileBasedCredentialStore(_directory, "user", "pass").Save(credential);

            Assert.Throws<InvalidCredentialsException>(() => new FileBasedCredentialStore(_directory, "user", "wrong-pass"));
        }

        [Fact]
        public async Task Fido2SecretManager_IncrementSignCountAsync_PersistsAcrossCallsBackedByFileBasedStore()
        {
            // Regression: FileBasedCredentialStore.Find decodes a fresh object from disk every
            // call (unlike InMemoryCredentialStore, which hands back the same live reference), so
            // Fido2SecretManager must explicitly Save() after incrementing or the count silently
            // resets to 1 on every login instead of climbing 1, 2, 3... - which real WebAuthn
            // relying parties reject as a possible cloned authenticator.
            var keys = new FileBasedSecretStore(Path.Combine(_directory, "keys"), "user", "pass");
            var credentials = new FileBasedCredentialStore(_directory, "user", "pass");
            var manager = new Fido2SecretManager(keys, credentials);

            var registration = await manager.CreateCredentialAsync("example.com", new byte[] { 1 }, "alice", "Alice", isResident: true, credProtect: 1);

            var first = await manager.IncrementSignCountAsync(registration.CredentialId);
            var second = await manager.IncrementSignCountAsync(registration.CredentialId);

            Assert.Equal(1u, first);
            Assert.Equal(2u, second);
        }
    }
}
