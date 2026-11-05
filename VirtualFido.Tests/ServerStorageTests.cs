using Microsoft.AspNetCore.DataProtection;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;

namespace VirtualFido.Tests;

public class ServerStorageTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MemoryStoreSurvivesSessionsButNotResolverRestart(bool passwordless)
    {
        var root = Path.Combine(Path.GetTempPath(), "vfido-storage-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            var options = new MtlsBasedSecretStoreServerOptions
            {
                ServerCertificatePath = "unused", ClientCaCertificatePath = "unused",
                SecretsRootPath = root, StorageProvider = ServerStorageProvider.Memory
            };
            var protector = new UserKeyProtector(DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(root, "protection"))));
            using var resolver = new UserDirectoryResolver(options, protector);
            var manager = passwordless ? resolver.BuildPasswordlessManager("alice")
                : resolver.BuildManagerFromPassword("alice", "password");
            var credential = await manager.CreateCredentialAsync("example.com", [1], "alice", "Alice", true, 1);
            var secondSession = passwordless ? resolver.BuildPasswordlessManager("alice")
                : resolver.BuildManagerFromPassword("alice", "password");
            Assert.True(await secondSession.CredentialExistsAsync(credential.CredentialId, "example.com"));
            Assert.NotEmpty(await secondSession.SignAsync(credential.CredentialId, [1, 2, 3]));
            Assert.False(await resolver.BuildPasswordlessManager("bob").CredentialExistsAsync(credential.CredentialId, "example.com"));
            if (!passwordless)
                Assert.Throws<InvalidCredentialsException>(() => resolver.BuildManagerFromPassword("alice", "wrong"));
            Assert.Empty(Directory.EnumerateFiles(Path.Combine(root, "alice"), "*.cred", SearchOption.AllDirectories));
            Assert.DoesNotContain(Directory.EnumerateFiles(Path.Combine(root, "alice"), "*.key", SearchOption.AllDirectories),
                path => Path.GetFileName(path) != "wrapped.key");
            using var restarted = new UserDirectoryResolver(options, protector);
            var afterRestart = passwordless ? restarted.BuildPasswordlessManager("alice")
                : restarted.BuildManagerFromPassword("alice", "password");
            Assert.False(await afterRestart.CredentialExistsAsync(credential.CredentialId, "example.com"));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void UndefinedProviderIsRejected()
    {
        var options = new MtlsBasedSecretStoreServerOptions
        {
            ServerCertificatePath = "unused", ClientCaCertificatePath = "unused",
            StorageProvider = (ServerStorageProvider)999
        };
        Assert.Throws<InvalidOperationException>(() => options.ResolvePaths(AppContext.BaseDirectory));
    }
}
