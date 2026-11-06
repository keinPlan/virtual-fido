using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography.X509Certificates;
using VFido.SecretManager.MtlsBasedSecretStoreServer;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VirtualFido.Tests;

public class ServerTpmMasterTests
{
    [Fact]
    public void CopiesMasterAndAuthorizationWithoutCopyingRecoveryAndCleansOnlyTemporaryExport()
    {
        var root = Path.Combine(Path.GetTempPath(), "vfido-template-" + Guid.NewGuid());
        var options = new MtlsBasedSecretStoreServerOptions
        {
            PkiRootPath = Path.Combine(root, "pki"), SecretsRootPath = Path.Combine(root, "users"),
            StorageProvider = ServerStorageProvider.Tpm
        };
        try
        {
            new CaManager(options.PkiRootPath).EnsureMasterProtectionCertificate();
            var template = ServerTpmMaster.DirectoryPath(options);
            Directory.CreateDirectory(template);
            File.WriteAllText(Path.Combine(template, "master.json"), "TPM-wrapped master");
            using var certificate = new X509Certificate2(Path.Combine(options.PkiRootPath, "master-protection.pfx"),
                (string?)null, X509KeyStorageFlags.EphemeralKeySet);
            var protection = DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(options.PkiRootPath, "keyring")),
                builder => builder.SetApplicationName("VFido.Server").ProtectKeysWithCertificate(certificate));
            var authorization = new UserKeyProtector(protection).GetOrCreateKey(template);
            File.WriteAllText(ServerTpmMaster.RecoveryPath(options), "temporary encrypted recovery export");
            var backup = Path.Combine(root, "downloaded-backup.pfx");
            File.Copy(ServerTpmMaster.RecoveryPath(options), backup);

            foreach (var name in new[] { "alice", "bob" })
            {
                var user = Path.Combine(options.SecretsRootPath, name);
                ServerTpmMaster.CopyToUser(options, user);
                ServerTpmMaster.CopyToUser(options, user); // Repeat creation does not replace files.
                Assert.Equal("TPM-wrapped master", File.ReadAllText(Path.Combine(user, "keys", "master.json")));
                Assert.Equal(Convert.ToBase64String(authorization), ServerTpmMaster.GetAuthorization(options));
                Assert.False(Directory.Exists(Path.Combine(user, "tpm")));
                Assert.False(File.Exists(Path.Combine(user, "keys", "wrapped.key")));
                Assert.False(File.Exists(Path.Combine(user, "keys", "vfido-tpm-recovery.pfx")));
                var userKey = new UserKeyProtector(protection).GetOrCreateKey(user);
                ServerTpmMaster.CopyToUser(options, user);
                Assert.Equal(userKey, new UserKeyProtector(protection).GetOrCreateKey(user));
                Assert.Single(Directory.EnumerateFiles(user, "wrapped.key", SearchOption.AllDirectories));
            }
            var conflict = Path.Combine(options.SecretsRootPath, "legacy", "keys");
            Directory.CreateDirectory(conflict);
            File.WriteAllText(Path.Combine(conflict, "master.json"), "different existing master");
            Assert.Throws<InvalidOperationException>(() => ServerTpmMaster.CopyToUser(options, Path.Combine(options.SecretsRootPath, "legacy")));
            Assert.Equal("different existing master", File.ReadAllText(Path.Combine(conflict, "master.json")));
            Assert.False(File.Exists(Path.Combine(conflict, "wrapped.key")));

            ServerTpmMaster.DeleteRecoveryExport(options);
            ServerTpmMaster.DeleteRecoveryExport(options);
            Assert.False(File.Exists(ServerTpmMaster.RecoveryPath(options)));
            Assert.True(File.Exists(backup));
            Assert.True(File.Exists(Path.Combine(template, "master.json")));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void TpmSetupRequiresRecoveryPassword()
    {
        Assert.NotNull(FirstRunSetup.Validate(new("localhost", "admin", "ca-password-123", "certificate-123", "Tpm", 5443)));
    }

    [Fact]
    public void InvalidRecoveryUploadDoesNotCreateInstallationFiles()
    {
        var root = Path.Combine(Path.GetTempPath(), "vfido-invalid-recovery-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            var options = new MtlsBasedSecretStoreServerOptions { PkiRootPath = "pki", SecretsRootPath = "users" };
            options.ResolvePaths(root);
            var request = new FirstRunSetup.SetupRequest("localhost", "admin", "ca-password-123", "certificate-123", "Tpm", 5443,
                "recovery-password-123", [1, 2, 3]);
            Assert.ThrowsAny<Exception>(() => FirstRunSetup.Initialize(options, Path.Combine(root, "appsettings.json"), request));
            Assert.True(FirstRunSetup.IsFreshInstallation(options));
            Assert.Empty(Directory.EnumerateFileSystemEntries(root));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [TpmIntegrationFact]
    public async Task SetupImportsRecoveryAndUsersSignWithCopiesAfterExportDeletion()
    {
        var root = Path.Combine(Path.GetTempPath(), "vfido-recovery-setup-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            var options = new MtlsBasedSecretStoreServerOptions { PkiRootPath = "pki", SecretsRootPath = "users" };
            options.ResolvePaths(root);
            using var master = TpmMasterKey.Generate();
            const string password = "recovery-password-123";
            var recovery = master.ExportPfx(password);
            var request = new FirstRunSetup.SetupRequest("localhost", "admin", "ca-password-123", "certificate-123", "Tpm", 5443, password, recovery);
            FirstRunSetup.Initialize(options, Path.Combine(root, "appsettings.json"), request);
            Assert.Equal(recovery, File.ReadAllBytes(ServerTpmMaster.RecoveryPath(options)));
            var protector = new UserKeyProtector(DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(root, "user-protection"))));
            ServerTpmMaster.DeleteRecoveryExport(options);
            using var resolver = new UserDirectoryResolver(options, protector);
            var alice = resolver.BuildPasswordlessManager("alice");
            var id = (await alice.CreateCredentialAsync("example.com", [1], "alice", "Alice", true, 1)).CredentialId;
            Assert.NotEmpty(await alice.SignAsync(id, [1, 2, 3]));
            Assert.Equal(File.ReadAllBytes(Path.Combine(ServerTpmMaster.DirectoryPath(options), "master.json")),
                File.ReadAllBytes(Path.Combine(options.SecretsRootPath, "alice", "keys", "master.json")));
            var bob = resolver.BuildPasswordlessManager("bob");
            Assert.False(await bob.CredentialExistsAsync(id, "example.com"));
            Assert.False(File.Exists(ServerTpmMaster.RecoveryPath(options)));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
