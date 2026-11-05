using System.Security.Cryptography;
using System.Text.Json;
using Tpm2Lib;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VirtualFido.Tests;

public sealed class TpmMasterProtectionTests
{
    [Fact]
    public void Authorization_IsPerStoreAndDoesNotChangePortableMasterIdentity()
    {
        var first = TpmMasterProtection.Create("store password", out var authorization);
        var second = TpmMasterProtection.Create("store password", out var other);
        try
        {
            Assert.Equal(32, authorization.Length);
            Assert.NotEqual(first.Salt, second.Salt);
            Assert.NotEqual(authorization, other);
            var unlocked = first.Unlock("store password");
            try { Assert.Equal(authorization, unlocked); }
            finally { CryptographicOperations.ZeroMemory(unlocked); }
            Assert.Throws<CryptographicException>(() => first.Unlock("wrong password"));
            Assert.Throws<CryptographicException>(() => first.Unlock(null));
            using var master = TpmMasterKey.Generate();
            var imported = master.ToImportObject(authorization);
            try
            {
                Assert.Equal(master.Name, imported.Public.GetName());
                Assert.Equal(authorization, imported.Sensitive.authValue);
                Assert.NotSame(authorization, imported.Sensitive.authValue);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(imported.Sensitive.authValue);
                CryptographicOperations.ZeroMemory(imported.Sensitive.seedValue);
                CryptographicOperations.ZeroMemory(((Tpm2bPrivateKeyRsa)imported.Sensitive.sensitive).buffer);
            }
        }
        finally { CryptographicOperations.ZeroMemory(authorization); CryptographicOperations.ZeroMemory(other); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(int.MaxValue)]
    public void UntrustedWorkFactors_AreRejected(int iterations)
    {
        var protection = new TpmMasterProtection(new byte[32], iterations, new byte[32]);
        Assert.Throws<InvalidDataException>(() => protection.Unlock("password"));
    }

    [Fact]
    public void WrongOrMissingPassword_IsRejectedBeforeConnectingAndPreservesFiles()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vfido-protected-test-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        var protection = TpmMasterProtection.Create("store password", out var authorization);
        CryptographicOperations.ZeroMemory(authorization);
        try
        {
            using var master = TpmMasterKey.Generate();
            var path = Path.Combine(directory, "master.json");
            var original = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Version = 2, PrimaryName = master.Name, Public = master.PublicArea, Private = new byte[] { 1 }, Protection = protection
            });
            File.WriteAllBytes(path, original);
            Tpm2Device NoConnect() => throw new InvalidOperationException("Must reject before TPM access.");
            Assert.Throws<CryptographicException>(() => new TpmBasedSecretStore(directory, NoConnect));
            Assert.Throws<CryptographicException>(() => new TpmBasedSecretStore(directory, NoConnect, masterPassword: "wrong"));
            Assert.Equal(original, File.ReadAllBytes(path));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [TpmIntegrationFact]
    public void ProtectedMaster_SignsReopensAndRecoversWithDifferentPassword()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vfido-auth-tpm-" + Guid.NewGuid());
        try
        {
            using var master = TpmMasterKey.Generate();
            TpmBasedSecretStore.Provision(directory, master, masterPassword: "first password");
            byte[] handle, wrapped;
            var data = new byte[] { 1, 2, 3 };
            using (var store = new TpmBasedSecretStore(directory, masterPassword: "first password"))
            {
                var key = store.CreateEs256Key();
                handle = key.ExportHandle();
                wrapped = store.ExportWrappedKey(handle);
                Assert.NotEmpty(key.Sign(data));
            }
            Assert.Throws<CryptographicException>(() => new TpmBasedSecretStore(directory, masterPassword: "wrong"));
            using (var reopened = new TpmBasedSecretStore(directory, masterPassword: "first password"))
                Assert.NotEmpty(reopened.LoadKey(handle).Sign(data));
            var recovered = Path.Combine(directory, "recovered");
            TpmBasedSecretStore.Provision(recovered, master, masterPassword: "second password");
            using var recovery = new TpmBasedSecretStore(recovered, masterPassword: "second password");
            var recoveredHandle = recovery.ImportWrappedKey(wrapped);
            Assert.Equal(wrapped, recovery.ExportWrappedKey(recoveredHandle));
            Assert.NotEmpty(recovery.LoadKey(recoveredHandle).Sign(data));
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }
}
