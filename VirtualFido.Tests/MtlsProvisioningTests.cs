using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;
using Xunit;

namespace VirtualFido.Tests
{
    /// <summary>
    /// Covers the CA/cert-issuance chain, per-user directory partitioning, and the
    /// password/passwordless split the mTLS server's admin CLI and identity-resolution filter rely
    /// on - see VFido.SecretManager.MtlsBasedSecretStoreServer/Pki/CaManager.cs and UserDirectoryResolver.cs.
    /// </summary>
    public class MtlsProvisioningTests
    {
        private static string NewTempDirectory()
        {
            var path = Path.Combine(Path.GetTempPath(), "vfido-mtls-tests-" + Guid.NewGuid());
            Directory.CreateDirectory(path);
            return path;
        }

        [Fact]
        public void IssueClientCertificate_ChainsToRoot_AndCarriesUsernameAsCn()
        {
            var pkiRoot = NewTempDirectory();
            var ca = new CaManager(pkiRoot);
            ca.EnsureRootAndIntermediate("correct-horse-battery-staple");

            var pfx = ca.IssueClientCertificate("alice", "correct-horse-battery-staple", pfxPassword: "client-pw");
            using var leaf = new X509Certificate2(pfx, "client-pw");
            using var intermediate = new X509Certificate2(ca.ExportIntermediateCertificate());

            Assert.Equal("alice", leaf.GetNameInfo(X509NameType.SimpleName, false));
            Assert.Equal(intermediate.SubjectName.Name, leaf.IssuerName.Name);

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(intermediate);
            chain.ChainPolicy.ExtraStore.Add(intermediate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            var built = chain.Build(leaf);
            Assert.True(built, string.Join(",", chain.ChainStatus.Select(s => s.Status + ":" + s.StatusInformation)));
        }

        [Fact]
        public void IssueClientCertificate_WithWrongPassphrase_Throws()
        {
            var pkiRoot = NewTempDirectory();
            var ca = new CaManager(pkiRoot);
            ca.EnsureRootAndIntermediate("correct-horse-battery-staple");

            Assert.Throws<InvalidCredentialsException>(() =>
                ca.IssueClientCertificate("alice", "wrong-passphrase", pfxPassword: null));
        }

        [Fact]
        public void Revoke_AddsSerialToRevocationStore()
        {
            var pkiRoot = NewTempDirectory();
            var ca = new CaManager(pkiRoot);
            ca.EnsureRootAndIntermediate("passphrase");
            var pfx = ca.IssueClientCertificate("alice", "passphrase", pfxPassword: null);
            using var leaf = new X509Certificate2(pfx);

            Assert.False(RevocationStore.Load(pkiRoot).IsRevoked(leaf.SerialNumber));

            ca.Revoke(leaf.SerialNumber);

            Assert.True(RevocationStore.Load(pkiRoot).IsRevoked(leaf.SerialNumber));
        }

        [Fact]
        public async Task PasswordUsers_GetIndependentStores_AndWrongPasswordFails()
        {
            var secretsRoot = NewTempDirectory();
            var options = new MtlsBasedSecretStoreServerOptions
            {
                ServerCertificatePath = "unused.pfx",
                ClientCaCertificatePath = "unused.crt",
                SecretsRootPath = secretsRoot,
            };
            var resolver = new UserDirectoryResolver(options, new UserKeyProtector(DataProtectionProvider.Create(new DirectoryInfo(NewTempDirectory()))));

            var alice = resolver.BuildManagerFromPassword("alice", "alice-password");
            var bob = resolver.BuildManagerFromPassword("bob", "bob-password");

            Assert.True(resolver.RequiresPassword("alice"));
            Assert.True(resolver.RequiresPassword("bob"));

            // Independent stores: a credential created for alice must not be visible to bob.
            var credentialId = await alice.CreateCredentialAsync("example.com", new byte[] { 1 }, "alice", "Alice", isResident: true, credProtect: 1);
            Assert.True(await alice.CredentialExistsAsync(credentialId.CredentialId, "example.com"));
            Assert.False(await bob.CredentialExistsAsync(credentialId.CredentialId, "example.com"));

            // Right directory, wrong password -> rejected instead of silently deriving a different key.
            Assert.Throws<InvalidCredentialsException>(() => resolver.BuildManagerFromPassword("alice", "not-alices-password"));
        }

        [Fact]
        public async Task PasswordlessUser_HasNoVerifierFile_AndKeyRoundTripsThroughDataProtection()
        {
            var secretsRoot = NewTempDirectory();
            var options = new MtlsBasedSecretStoreServerOptions
            {
                ServerCertificatePath = "unused.pfx",
                ClientCaCertificatePath = "unused.crt",
                SecretsRootPath = secretsRoot,
            };
            var provider = DataProtectionProvider.Create(new DirectoryInfo(NewTempDirectory()));
            var resolver = new UserDirectoryResolver(options, new UserKeyProtector(provider));

            var carol = resolver.BuildPasswordlessManager("carol");

            Assert.False(resolver.RequiresPassword("carol")); // no login password -> mTLS cert alone is sufficient
            Assert.True(UserKeyProtector.HasWrappedKey(resolver.GetUserDirectory("carol")));

            // Re-resolving (e.g. a second request in the same process) must reuse the same wrapped
            // key rather than generating a new one, or carol's first-created credentials would
            // become undecryptable.
            var carolAgain = resolver.BuildPasswordlessManager("carol");
            var credentialId = await carol.CreateCredentialAsync("example.com", new byte[] { 2 }, "carol", "Carol", isResident: true, credProtect: 1);
            Assert.True(await carolAgain.CredentialExistsAsync(credentialId.CredentialId, "example.com"));
        }
    }
}
