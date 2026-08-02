using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

        [Fact]
        public void GetOrCreateAttestationCertificate_IssuesLeafFromIntermediateFromRoot_StableAcrossCalls()
        {
            var store = new FileBasedSecretStore(_directory, "user", "pass");

            var first = store.GetOrCreateAttestationCertificate();
            var second = store.GetOrCreateAttestationCertificate();

            Assert.Equal(first.CertificateChainDer, second.CertificateChainDer);
            Assert.Equal(first.KeyHandle, second.KeyHandle);
            Assert.Equal(2, first.CertificateChainDer.Count); // x5c carries only leaf + intermediate, not the root

            using var leaf = new X509Certificate2(first.CertificateChainDer[0]);
            using var intermediate = new X509Certificate2(first.CertificateChainDer[1]);
            using var root = new X509Certificate2(File.ReadAllBytes(Path.Combine(_directory, "attestation-root.crt")));

            Assert.Equal(root.SubjectName.Name, root.IssuerName.Name); // root is self-signed
            Assert.Equal(root.SubjectName.Name, intermediate.IssuerName.Name); // intermediate is issued by the root
            Assert.Equal(intermediate.SubjectName.Name, leaf.IssuerName.Name); // leaf is issued by the intermediate
            Assert.NotEqual(leaf.SubjectName.Name, leaf.IssuerName.Name); // leaf is not self-signed

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.ExtraStore.Add(intermediate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            Assert.True(chain.Build(leaf));
        }

        [Fact]
        public void GetOrCreateAttestationCertificate_PersistsAcrossReopenedStore()
        {
            var store = new FileBasedSecretStore(_directory, "user", "pass");
            var original = store.GetOrCreateAttestationCertificate();

            var reopened = new FileBasedSecretStore(_directory, "user", "pass");
            var reloaded = reopened.GetOrCreateAttestationCertificate();

            Assert.Equal(original.CertificateChainDer, reloaded.CertificateChainDer);

            var key = reopened.LoadKey(reloaded.KeyHandle);
            using var leaf = new X509Certificate2(reloaded.CertificateChainDer[0]);
            using var leafPublicKey = leaf.GetECDsaPublicKey();
            Assert.NotNull(leafPublicKey);
            Assert.Equal(key.ExportCosePublicKey(), VFido.SecretManager.Crypto.CoseKeyEncoder.Encode(leafPublicKey!.ExportParameters(includePrivateParameters: false)));
        }
    }
}
