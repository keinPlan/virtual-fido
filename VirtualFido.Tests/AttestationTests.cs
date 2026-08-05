using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using VFido.Core.Device.Ctap2.Authenticator;
using VFido.Core.Device.Ctap2.Model;
using VFido.SecretManager;
using VFido.SecretManager.Crypto;
using VFido.SecretManager.MemoryBasedSecretStore;
using Xunit;

namespace VirtualFido.Tests
{
    /// <summary>
    /// Covers the "packed" attestation statement's x5c: MakeCredential must attest with a leaf
    /// certificate issued by an intermediate CA (itself issued by a self-signed root that stays
    /// out of x5c), stable across credentials/calls, rather than the bare self-attestation
    /// signature the credential's own key would produce.
    /// </summary>
    public class AttestationTests
    {
        private static Task<Fido2Authenticator> NewAuthenticatorAsync() =>
            Fido2Authenticator.CreateAsync(new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore()),
                aaguid: Guid.NewGuid().ToByteArray());

        private static MakeCredentialRequest NewMakeCredentialRequest() => new(
            ClientDataHash: new byte[32],
            RelyingParty: new RelyingParty("example.com", "Example"),
            User: new UserEntity(new byte[] { 1, 2, 3 }, "user", "User"),
            PubKeyCredParams: new[] { new PublicKeyCredentialParameters("public-key", -7) },
            PinUvAuthParam: null,
            RequireResidentKey: true,
            RequireUserVerification: false,
            CredProtect: null);

        [Fact]
        public async Task MakeCredential_AttestsWithIntermediateIssuedLeafCertificate_AndSignatureVerifiesAgainstIt()
        {
            var authenticator = await NewAuthenticatorAsync();
            var request = NewMakeCredentialRequest();

            var result = await authenticator.MakeCredentialAsync(request);

            Assert.Equal(2, result.AttestationCertificateChainDer.Count); // x5c carries only leaf + intermediate, not the root

            using var leaf = new X509Certificate2(result.AttestationCertificateChainDer[0]);
            using var intermediate = new X509Certificate2(result.AttestationCertificateChainDer[1]);
            Assert.Equal(AttestationCertificateFactory.RootSubjectName, intermediate.IssuerName.Name); // intermediate is issued by the (unshipped) root
            Assert.Equal(intermediate.SubjectName.Name, leaf.IssuerName.Name); // leaf is issued by the intermediate
            Assert.NotEqual(leaf.SubjectName.Name, leaf.IssuerName.Name); // leaf is not self-signed

            using var publicKey = leaf.GetECDsaPublicKey();
            Assert.NotNull(publicKey);

            var signedData = new byte[result.AuthenticatorData.Length + request.ClientDataHash.Length];
            Buffer.BlockCopy(result.AuthenticatorData, 0, signedData, 0, result.AuthenticatorData.Length);
            Buffer.BlockCopy(request.ClientDataHash, 0, signedData, result.AuthenticatorData.Length, request.ClientDataHash.Length);

            Assert.True(publicKey!.VerifyData(signedData, result.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        }

        [Fact]
        public async Task MakeCredential_TwoCredentials_ShareTheSameAttestationChain()
        {
            var authenticator = await NewAuthenticatorAsync();

            var first = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest());
            var second = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest());

            Assert.Equal(first.AttestationCertificateChainDer, second.AttestationCertificateChainDer);
        }

        [Fact]
        public async Task MakeCredential_LeafCertificate_CarriesTheStoresAaguidExtension()
        {
            var keyStore = new MemoryBasedSecretStore();
            var secrets = new Fido2SecretManager(keyStore, new InMemoryCredentialStore());
            var authenticator = await Fido2Authenticator.CreateAsync(secrets, await secrets.GetAaguidAsync());

            var result = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest());

            using var leaf = new X509Certificate2(result.AttestationCertificateChainDer[0]);
            var extension = leaf.Extensions["1.3.6.1.4.1.45724.1.1.4"];
            Assert.NotNull(extension);
            Assert.False(extension!.Critical);

            // Extension value is a DER OCTET STRING wrapping the raw 16-byte AAGUID.
            var rawData = extension.RawData;
            Assert.Equal(0x04, rawData[0]);
            Assert.Equal(16, rawData[1]);
            Assert.Equal(keyStore.Aaguid, rawData[2..]);
        }
    }
}
