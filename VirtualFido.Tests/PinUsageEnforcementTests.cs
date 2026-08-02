using System.Security.Cryptography;
using System.Text;
using VFido.Core.Device.Ctap2.Authenticator;
using VFido.Core.Device.Ctap2.Authenticator.Pin;
using VFido.Core.Device.Ctap2.Errors;
using VFido.Core.Device.Ctap2.Model;
using VFido.SecretManager;
using VFido.SecretManager.MemoryBasedSecretStore;
using Xunit;

namespace VirtualFido.Tests
{
    /// <summary>
    /// Covers Fido2Authenticator.RequireUserVerification's pin_usage override: Always forces UV
    /// even when the platform didn't ask; Avoid never insists on it even when the platform did;
    /// Prefer is unchanged (governed purely by what the platform's request asked for).
    /// </summary>
    public class PinUsageEnforcementTests
    {
        private static Fido2Authenticator NewAuthenticator(PinUsagePreference pinUsage) =>
            new(new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore()),
                aaguid: Guid.NewGuid().ToByteArray(), pinUsage);

        private static MakeCredentialRequest NewMakeCredentialRequest(bool requireUserVerification, byte[]? pinUvAuthParam = null) => new(
            ClientDataHash: new byte[32],
            RelyingParty: new RelyingParty("example.com", "Example"),
            User: new UserEntity(new byte[] { 1, 2, 3 }, "user", "User"),
            PubKeyCredParams: new[] { new PublicKeyCredentialParameters("public-key", -7) },
            PinUvAuthParam: pinUvAuthParam,
            RequireUserVerification: requireUserVerification);

        /// <summary>Drives the real ClientPIN setPIN ceremony against the authenticator, playing the platform side of PIN/UV Auth Protocol One so tests can exercise "a PIN is already configured" scenarios.</summary>
        private static async Task<byte[]> SetPinAsync(Fido2Authenticator authenticator, string pin)
        {
            var keyAgreement = await authenticator.ClientPinAsync(new ClientPinRequest(PinProtocol: 1, SubCommand: 2, null, null, null, null));
            var authenticatorPublicKey = keyAgreement.KeyAgreementPublicKey!.Value;

            using var platformKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var platformPublicKey = platformKey.ExportParameters(includePrivateParameters: false);
            var sharedSecret = PinProtocolOne.DeriveSharedSecret(platformKey, authenticatorPublicKey);

            var padded = new byte[64];
            Encoding.UTF8.GetBytes(pin).CopyTo(padded, 0);
            var newPinEnc = PinProtocolOne.Encrypt(sharedSecret, padded);
            var setPinAuthParam = PinProtocolOne.Authenticate(sharedSecret, newPinEnc);

            await authenticator.ClientPinAsync(new ClientPinRequest(PinProtocol: 1, SubCommand: 3, platformPublicKey, setPinAuthParam, newPinEnc, null));

            return sharedSecret;
        }

        /// <summary>Drives the real ClientPIN getPinToken ceremony, returning the decrypted pinUvAuthToken used to authenticate subsequent requests.</summary>
        private static async Task<byte[]> GetPinTokenAsync(Fido2Authenticator authenticator, string pin)
        {
            var keyAgreement = await authenticator.ClientPinAsync(new ClientPinRequest(PinProtocol: 1, SubCommand: 2, null, null, null, null));
            var authenticatorPublicKey = keyAgreement.KeyAgreementPublicKey!.Value;

            using var platformKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var platformPublicKey = platformKey.ExportParameters(includePrivateParameters: false);
            var sharedSecret = PinProtocolOne.DeriveSharedSecret(platformKey, authenticatorPublicKey);

            var pinHash = SHA256.HashData(Encoding.UTF8.GetBytes(pin)).AsSpan(0, 16).ToArray();
            var pinHashEnc = PinProtocolOne.Encrypt(sharedSecret, pinHash);

            var result = await authenticator.ClientPinAsync(new ClientPinRequest(PinProtocol: 1, SubCommand: 5, platformPublicKey, null, null, pinHashEnc));

            return PinProtocolOne.Decrypt(sharedSecret, result.PinUvAuthTokenEnc!);
        }

        [Fact]
        public async Task Avoid_NoPinSet_PlatformRequestsUv_StillSucceedsWithoutRequiringPin()
        {
            var authenticator = NewAuthenticator(PinUsagePreference.Avoid);

            var result = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(requireUserVerification: true));

            Assert.NotNull(result);
        }

        [Fact]
        public async Task Avoid_PinAlreadySet_PlatformSendsNoAuthParam_StillSucceedsWithoutRequiringPin()
        {
            // Regression: pin_usage=Avoid must skip PIN verification even once a PIN is configured
            // on the stick - not just before any PIN exists. The platform here mirrors WebAuthn
            // userVerification="preferred": it doesn't request UV and sends no pinUvAuthParam.
            var authenticator = NewAuthenticator(PinUsagePreference.Avoid);
            await SetPinAsync(authenticator, "1234");

            var result = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(requireUserVerification: false));

            Assert.NotNull(result);
        }

        [Fact]
        public async Task Avoid_PinAlreadySet_PlatformSendsValidAuthParamAnyway_StillHonorsIt()
        {
            var authenticator = NewAuthenticator(PinUsagePreference.Avoid);
            await SetPinAsync(authenticator, "1234");
            var pinToken = await GetPinTokenAsync(authenticator, "1234");

            var clientDataHash = new byte[32];
            var pinUvAuthParam = PinProtocolOne.Authenticate(pinToken, clientDataHash);
            var request = NewMakeCredentialRequest(requireUserVerification: false, pinUvAuthParam: pinUvAuthParam) with { ClientDataHash = clientDataHash };

            var result = await authenticator.MakeCredentialAsync(request);

            Assert.NotNull(result);
        }

        [Fact]
        public async Task Always_NoPinSet_PlatformDoesNotRequestUv_StillThrowsPinRequired()
        {
            var authenticator = NewAuthenticator(PinUsagePreference.Always);

            var ex = await Assert.ThrowsAsync<Ctap2Exception>(
                () => authenticator.MakeCredentialAsync(NewMakeCredentialRequest(requireUserVerification: false)));

            Assert.Equal(VFido.Core.Device.Ctap2.Ctap2Constants.Ctap2ErrPinRequired, ex.StatusCode);
        }

        [Fact]
        public async Task Prefer_NoPinSet_PlatformRequestsUv_ThrowsPinRequired_UnchangedBehavior()
        {
            var authenticator = NewAuthenticator(PinUsagePreference.Prefer);

            var ex = await Assert.ThrowsAsync<Ctap2Exception>(
                () => authenticator.MakeCredentialAsync(NewMakeCredentialRequest(requireUserVerification: true)));

            Assert.Equal(VFido.Core.Device.Ctap2.Ctap2Constants.Ctap2ErrPinRequired, ex.StatusCode);
        }

        [Fact]
        public async Task Prefer_NoPinSet_PlatformDoesNotRequestUv_Succeeds_UnchangedBehavior()
        {
            var authenticator = NewAuthenticator(PinUsagePreference.Prefer);

            var result = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(requireUserVerification: false));

            Assert.NotNull(result);
        }
    }
}
