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

        private static MakeCredentialRequest NewMakeCredentialRequest(bool requireUserVerification) => new(
            ClientDataHash: new byte[32],
            RelyingParty: new RelyingParty("example.com", "Example"),
            User: new UserEntity(new byte[] { 1, 2, 3 }, "user", "User"),
            PubKeyCredParams: new[] { new PublicKeyCredentialParameters("public-key", -7) },
            RequireUserVerification: requireUserVerification);

        [Fact]
        public async Task Avoid_NoPinSet_PlatformRequestsUv_StillSucceedsWithoutRequiringPin()
        {
            var authenticator = NewAuthenticator(PinUsagePreference.Avoid);

            var result = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(requireUserVerification: true));

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
