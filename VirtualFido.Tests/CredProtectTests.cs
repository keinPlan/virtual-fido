using System.Formats.Cbor;
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
    /// Covers the credProtect extension (CTAP2 §11.3): level 3 always requires UV (even at
    /// creation time); level 2 only requires UV when a credential is discovered via an empty
    /// allowList rather than explicitly named; level 1 (default, or when the extension isn't
    /// requested) behaves exactly like today.
    /// </summary>
    public class CredProtectTests
    {
        private static Fido2Authenticator NewAuthenticator() =>
            new(new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore()),
                aaguid: Guid.NewGuid().ToByteArray());

        private static MakeCredentialRequest NewMakeCredentialRequest(int? credProtect, bool requireResidentKey = true, bool requireUserVerification = false, byte[]? pinUvAuthParam = null) => new(
            ClientDataHash: new byte[32],
            RelyingParty: new RelyingParty("example.com", "Example"),
            User: new UserEntity(new byte[] { 1, 2, 3 }, "user", "User"),
            PubKeyCredParams: new[] { new PublicKeyCredentialParameters("public-key", -7) },
            PinUvAuthParam: pinUvAuthParam,
            RequireResidentKey: requireResidentKey,
            RequireUserVerification: requireUserVerification,
            CredProtect: credProtect);

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

        private static int? ExtractCredProtectExtension(byte[] authenticatorData)
        {
            var flags = authenticatorData[32];
            if ((flags & 0x40) == 0) // attested credential data not included
                return null;

            var offset = 32 + 1 + 4 + 16; // rpIdHash + flags + signCount + aaguid
            var credIdLen = (authenticatorData[offset] << 8) | authenticatorData[offset + 1];
            offset += 2 + credIdLen;

            var reader = new CborReader(authenticatorData.AsMemory(offset), CborConformanceMode.Ctap2Canonical, allowMultipleRootLevelValues: true);
            reader.SkipValue(); // coseKey map

            if ((flags & 0x80) == 0) // extension data not included
                return null;

            reader.ReadStartMap();
            int? credProtect = null;
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                if (reader.ReadTextString() == "credProtect")
                    credProtect = reader.ReadInt32();
                else
                    reader.SkipValue();
            }
            reader.ReadEndMap();
            return credProtect;
        }

        [Fact]
        public async Task MakeCredential_CredProtectNotRequested_DefaultsToLevel1AndOmitsExtensionOutput()
        {
            var authenticator = NewAuthenticator();

            var result = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(credProtect: null));

            Assert.Null(ExtractCredProtectExtension(result.AuthenticatorData));
        }

        [Fact]
        public async Task MakeCredential_CredProtectRequested_EchoesLevelInExtensionOutput()
        {
            var authenticator = NewAuthenticator();

            var result = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(credProtect: 2));

            Assert.Equal(2, ExtractCredProtectExtension(result.AuthenticatorData));
        }

        [Fact]
        public async Task MakeCredential_CredProtectLevel3_NoPinSet_RequiresPinRegardlessOfRequest()
        {
            var authenticator = NewAuthenticator();

            var ex = await Assert.ThrowsAsync<Ctap2Exception>(
                () => authenticator.MakeCredentialAsync(NewMakeCredentialRequest(credProtect: 3, requireUserVerification: false)));

            Assert.Equal(VFido.Core.Device.Ctap2.Ctap2Constants.Ctap2ErrPinRequired, ex.StatusCode);
        }

        [Fact]
        public async Task GetAssertion_CredProtectLevel2_ViaExplicitAllowList_DoesNotRequireUv()
        {
            var authenticator = NewAuthenticator();
            var created = await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(credProtect: 2));
            var credentialId = ExtractCredentialId(created.AuthenticatorData);

            var result = await authenticator.GetAssertionAsync(new GetAssertionRequest(
                RpId: "example.com", ClientDataHash: new byte[32], AllowList: new[] { credentialId }));

            Assert.NotNull(result);
        }

        [Fact]
        public async Task GetAssertion_CredProtectLevel2_ViaEmptyAllowListDiscovery_RequiresUv()
        {
            var authenticator = NewAuthenticator();
            await authenticator.MakeCredentialAsync(NewMakeCredentialRequest(credProtect: 2));

            var ex = await Assert.ThrowsAsync<Ctap2Exception>(() => authenticator.GetAssertionAsync(new GetAssertionRequest(
                RpId: "example.com", ClientDataHash: new byte[32], AllowList: Array.Empty<byte[]>())));

            Assert.Equal(VFido.Core.Device.Ctap2.Ctap2Constants.Ctap2ErrPinRequired, ex.StatusCode);
        }

        [Fact]
        public async Task GetAssertion_CredProtectLevel3_EvenViaExplicitAllowList_RequiresUv()
        {
            // Level 3 forces UV at creation too, so a PIN must already be set to create it at all.
            var authenticator = NewAuthenticator();
            await SetPinAsync(authenticator, "1234");
            var pinToken = await GetPinTokenAsync(authenticator, "1234");
            var clientDataHash = new byte[32];
            var pinUvAuthParam = PinProtocolOne.Authenticate(pinToken, clientDataHash);

            var created = await authenticator.MakeCredentialAsync(
                NewMakeCredentialRequest(credProtect: 3, pinUvAuthParam: pinUvAuthParam) with { ClientDataHash = clientDataHash });
            var credentialId = ExtractCredentialId(created.AuthenticatorData);

            // No pinUvAuthParam this time - even though the credential is named explicitly.
            var ex = await Assert.ThrowsAsync<Ctap2Exception>(() => authenticator.GetAssertionAsync(new GetAssertionRequest(
                RpId: "example.com", ClientDataHash: new byte[32], AllowList: new[] { credentialId })));

            Assert.Equal(VFido.Core.Device.Ctap2.Ctap2Constants.Ctap2ErrPinRequired, ex.StatusCode);
        }

        private static byte[] ExtractCredentialId(byte[] authenticatorData)
        {
            var offset = 32 + 1 + 4 + 16;
            var credIdLen = (authenticatorData[offset] << 8) | authenticatorData[offset + 1];
            offset += 2;
            return authenticatorData[offset..(offset + credIdLen)];
        }
    }
}
