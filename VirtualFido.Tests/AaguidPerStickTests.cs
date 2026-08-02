using System.Formats.Cbor;
using VFido.Core.Device.Ctap2;
using VFido.Core.Device.Ctap2.Authenticator;
using VFido.Core.Device.Ctap2.Authenticator.Pin;
using VFido.SecretManager;
using VFido.SecretManager.MemoryBasedSecretStore;
using Xunit;

namespace VirtualFido.Tests
{
    /// <summary>Regression coverage guarding against AAGUID becoming a shared static again.</summary>
    public class AaguidPerStickTests
    {
        private static byte[] ExtractAaguid(byte[] getInfoResponse)
        {
            Assert.Equal(Ctap2Constants.Ctap2Ok, getInfoResponse[0]);

            var reader = new CborReader(getInfoResponse.AsMemory(1));
            var mapCount = reader.ReadStartMap();
            byte[]? aaguid = null;
            for (var i = 0; i < mapCount; i++)
            {
                var key = reader.ReadInt32();
                if (key == Ctap2Constants.InfoKeyAaguid)
                    aaguid = reader.ReadByteString();
                else
                    reader.SkipValue();
            }

            Assert.NotNull(aaguid);
            return aaguid!;
        }

        private static Fido2Authenticator NewAuthenticator(byte[] aaguid) =>
            new(new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore()), aaguid, PinUsagePreference.Prefer);

        [Fact]
        public async Task GetInfo_ReportsThePerStickConfiguredAaguid_NotASharedConstant()
        {
            var aaguidA = Guid.NewGuid().ToByteArray();
            var aaguidB = Guid.NewGuid().ToByteArray();

            var authenticatorA = NewAuthenticator(aaguidA);
            var authenticatorB = NewAuthenticator(aaguidB);

            var responseA = await Ctap2Dispatcher.Handle(new[] { Ctap2Constants.AuthenticatorGetInfo }, authenticatorA);
            var responseB = await Ctap2Dispatcher.Handle(new[] { Ctap2Constants.AuthenticatorGetInfo }, authenticatorB);

            var reportedA = ExtractAaguid(responseA);
            var reportedB = ExtractAaguid(responseB);

            Assert.Equal(aaguidA, reportedA);
            Assert.Equal(aaguidB, reportedB);
            Assert.NotEqual(reportedA, reportedB);
        }
    }
}
