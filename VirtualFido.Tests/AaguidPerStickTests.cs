using System.Formats.Cbor;
using VFido.Core.Device.Ctap2;
using VFido.Core.Device.Ctap2.Authenticator;
using VFido.SecretManager;
using VFido.SecretManager.MemoryBasedSecretStore;
using Xunit;

namespace VirtualFido.Tests
{
    /// <summary>Regression coverage for the AAGUID being fixed per secret manager store, not per stick.</summary>
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

        private static async Task<Fido2Authenticator> NewAuthenticatorAsync()
        {
            var secrets = new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore());
            return new Fido2Authenticator(secrets, await secrets.GetAaguidAsync());
        }

        [Fact]
        public async Task GetInfo_ReportsTheFixedAaguidForThisStoreType_TheSameAcrossInstances()
        {
            var authenticatorA = await NewAuthenticatorAsync();
            var authenticatorB = await NewAuthenticatorAsync();

            var responseA = await Ctap2Dispatcher.Handle(new[] { Ctap2Constants.AuthenticatorGetInfo }, authenticatorA);
            var responseB = await Ctap2Dispatcher.Handle(new[] { Ctap2Constants.AuthenticatorGetInfo }, authenticatorB);

            var reportedA = ExtractAaguid(responseA);
            var reportedB = ExtractAaguid(responseB);

            // Two sticks backed by the same store type (MemoryBasedSecretStore) share the same
            // hardcoded AAGUID - it identifies the authenticator model, not the individual stick.
            Assert.Equal(reportedA, reportedB);
            Assert.Equal(new MemoryBasedSecretStore().Aaguid, reportedA);
        }
    }
}
