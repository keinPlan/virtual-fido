using VFido.Core.Device.Ctap2.Authenticator;
using VFido.Core.Device.Ctap2.Errors;
using VFido.Core.Device.Ctap2.Model;
using VFido.SecretManager;
using VFido.SecretManager.MemoryBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer;

namespace VirtualFido.Tests;

public class AssertionPresenceTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void SignedFlagsAndLogMetadataKeepPresenceSeparateFromVerification(bool present, bool verified)
    {
        var authData = AuthenticatorDataBuilder.BuildWithoutAttestedCredential("example.com", 258, verified, present);
        var metadata = AssertionLogMetadata.FromSigningData(authData.Concat(new byte[32]).ToArray());

        Assert.Equal((present ? 1 : 0) | (verified ? 4 : 0), authData[32]);
        Assert.Equal(present, metadata.UserPresent);
        Assert.Equal(verified, metadata.UserVerified);
        Assert.Equal(258u, metadata.SignCount);
        Assert.Equal(present ? "user-present assertion" : "silent probe", metadata.AssertionKind);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DiscoverableAssertionsPreservePresenceAcrossTheSequence(bool requirePresence)
    {
        var (authenticator, gate) = await CreateAsync(approve: true);
        var first = await authenticator.GetAssertionAsync(Request(requirePresence));
        var second = await authenticator.GetNextAssertionAsync();

        Assert.Equal(requirePresence ? 1 : 0, first.AuthenticatorData[32] & 1);
        Assert.Equal(requirePresence ? 1 : 0, second.AuthenticatorData[32] & 1);
        Assert.Equal(requirePresence ? 1 : 0, gate.Calls);
    }

    [Fact]
    public async Task DeniedApprovalCannotBeBypassedWithGetNextAssertion()
    {
        var (authenticator, gate) = await CreateAsync(approve: false);
        // A new denied request must also discard any earlier silent-probe sequence.
        await authenticator.GetAssertionAsync(Request(false));
        await Assert.ThrowsAsync<Ctap2Exception>(() => authenticator.GetAssertionAsync(Request(true)));
        await Assert.ThrowsAsync<Ctap2Exception>(() => authenticator.GetNextAssertionAsync());
        Assert.Equal(1, gate.Calls);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(32, 0)]
    [InlineData(68, 0)]
    [InlineData(70, 0)]
    [InlineData(69, 0x40)]
    [InlineData(69, 0x80)]
    public void UnrecognizedSigningPayloadDoesNotClaimPresenceOrVerification(int length, int flags)
    {
        var data = new byte[length];
        if (length > 32) data[32] = (byte)flags;
        var metadata = AssertionLogMetadata.FromSigningData(data);
        Assert.Equal("unrecognized signing data", metadata.AssertionKind);
        Assert.Null(metadata.UserPresent);
        Assert.Null(metadata.UserVerified);
        Assert.Null(metadata.SignCount);
    }

    private static GetAssertionRequest Request(bool requirePresence) =>
        new("example.com", new byte[32], Array.Empty<byte[]>(), RequireUserPresence: requirePresence);

    private static async Task<(Fido2Authenticator, PresenceGate)> CreateAsync(bool approve)
    {
        var manager = new Fido2SecretManager(new MemoryBasedSecretStore(), new InMemoryCredentialStore());
        for (byte i = 1; i <= 2; i++)
            await manager.CreateCredentialAsync("example.com", [i], "user" + i, "User", true, 1);
        var gate = new PresenceGate(approve);
        return (await Fido2Authenticator.CreateAsync(manager, new byte[16], gate), gate);
    }

    private sealed class PresenceGate(bool approve) : IUserPresenceGate
    {
        public int Calls { get; private set; }
        public bool RequestApproval(string operation, string rpId) { Calls++; return approve; }
    }
}
