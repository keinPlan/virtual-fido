using System.Buffers.Binary;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer;

/// <summary>
/// Describes the client-supplied assertion bytes being signed, not server-side proof
/// of PIN verification, user approval, or acceptance by the relying party.
/// </summary>
public sealed record AssertionLogMetadata(string AssertionKind, bool? UserPresent, bool? UserVerified, uint? SignCount)
{
    public static AssertionLogMetadata FromSigningData(byte[] data)
    {
        // Current assertions contain 37 bytes of authData followed by a 32-byte clientDataHash.
        // Do not interpret arbitrary signing payloads or unsupported extension/attestation layouts.
        if (data.Length != 69 || (data[32] & ~0x1D) != 0)
            return new("unrecognized signing data", null, null, null);

        var present = (data[32] & 0x01) != 0;
        var verified = (data[32] & 0x04) != 0;
        return new(present ? "user-present assertion" : "silent probe", present, verified,
            BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(33, 4)));
    }
}
