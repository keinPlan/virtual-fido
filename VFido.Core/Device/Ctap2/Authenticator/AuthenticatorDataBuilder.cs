using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VFido.Core.Device.Ctap2.Authenticator
{
    /// <summary>Builds the authData byte string embedded in attestation objects and assertions (CTAP2 section 6.1).</summary>
    internal static class AuthenticatorDataBuilder
    {
        private const byte FlagUserPresent = 0x01;
        private const byte FlagUserVerified = 0x04;
        private const byte FlagAttestedCredentialDataIncluded = 0x40;
        private const byte FlagExtensionDataIncluded = 0x80;

        /// <summary><paramref name="extensions"/>, if given, must already be a CBOR-encoded extensions map (e.g. the credProtect output) - it's appended as-is and sets the ED flag.</summary>
        internal static byte[] BuildWithAttestedCredential(string rpId, byte[] aaguid, byte[] credentialId, byte[] coseKey, uint signCount, bool userVerified = false, byte[]? extensions = null)
        {
            using var ms = new MemoryStream();
            ms.Write(ComputeRpIdHash(rpId));
            var flags = FlagUserPresent | FlagAttestedCredentialDataIncluded | (userVerified ? FlagUserVerified : 0) | (extensions != null ? FlagExtensionDataIncluded : 0);
            ms.WriteByte((byte)flags);
            WriteUInt32BigEndian(ms, signCount);
            ms.Write(aaguid);
            WriteUInt16BigEndian(ms, (ushort)credentialId.Length);
            ms.Write(credentialId);
            ms.Write(coseKey);
            if (extensions != null)
                ms.Write(extensions);
            return ms.ToArray();
        }

        internal static byte[] BuildWithoutAttestedCredential(string rpId, uint signCount, bool userVerified = false)
        {
            using var ms = new MemoryStream();
            ms.Write(ComputeRpIdHash(rpId));
            ms.WriteByte((byte)(FlagUserPresent | (userVerified ? FlagUserVerified : 0)));
            WriteUInt32BigEndian(ms, signCount);
            return ms.ToArray();
        }

        private static byte[] ComputeRpIdHash(string rpId) => SHA256.HashData(Encoding.UTF8.GetBytes(rpId));

        private static void WriteUInt32BigEndian(Stream stream, uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
            stream.Write(buffer);
        }

        private static void WriteUInt16BigEndian(Stream stream, ushort value)
        {
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
            stream.Write(buffer);
        }
    }
}
