using System.Collections.Generic;
using System.Formats.Cbor;
using VFido.Core.Device.Ctap2.Authenticator;
using VFido.Core.Device.Ctap2.Errors;
using VFido.Core.Device.Ctap2.Model;

namespace VFido.Core.Device.Ctap2.Commands
{
    /// <summary>authenticatorGetAssertion (0x02), CTAP2 section 6.2.</summary>
    internal static class GetAssertionCommand
    {
        internal static async Task<byte[]> Handle(byte[] body, IAuthenticator authenticator)
        {
            var request = Decode(body);
            var result = await authenticator.GetAssertionAsync(request);
            return Encode(result);
        }

        private static GetAssertionRequest Decode(byte[] body)
        {
            var reader = new CborReader(body, CborConformanceMode.Lax);
            reader.ReadStartMap();

            string? rpId = null;
            byte[]? clientDataHash = null;
            var allowList = new List<byte[]>();
            byte[]? pinUvAuthParam = null;
            byte? pinUvAuthProtocol = null;
            var requireUserVerification = false;
            var requireUserPresence = true;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadInt32())
                {
                    case 1:
                        rpId = reader.ReadTextString();
                        break;
                    case 2:
                        clientDataHash = reader.ReadByteString();
                        break;
                    case 3:
                        allowList = DecodeAllowList(reader);
                        break;
                    case 5:
                        (requireUserVerification, requireUserPresence) = DecodeOptions(reader);
                        break;
                    case 6:
                        pinUvAuthParam = reader.ReadByteString();
                        break;
                    case 7:
                        pinUvAuthProtocol = (byte)reader.ReadInt32();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }
            reader.ReadEndMap();

            if (rpId == null || clientDataHash == null)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            return new GetAssertionRequest(rpId, clientDataHash, allowList, pinUvAuthParam, pinUvAuthProtocol, requireUserVerification, requireUserPresence);
        }

        // "up" (user presence) defaults to true per CTAP2 6.2; a platform sets it to false for a
        // silent credential probe (e.g. WebAuthn conditional mediation / autofill discovery) that
        // must not prompt the user at all.
        private static (bool uv, bool up) DecodeOptions(CborReader reader)
        {
            reader.ReadStartMap();
            var uv = false;
            var up = true;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadTextString())
                {
                    case "uv": uv = reader.ReadBoolean(); break;
                    case "up": up = reader.ReadBoolean(); break;
                    default: reader.SkipValue(); break;
                }
            }
            reader.ReadEndMap();

            return (uv, up);
        }

        private static List<byte[]> DecodeAllowList(CborReader reader)
        {
            var list = new List<byte[]>();
            reader.ReadStartArray();

            while (reader.PeekState() != CborReaderState.EndArray)
            {
                reader.ReadStartMap();
                byte[]? id = null;

                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    switch (reader.ReadTextString())
                    {
                        case "id": id = reader.ReadByteString(); break;
                        default: reader.SkipValue(); break;
                    }
                }
                reader.ReadEndMap();

                if (id != null)
                    list.Add(id);
            }
            reader.ReadEndArray();

            return list;
        }

        internal static byte[] Encode(GetAssertionResult result)
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

            var fieldCount = 3 + (result.User != null ? 1 : 0) + (result.NumberOfCredentials != null ? 1 : 0);
            writer.WriteStartMap(fieldCount);

            writer.WriteInt32(1); // credential
            writer.WriteStartMap(2);
            writer.WriteTextString("id");
            writer.WriteByteString(result.CredentialId);
            writer.WriteTextString("type");
            writer.WriteTextString("public-key");
            writer.WriteEndMap();

            writer.WriteInt32(2); // authData
            writer.WriteByteString(result.AuthenticatorData);

            writer.WriteInt32(3); // signature
            writer.WriteByteString(result.Signature);

            if (result.User is { } user)
            {
                // Only disclose name/displayName when the platform has to distinguish between
                // multiple discoverable accounts for this RP; a single match keeps just the id.
                // This must stay true for every authenticatorGetNextAssertion in the sequence too,
                // not just the first response (which is the only one carrying numberOfCredentials).
                var includeNames = result.IncludeUserDetails;
                writer.WriteInt32(4); // user
                writer.WriteStartMap(includeNames ? 3 : 1);
                writer.WriteTextString("id");
                writer.WriteByteString(user.Id);
                if (includeNames)
                {
                    writer.WriteTextString("name");
                    writer.WriteTextString(user.Name);
                    writer.WriteTextString("displayName");
                    writer.WriteTextString(user.DisplayName);
                }
                writer.WriteEndMap();
            }

            if (result.NumberOfCredentials is { } numberOfCredentials)
            {
                writer.WriteInt32(5); // numberOfCredentials
                writer.WriteInt32(numberOfCredentials);
            }

            writer.WriteEndMap();

            return writer.Encode();
        }
    }
}
