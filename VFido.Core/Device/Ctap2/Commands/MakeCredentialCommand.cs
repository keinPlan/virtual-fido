using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using VFido.Core.Device.Ctap2.Authenticator;
using VFido.Core.Device.Ctap2.Errors;
using VFido.Core.Device.Ctap2.Model;

namespace VFido.Core.Device.Ctap2.Commands
{
    /// <summary>authenticatorMakeCredential (0x01), CTAP2 section 6.1.</summary>
    internal static class MakeCredentialCommand
    {
        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        internal static async Task<byte[]> Handle(byte[] body, IAuthenticator authenticator)
        {
            var request = Decode(body);
            Logger.Debug(() => $"authenticatorMakeCredential rp={request.RelyingParty.Id} user={request.User.Name} " +
                $"excludeListCount={request.ExcludeList?.Count ?? 0} rk={request.RequireResidentKey} uv={request.RequireUserVerification}");

            var result = await authenticator.MakeCredentialAsync(request);
            return Encode(result);
        }

        private static MakeCredentialRequest Decode(byte[] body)
        {
            var reader = new CborReader(body, CborConformanceMode.Lax);
            reader.ReadStartMap();

            byte[]? clientDataHash = null;
            RelyingParty? rp = null;
            UserEntity? user = null;
            List<PublicKeyCredentialParameters>? pubKeyCredParams = null;
            List<byte[]>? excludeList = null;
            byte[]? pinUvAuthParam = null;
            byte? pinUvAuthProtocol = null;
            var residentKey = false;
            var requireUserVerification = false;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadInt32())
                {
                    case 1:
                        clientDataHash = reader.ReadByteString();
                        break;
                    case 2:
                        rp = DecodeRp(reader);
                        break;
                    case 3:
                        user = DecodeUser(reader);
                        break;
                    case 4:
                        pubKeyCredParams = DecodeParams(reader);
                        break;
                    case 5:
                        excludeList = DecodeCredentialIdList(reader);
                        break;
                    case 7:
                        (residentKey, requireUserVerification) = DecodeOptions(reader);
                        break;
                    case 8:
                        pinUvAuthParam = reader.ReadByteString();
                        break;
                    case 9:
                        pinUvAuthProtocol = (byte)reader.ReadInt32();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }
            reader.ReadEndMap();

            if (clientDataHash == null || rp == null || user == null || pubKeyCredParams is not { Count: > 0 })
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            return new MakeCredentialRequest(clientDataHash, rp, user, pubKeyCredParams, pinUvAuthParam, pinUvAuthProtocol, residentKey, requireUserVerification, excludeList);
        }

        private static List<byte[]> DecodeCredentialIdList(CborReader reader)
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

        private static (bool ResidentKey, bool UserVerification) DecodeOptions(CborReader reader)
        {
            reader.ReadStartMap();
            var rk = false;
            var uv = false;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadTextString())
                {
                    case "rk": rk = reader.ReadBoolean(); break;
                    case "uv": uv = reader.ReadBoolean(); break;
                    default: reader.SkipValue(); break;
                }
            }
            reader.ReadEndMap();

            return (rk, uv);
        }

        private static RelyingParty DecodeRp(CborReader reader)
        {
            reader.ReadStartMap();
            string? id = null, name = null;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadTextString())
                {
                    case "id": id = reader.ReadTextString(); break;
                    case "name": name = reader.ReadTextString(); break;
                    default: reader.SkipValue(); break;
                }
            }
            reader.ReadEndMap();

            if (id == null)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            return new RelyingParty(id, name ?? string.Empty);
        }

        private static UserEntity DecodeUser(CborReader reader)
        {
            reader.ReadStartMap();
            byte[]? id = null;
            string? name = null, displayName = null;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadTextString())
                {
                    case "id": id = reader.ReadByteString(); break;
                    case "name": name = reader.ReadTextString(); break;
                    case "displayName": displayName = reader.ReadTextString(); break;
                    default: reader.SkipValue(); break;
                }
            }
            reader.ReadEndMap();

            if (id == null)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            return new UserEntity(id, name ?? string.Empty, displayName ?? string.Empty);
        }

        private static List<PublicKeyCredentialParameters> DecodeParams(CborReader reader)
        {
            var list = new List<PublicKeyCredentialParameters>();
            reader.ReadStartArray();

            while (reader.PeekState() != CborReaderState.EndArray)
            {
                reader.ReadStartMap();
                string? type = null;
                var alg = 0;

                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    switch (reader.ReadTextString())
                    {
                        case "type": type = reader.ReadTextString(); break;
                        case "alg": alg = reader.ReadInt32(); break;
                        default: reader.SkipValue(); break;
                    }
                }
                reader.ReadEndMap();
                list.Add(new PublicKeyCredentialParameters(type ?? "public-key", alg));
            }
            reader.ReadEndArray();

            return list;
        }

        private static byte[] Encode(MakeCredentialResult result)
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

            writer.WriteStartMap(3);

            writer.WriteInt32(1); // fmt
            writer.WriteTextString("packed");

            writer.WriteInt32(2); // authData
            writer.WriteByteString(result.AuthenticatorData);

            writer.WriteInt32(3); // attStmt
            writer.WriteStartMap(2);
            writer.WriteTextString("alg");
            writer.WriteInt32(result.Algorithm);
            writer.WriteTextString("sig");
            writer.WriteByteString(result.Signature);
            writer.WriteEndMap();

            writer.WriteEndMap();

            return writer.Encode();
        }
    }
}
