using System.Formats.Cbor;
using VFido.Core.Device.Ctap2.Authenticator;
using VFido.Core.Device.Ctap2.Authenticator.Crypto;
using VFido.Core.Device.Ctap2.Errors;
using VFido.Core.Device.Ctap2.Model;

namespace VFido.Core.Device.Ctap2.Commands
{
    /// <summary>authenticatorClientPIN (0x06), CTAP2 section 6.5. PIN/UV Auth Protocol One only.</summary>
    internal static class ClientPinCommand
    {
        internal static byte[] Handle(byte[] body, IAuthenticator authenticator)
        {
            var request = Decode(body);
            var result = authenticator.ClientPin(request);
            return Encode(result);
        }

        private static ClientPinRequest Decode(byte[] body)
        {
            var reader = new CborReader(body, CborConformanceMode.Lax);
            reader.ReadStartMap();

            byte pinProtocol = 0;
            byte subCommand = 0;
            System.Security.Cryptography.ECParameters? keyAgreement = null;
            byte[]? pinUvAuthParam = null;
            byte[]? newPinEnc = null;
            byte[]? pinHashEnc = null;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadInt32())
                {
                    case 1:
                        pinProtocol = (byte)reader.ReadInt32();
                        break;
                    case 2:
                        subCommand = (byte)reader.ReadInt32();
                        break;
                    case 3:
                        keyAgreement = CoseKeyDecoder.DecodePublicKey(reader);
                        break;
                    case 4:
                        pinUvAuthParam = reader.ReadByteString();
                        break;
                    case 5:
                        newPinEnc = reader.ReadByteString();
                        break;
                    case 6:
                        pinHashEnc = reader.ReadByteString();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }
            reader.ReadEndMap();

            if (subCommand == 0)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            return new ClientPinRequest(pinProtocol, subCommand, keyAgreement, pinUvAuthParam, newPinEnc, pinHashEnc);
        }

        private static byte[] Encode(ClientPinResult result)
        {
            var fieldCount = (result.KeyAgreementPublicKey != null ? 1 : 0)
                           + (result.PinUvAuthTokenEnc != null ? 1 : 0)
                           + (result.PinRetries != null ? 1 : 0);

            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
            writer.WriteStartMap(fieldCount);

            if (result.KeyAgreementPublicKey is { } publicKey)
            {
                writer.WriteInt32(1);
                writer.WriteEncodedValue(CoseKeyEncoder.EncodeKeyAgreementKey(publicKey));
            }
            if (result.PinUvAuthTokenEnc != null)
            {
                writer.WriteInt32(2);
                writer.WriteByteString(result.PinUvAuthTokenEnc);
            }
            if (result.PinRetries != null)
            {
                writer.WriteInt32(3);
                writer.WriteInt32(result.PinRetries.Value);
            }

            writer.WriteEndMap();
            return writer.Encode();
        }
    }
}
