using System.Formats.Cbor;
using System.Security.Cryptography;

namespace VFido.SecretManager.Crypto
{
    /// <summary>Encodes an EC public key as a COSE_Key CBOR map (RFC 9053).</summary>
    public static class CoseKeyEncoder
    {
        private const int KtyEc2 = 2;
        private const int AlgEs256 = -7;
        private const int AlgEcdhEsHkdf256 = -25;
        private const int CrvP256 = 1;

        /// <summary>For a credential's public key, embedded in attestedCredentialData.</summary>
        public static byte[] Encode(ECParameters publicKeyParameters) => Encode(publicKeyParameters, AlgEs256);

        /// <summary>
        /// For the authenticator's ephemeral key-agreement public key (ClientPIN getKeyAgreement).
        /// This key is only ever used for ECDH, never for signing - CTAP2 requires it be tagged
        /// with the ECDH algorithm, not ES256, or strict clients (Windows Hello, Chrome) reject it
        /// and silently abort the PIN ceremony.
        /// </summary>
        public static byte[] EncodeKeyAgreementKey(ECParameters publicKeyParameters) => Encode(publicKeyParameters, AlgEcdhEsHkdf256);

        private static byte[] Encode(ECParameters publicKeyParameters, int alg)
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

            writer.WriteStartMap(5);
            writer.WriteInt32(1); // kty
            writer.WriteInt32(KtyEc2);
            writer.WriteInt32(3); // alg
            writer.WriteInt32(alg);
            writer.WriteInt32(-1); // crv
            writer.WriteInt32(CrvP256);
            writer.WriteInt32(-2); // x
            writer.WriteByteString(publicKeyParameters.Q.X!);
            writer.WriteInt32(-3); // y
            writer.WriteByteString(publicKeyParameters.Q.Y!);
            writer.WriteEndMap();

            return writer.Encode();
        }
    }
}
