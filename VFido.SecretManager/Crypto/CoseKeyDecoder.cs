using System.Formats.Cbor;
using System.Security.Cryptography;

namespace VFido.SecretManager.Crypto
{
    /// <summary>Decodes a COSE_Key EC2 public key (as sent by the platform in ClientPIN's keyAgreement field).</summary>
    public static class CoseKeyDecoder
    {
        public static ECParameters DecodePublicKey(CborReader reader)
        {
            reader.ReadStartMap();

            byte[]? x = null, y = null;
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadInt32())
                {
                    case -2: x = reader.ReadByteString(); break;
                    case -3: y = reader.ReadByteString(); break;
                    default: reader.SkipValue(); break;
                }
            }
            reader.ReadEndMap();

            if (x == null || y == null)
                throw new InvalidOperationException("COSE_Key is missing required EC2 coordinate (-2/-3).");

            return new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            };
        }
    }
}
