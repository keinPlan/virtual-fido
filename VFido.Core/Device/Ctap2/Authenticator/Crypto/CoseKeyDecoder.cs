using System.Formats.Cbor;
using System.Security.Cryptography;
using VFido.Core.Device.Ctap2.Errors;

namespace VFido.Core.Device.Ctap2.Authenticator.Crypto
{
    /// <summary>Decodes a COSE_Key EC2 public key (as sent by the platform in ClientPIN's keyAgreement field).</summary>
    internal static class CoseKeyDecoder
    {
        internal static ECParameters DecodePublicKey(CborReader reader)
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
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            return new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            };
        }
    }
}
