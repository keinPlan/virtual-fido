using System.Security.Cryptography;

namespace VFido.SecretManager.Crypto
{
    public static class EcdsaProvider
    {
        public static ECDsa GenerateP256() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

        /// <summary>
        /// CTAP2/COSE ES256 signatures are DER (ASN.1 SEQUENCE of r,s), not the IEEE P1363
        /// concatenation .NET defaults to.
        /// </summary>
        public static byte[] SignDerSha256(ECDsa key, byte[] data) =>
            key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }
}
