namespace VFido.Core.Device.Ctap2.Model
{
    /// <summary>
    /// Everything the "packed" self-attestation statement and outer CTAP2 response need.
    /// CBOR encoding stays in the Commands layer; this record carries plain values only.
    /// </summary>
    internal record MakeCredentialResult(byte[] AuthenticatorData, int Algorithm, byte[] Signature);
}
