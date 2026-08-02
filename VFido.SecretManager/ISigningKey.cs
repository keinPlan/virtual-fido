namespace VFido.SecretManager
{
    /// <summary>
    /// A single credential's signing key. Never exposes raw private key material - only the
    /// operations CTAP2 actually needs - so a TPM-backed implementation (private key stays in
    /// the TPM, Sign() becomes a TPM2_Sign call) can drop in without changing any caller.
    /// </summary>
    public interface ISigningKey
    {
        /// <summary>COSE algorithm identifier (e.g. -7 for ES256).</summary>
        int CoseAlgorithm { get; }

        /// <summary>DER-encoded (ASN.1 SEQUENCE of r,s) signature over <paramref name="data"/>.</summary>
        byte[] Sign(byte[] data);

        /// <summary>COSE_Key CBOR encoding of the public key, for attestedCredentialData.</summary>
        byte[] ExportCosePublicKey();

        /// <summary>
        /// Opaque, provider-specific bytes that let <see cref="IKeyStore.LoadKey"/> recover this
        /// key later. For file-based keys this is a PKCS8 private key blob; for a TPM-backed
        /// provider it would be a persistent handle or a TPM-wrapped key blob - never raw key
        /// material that could be reconstructed outside the TPM.
        /// </summary>
        byte[] ExportHandle();
    }
}
