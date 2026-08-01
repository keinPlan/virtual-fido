namespace VFido.Core.Device.Ctap2.Authenticator.Keys
{
    /// <summary>
    /// Creates and reloads credential signing keys. This is the seam a future TPM-backed
    /// provider implements: CreateEs256Key() would ask the TPM for a non-exportable key and
    /// LoadKey() would rehydrate a wrapper around its persistent handle, keeping
    /// ICredentialStore and Fido2Authenticator unaware of where keys actually live.
    /// </summary>
    internal interface IKeyStore
    {
        ISigningKey CreateEs256Key();
        ISigningKey LoadKey(byte[] handle);
    }
}
