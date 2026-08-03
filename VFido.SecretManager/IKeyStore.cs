namespace VFido.SecretManager
{
    /// <summary>
    /// Creates and reloads credential signing keys. This is the seam different secret backends
    /// implement (file-based, TPM-based, server-based): CreateEs256Key() would ask the backend
    /// for a key and LoadKey() would rehydrate a wrapper around its persistent handle, keeping
    /// ICredentialStore and Fido2Authenticator unaware of where keys actually live.
    /// </summary>
    public interface IKeyStore
    {
        /// <summary>Fixed 16-byte AAGUID identifying this store's authenticator model, embedded in authenticatorData and the attestation leaf certificate.</summary>
        byte[] Aaguid { get; }

        ISigningKey CreateEs256Key();
        ISigningKey LoadKey(byte[] handle);

        /// <summary>Permanently removes a key previously returned by <see cref="CreateEs256Key"/>, identified by its exported handle.</summary>
        void DeleteKey(byte[] handle);

        /// <summary>
        /// Returns this authenticator's attestation key/certificate chain, generating and
        /// persisting a self-signed root CA and a leaf certificate it issues on first call.
        /// Stable across calls: every MakeCredential attests with the same chain, the way a real
        /// authenticator's batch attestation certificate would.
        /// </summary>
        AttestationCertificate GetOrCreateAttestationCertificate();
    }

    /// <summary>
    /// A persisted leaf attestation key handle (loadable via <see cref="IKeyStore.LoadKey"/>) paired
    /// with its DER certificate chain, leaf first followed by the issuing root CA.
    /// </summary>
    public sealed record AttestationCertificate(byte[] KeyHandle, IReadOnlyList<byte[]> CertificateChainDer);
}
