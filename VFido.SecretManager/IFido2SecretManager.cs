namespace VFido.SecretManager
{
    /// <summary>
    /// The only seam a CTAP2 authenticator implementation should touch for credential key
    /// material. All actual crypto (key generation, signing, handle export/import) happens
    /// behind this interface - callers only ever see credential ids, public keys, signatures
    /// and metadata, never a key handle or private key bytes.
    ///
    /// Async throughout so an implementation can live behind a network call (e.g. a
    /// server-hosted secret manager the authenticator talks to over a secure channel)
    /// without a different interface shape from the in-process case.
    /// </summary>
    public interface IFido2SecretManager
    {
        /// <summary>The fixed 16-byte AAGUID identifying this store's authenticator model.</summary>
        Task<byte[]> GetAaguidAsync();

        /// <summary>Generates a new credential key pair and persists it, returning only its public half.</summary>
        Task<CredentialRegistration> CreateCredentialAsync(string rpId, byte[] userId, string userName, string userDisplayName, bool isResident, int credProtect);

        /// <summary>True if a credential with this id exists for this RP (for authenticatorMakeCredential's excludeList).</summary>
        Task<bool> CredentialExistsAsync(byte[] credentialId, string rpId);

        /// <summary>Looks up a credential's metadata, scoped to the RP; null if not found or the RP doesn't match.</summary>
        Task<CredentialInfo?> FindCredentialAsync(byte[] credentialId, string rpId);

        /// <summary>All discoverable (resident) credentials for an RP, for allowList-less authenticatorGetAssertion.</summary>
        Task<IReadOnlyList<CredentialInfo>> FindResidentCredentialsAsync(string rpId);

        /// <summary>Every credential stored on this authenticator, across all RPs - metadata only, for a management UI.</summary>
        Task<IReadOnlyList<CredentialInfo>> FindAllCredentialsAsync();

        /// <summary>Permanently removes a stored credential (and its key handle) from this authenticator.</summary>
        Task DeleteCredentialAsync(byte[] credentialId);

        /// <summary>Increments and persists the credential's signature counter, returning the new value to embed in authenticatorData.</summary>
        Task<uint> IncrementSignCountAsync(byte[] credentialId);

        /// <summary>Signs <paramref name="data"/> (typically authenticatorData || clientDataHash) with the credential's key.</summary>
        Task<byte[]> SignAsync(byte[] credentialId, byte[] data);

        /// <summary>The DER-encoded certificate chain (leaf attestation certificate, then its issuing root CA) to embed as x5c in a "packed" attestation statement.</summary>
        Task<IReadOnlyList<byte[]>> GetAttestationCertificateChainAsync();

        /// <summary>Signs <paramref name="data"/> (typically authenticatorData || clientDataHash) with the leaf attestation key backing <see cref="GetAttestationCertificateChainAsync"/>.</summary>
        Task<byte[]> SignWithAttestationKeyAsync(byte[] data);

        /// <summary>The PIN hash and retry counter last saved via <see cref="SavePinStateAsync"/>, or null if no PIN has been set yet. An implementation with no durable backing may always return null, in which case PIN state stays process-lifetime only.</summary>
        Task<PinState?> LoadPinStateAsync();

        /// <summary>Persists the PIN hash and retry counter so they survive a reconnect/restart.</summary>
        Task SavePinStateAsync(PinState state);
    }
}
