namespace VFido.Core.Device.Ctap2.Authenticator
{
    internal class StoredCredential
    {
        internal required byte[] CredentialId { get; init; }
        internal required string RpId { get; init; }
        internal required byte[] UserId { get; init; }

        /// <summary>Opaque handle from IKeyStore.CreateEs256Key/ExportHandle - never raw key material.</summary>
        internal required byte[] KeyHandle { get; init; }

        internal uint SignCount { get; set; }

        /// <summary>Set when created with options.rk=true; only resident credentials are discoverable via an empty allowList.</summary>
        internal bool IsResident { get; init; }

        internal string UserName { get; init; } = string.Empty;
        internal string UserDisplayName { get; init; } = string.Empty;
    }
}
