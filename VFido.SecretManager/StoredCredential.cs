namespace VFido.SecretManager
{
    public class StoredCredential
    {
        public required byte[] CredentialId { get; init; }
        public required string RpId { get; init; }
        public required byte[] UserId { get; init; }

        /// <summary>Opaque handle from IKeyStore.CreateEs256Key/ExportHandle - never raw key material.</summary>
        public required byte[] KeyHandle { get; init; }

        public uint SignCount { get; set; }

        /// <summary>Set when created with options.rk=true; only resident credentials are discoverable via an empty allowList.</summary>
        public bool IsResident { get; init; }

        public string UserName { get; init; } = string.Empty;
        public string UserDisplayName { get; init; } = string.Empty;
    }
}
