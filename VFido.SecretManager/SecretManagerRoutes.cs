namespace VFido.SecretManager
{
    /// <summary>Wire-level route constants shared by <c>MtlsBasedSecretStoreClient</c> and the server host.</summary>
    public static class SecretManagerRoutes
    {
        public const string Login = "/api/secretmanager/login";
        public const string CreateCredential = "/api/secretmanager/credentials/create";
        public const string CredentialExists = "/api/secretmanager/credentials/exists";
        public const string FindCredential = "/api/secretmanager/credentials/find";
        public const string FindResidentCredentials = "/api/secretmanager/credentials/resident";
        public const string FindAllCredentials = "/api/secretmanager/credentials/all";
        public const string DeleteCredential = "/api/secretmanager/credentials/delete";
        public const string IncrementSignCount = "/api/secretmanager/credentials/increment-sign-count";
        public const string Sign = "/api/secretmanager/credentials/sign";
        public const string GetAttestationCertificate = "/api/secretmanager/attestation/certificate";
        public const string SignWithAttestationKey = "/api/secretmanager/attestation/sign";
    }
}
