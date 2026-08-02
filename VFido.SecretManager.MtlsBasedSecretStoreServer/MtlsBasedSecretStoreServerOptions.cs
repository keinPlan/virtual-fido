namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>Bound from configuration section "MtlsBasedSecretStoreServer".</summary>
    public sealed class MtlsBasedSecretStoreServerOptions
    {
        public int ListenPort { get; set; } = 5443;

        /// <summary>PFX containing this server's TLS certificate + private key (presented to clients).</summary>
        public required string ServerCertificatePath { get; set; }
        public string? ServerCertificatePassword { get; set; }

        /// <summary>CA certificate (public only) that every client's leaf certificate must chain to.</summary>
        public required string ClientCaCertificatePath { get; set; }

        public string SeedUsername { get; set; } = "admin";
        public string SeedPassword { get; set; } = "changeme";

        public int TokenLifetimeMinutes { get; set; } = 30;
    }
}
