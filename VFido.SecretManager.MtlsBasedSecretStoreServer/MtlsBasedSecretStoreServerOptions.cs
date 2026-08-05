namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>Bound from configuration section "MtlsBasedSecretStoreServer".</summary>
    public sealed class MtlsBasedSecretStoreServerOptions
    {
        public int ListenPort { get; set; } = 5443;

        /// <summary>PFX containing this server's TLS certificate + private key (presented to clients). Produced by the "init" admin command.</summary>
        public required string ServerCertificatePath { get; set; }
        public string? ServerCertificatePassword { get; set; }

        /// <summary>CA certificate (public only) that every client's leaf certificate must chain to. Produced by the "init" admin command.</summary>
        public required string ClientCaCertificatePath { get; set; }

        public int TokenLifetimeMinutes { get; set; } = 30;

        /// <summary>Root CA/intermediate CA/master protection cert state, managed by the admin CLI. Defaults next to the server executable.</summary>
        public string PkiRootPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "pki");

        /// <summary>Per-user FIDO secrets: <c>&lt;SecretsRootPath&gt;\&lt;username&gt;\{keys,credentials,certs}</c>. Defaults next to the server executable.</summary>
        public string SecretsRootPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "VFido");
    }
}
