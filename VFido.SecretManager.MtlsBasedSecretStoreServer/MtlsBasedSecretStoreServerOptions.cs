namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>Bound from configuration section "MtlsBasedSecretStoreServer".</summary>
    public sealed class MtlsBasedSecretStoreServerOptions
    {
        /// <summary>Encrypt .cred metadata files. Existing directories require explicit conversion before changing this.</summary>
        public bool EncryptCredentialFiles { get; set; } = true;

        public int ListenPort { get; set; } = 5443;

        /// <summary>FIDO storage provider: File (default), Tpm, or Memory. Restart to change; existing credentials are not migrated.</summary>
        public ServerStorageProvider StorageProvider { get; set; } = ServerStorageProvider.File;

        /// <summary>PFX containing this server's TLS certificate + private key (presented to clients). Produced by the "init" admin command.</summary>
        public string ServerCertificatePath { get; set; } = "certs/server.pfx";
        public string? ServerCertificatePassword { get; set; }

        /// <summary>CA certificate (public only) that every client's leaf certificate must chain to. Produced by the "init" admin command.</summary>
        public string ClientCaCertificatePath { get; set; } = "certs/ca.crt";

        public int TokenLifetimeMinutes { get; set; } = 30;

        /// <summary>Client certificate SHA-1 thumbprints allowed to view /admin. Empty disables dashboard access.</summary>
        public string[] AdminCertificateThumbprints { get; set; } = [];

        /// <summary>Server PKI, protection certificate, and TPM master template in <c>tpm/master.json</c>. Defaults next to the server executable.</summary>
        public string PkiRootPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "pki");

        /// <summary>Per-user FIDO secrets: <c>&lt;SecretsRootPath&gt;\&lt;username&gt;\{keys,credentials,certs}</c>. Defaults next to the server executable.</summary>
        public string SecretsRootPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "VFido");

        /// <summary>Resolve configured relative paths against the executable directory for both CLI and server startup.</summary>
        public void ResolvePaths(string baseDirectory)
        {
            if (!Enum.IsDefined(StorageProvider))
                throw new InvalidOperationException("StorageProvider must be File, Tpm, or Memory.");
            ServerCertificatePath = Path.GetFullPath(ServerCertificatePath, baseDirectory);
            ClientCaCertificatePath = Path.GetFullPath(ClientCaCertificatePath, baseDirectory);
            PkiRootPath = Path.GetFullPath(PkiRootPath, baseDirectory);
            SecretsRootPath = Path.GetFullPath(SecretsRootPath, baseDirectory);
        }
    }

    public enum ServerStorageProvider { File, Tpm, Memory }
}
