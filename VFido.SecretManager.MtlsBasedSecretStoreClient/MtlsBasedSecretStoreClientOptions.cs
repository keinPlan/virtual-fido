using System.Security.Cryptography.X509Certificates;

namespace VFido.SecretManager.MtlsBasedSecretStoreClient
{
    /// <summary>
    /// Everything <see cref="MtlsBasedSecretStoreClient"/> needs to reach a server-hosted
    /// <see cref="IFido2SecretManager"/> over mutual TLS: the server address, the client's own
    /// leaf certificate (issued by the server's CA, proves this device's identity - its CN is
    /// the username, so none is configured separately), the CA certificate to validate the
    /// server's presented certificate against, and the password presented once the channel is
    /// established.
    /// </summary>
    public sealed class MtlsBasedSecretStoreClientOptions
    {
        /// <summary>Base address of the secret manager server, e.g. https://secrets.example.internal:5443.</summary>
        public required Uri ServerBaseAddress { get; init; }

        /// <summary>This client's leaf certificate (with private key) issued by <see cref="ServerCaCertificate"/>.</summary>
        public required X509Certificate2 ClientCertificate { get; init; }

        /// <summary>CA certificate the server's certificate must chain to; pins the connection against MITM.</summary>
        public required X509Certificate2 ServerCaCertificate { get; init; }

        public required string Password { get; init; }
    }
}
