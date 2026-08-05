using System.Text.Json;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer.Pki
{
    /// <summary>
    /// A local revoked-serials list, checked against every presented client certificate alongside
    /// the usual chain validation (Kestrel's ClientCertificateValidation callback doesn't check a
    /// CRL/OCSP responder - this is the lightweight local equivalent). Loaded once at server startup;
    /// picking up a revocation added by <c>revoke-user</c> requires restarting the server, which is an
    /// accepted, documented limitation for this pass.
    /// </summary>
    public sealed class RevocationStore
    {
        private const string FileName = "revoked.json";

        private readonly HashSet<string> _revokedSerials;

        private RevocationStore(HashSet<string> revokedSerials) => _revokedSerials = revokedSerials;

        public static RevocationStore Load(string pkiRoot)
        {
            var path = Path.Combine(pkiRoot, FileName);
            if (!File.Exists(path))
                return new RevocationStore(new HashSet<string>(StringComparer.OrdinalIgnoreCase));

            var serials = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) ?? new List<string>();
            return new RevocationStore(new HashSet<string>(serials, StringComparer.OrdinalIgnoreCase));
        }

        public bool IsRevoked(string serialNumberHex) => _revokedSerials.Contains(serialNumberHex);

        /// <summary>Appends a serial to the on-disk revocation list (used by the <c>revoke-user</c> admin command, not the running server).</summary>
        public static void Add(string pkiRoot, string serialNumberHex)
        {
            var path = Path.Combine(pkiRoot, FileName);
            var serials = File.Exists(path)
                ? JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) ?? new List<string>()
                : new List<string>();

            if (!serials.Contains(serialNumberHex, StringComparer.OrdinalIgnoreCase))
                serials.Add(serialNumberHex);

            File.WriteAllText(path, JsonSerializer.Serialize(serials));
        }
    }
}
