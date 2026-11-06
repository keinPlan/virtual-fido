using System.Text.Json;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer.Pki
{
    /// <summary>
    /// A local revoked-serials list, checked against every presented client certificate alongside
    /// the usual chain validation (Kestrel's ClientCertificateValidation callback doesn't check a
    /// CRL/OCSP responder - this is the lightweight local equivalent). Loaded once at server startup;
    /// picking up a revocation added by <c>revoke-user</c> requires restarting the server.
    /// This is a CLI limitation. Dashboard revocations also update the live store immediately.
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

        private static readonly object Sync = new();

        public bool IsRevoked(string serialNumberHex)
        {
            lock (Sync) return _revokedSerials.Contains(serialNumberHex);
        }

        public void Revoke(string pkiRoot, string serialNumberHex)
        {
            lock (Sync)
            {
                Add(pkiRoot, serialNumberHex);
                _revokedSerials.Add(serialNumberHex);
            }
        }

        /// <summary>Atomically persists a serial to the on-disk list; use Revoke to update the live store too.</summary>
        public static void Add(string pkiRoot, string serialNumberHex)
        {
            lock (Sync)
            {
                var path = Path.Combine(pkiRoot, FileName);
                var serials = File.Exists(path)
                    ? JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) ?? new List<string>()
                    : new List<string>();

                if (!serials.Contains(serialNumberHex, StringComparer.OrdinalIgnoreCase))
                    serials.Add(serialNumberHex);

                var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    File.WriteAllText(temporary, JsonSerializer.Serialize(serials));
                    File.Move(temporary, path, overwrite: true);
                }
                finally { File.Delete(temporary); }
            }
        }
    }
}
