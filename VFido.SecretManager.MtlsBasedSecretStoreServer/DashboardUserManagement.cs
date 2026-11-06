using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;
using VFido.SecretManager.Protection;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer;

public sealed record CreateDashboardUser(string Username, string CaPassphrase, string? LoginPassword, string? PfxPassword, bool NoPassword);
public sealed record RevokeDashboardCertificate(string? PfxPassword);

public sealed class DashboardUserManagement(MtlsBasedSecretStoreServerOptions options, RevocationStore revocations)
{
    private readonly object sync = new();

    public string UserPath(string username)
    {
        if (string.IsNullOrEmpty(username) || !Regex.IsMatch(username, @"\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\z") ||
            Regex.IsMatch(username, @"\A(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])\z", RegexOptions.IgnoreCase))
            throw new ArgumentException("Use 1–64 letters, numbers, underscores or hyphens, starting with a letter or number; reserved device names are not allowed.");
        var path = Path.Combine(options.SecretsRootPath, username);
        if (Directory.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException("Linked user directories cannot be managed.");
        return path;
    }

    public byte[] Create(CreateDashboardUser request)
    {
        lock (sync)
        {
            var destination = UserPath(request.Username);
            if (Directory.Exists(destination) || File.Exists(destination))
                throw new InvalidOperationException("That user already exists.");
            if (string.IsNullOrEmpty(request.CaPassphrase) || (!request.NoPassword && string.IsNullOrEmpty(request.LoginPassword)))
                throw new ArgumentException("CA passphrase and, unless certificate-only is selected, login password are required.");
            var pfx = new CaManager(options.PkiRootPath).IssueClientCertificate(request.Username, request.CaPassphrase, request.PfxPassword);
            using var certificate = new X509Certificate2(pfx, request.PfxPassword, X509KeyStorageFlags.EphemeralKeySet);
            Directory.CreateDirectory(options.SecretsRootPath);
            var stagingRoot = options.SecretsRootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + ".provisioning";
            var staging = Path.Combine(stagingRoot, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(staging);
            try
            {
                ServerTpmMaster.CopyToUser(options, staging);
                if (!request.NoPassword)
                {
                    using var protection = PasswordStorageProtection.Create(staging, request.Username, request.LoginPassword!);
                }
                File.WriteAllBytes(Path.Combine(staging, "client.pfx"), pfx);
                File.WriteAllBytes(Path.Combine(staging, "client.cer"), certificate.Export(X509ContentType.Cert));
                Directory.Move(staging, destination);
                return pfx;
            }
            finally
            {
                if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
            }
        }
    }

    public void Revoke(string username, string? password, string? administratorThumbprint)
    {
        lock (sync)
        {
            var directory = UserPath(username);
            var publicPath = Path.Combine(directory, "client.cer");
            using var certificate = File.Exists(publicPath)
                ? new X509Certificate2(publicPath)
                : new X509Certificate2(Path.Combine(directory, "client.pfx"), password, X509KeyStorageFlags.EphemeralKeySet);
            if (string.Equals(certificate.Thumbprint, administratorThumbprint, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Use another administrator certificate to revoke your current certificate.");
            if (!File.Exists(publicPath))
                File.WriteAllBytes(publicPath, certificate.Export(X509ContentType.Cert));
            revocations.Revoke(options.PkiRootPath, certificate.SerialNumber);
        }
    }

    public bool? IsRevoked(string directory)
    {
        var path = Path.Combine(directory, "client.cer");
        if (!File.Exists(path)) return null;
        using var certificate = new X509Certificate2(path);
        return revocations.IsRevoked(certificate.SerialNumber);
    }
}
