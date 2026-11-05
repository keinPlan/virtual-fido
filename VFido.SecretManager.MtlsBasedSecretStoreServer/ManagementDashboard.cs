using System.Security.Cryptography.X509Certificates;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer;

public static class ManagementDashboard
{
    public static bool IsAdministrator(X509Certificate2? certificate, IEnumerable<string> thumbprints) =>
        certificate is not null && thumbprints.Any(value =>
            string.Equals(value.Replace(" ", "").Replace(":", ""), certificate.Thumbprint,
                StringComparison.OrdinalIgnoreCase));

    public static void MapManagementDashboard(this WebApplication app,
        MtlsBasedSecretStoreServerOptions options, X509Certificate2 serverCertificate)
    {
        var startedAt = DateTimeOffset.UtcNow;
        // Protect assets and data alike, independently of ordinary user identity resolution.
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/admin"))
            {
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                context.Response.Headers["Content-Security-Policy"] =
                    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
                if (!IsAdministrator(context.Connection.ClientCertificate, options.AdminCertificateThumbprints))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("Dashboard access requires an administrator client certificate.");
                    return;
                }
            }
            await next(context);
        });

        app.MapGet("/admin", () => Asset("index.html", "text/html"));
        app.MapGet("/admin/dashboard.css", () => Asset("dashboard.css", "text/css"));
        app.MapGet("/admin/dashboard.js", () => Asset("dashboard.js", "text/javascript"));
        app.MapGet("/admin/api/overview", (SessionTokenService sessions, ILoggerFactory logging) =>
        {
            try
            {
                var counts = sessions.GetActiveSessionCounts();
                var users = Directory.Exists(options.SecretsRootPath)
                    ? Directory.EnumerateDirectories(options.SecretsRootPath)
                        .Where(path => (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0)
                        .Select(path =>
                        {
                            var name = Path.GetFileName(path);
                            var credentials = Path.Combine(path, "credentials");
                            return new
                            {
                                name,
                                passwordRequired = File.Exists(Path.Combine(path, "verifier.bin")),
                                credentialCount = Directory.Exists(credentials)
                                    ? Directory.EnumerateFiles(credentials, "*.cred").Count() : 0,
                                activeSessions = counts.GetValueOrDefault(name),
                                certificateIssued = File.Exists(Path.Combine(path, "client.pfx"))
                            };
                        }).OrderBy(user => user.name, StringComparer.OrdinalIgnoreCase).ToArray()
                    : [];
                return Results.Ok(new
                {
                    startedAt, observedAt = DateTimeOffset.UtcNow,
                    listenPort = options.ListenPort, tokenLifetimeMinutes = options.TokenLifetimeMinutes,
                    certificateExpiresAt = serverCertificate.NotAfter.ToUniversalTime(),
                    certificateSubject = serverCertificate.GetNameInfo(X509NameType.SimpleName, false),
                    activeSessions = counts.Values.Sum(), users
                });
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                logging.CreateLogger("ManagementDashboard").LogError(exception, "Unable to read dashboard inventory.");
                return Results.Problem("Unable to read the user inventory. Check the server logs.", statusCode: 503);
            }
        });
    }

    private static IResult Asset(string name, string contentType)
    {
        var stream = typeof(ManagementDashboard).Assembly.GetManifestResourceStream(
            $"VFido.SecretManager.MtlsBasedSecretStoreServer.Dashboard.{name}")!;
        return Results.Stream(stream, contentType);
    }
}
