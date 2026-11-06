using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

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
                // A custom header prevents cross-origin form submissions with ambient mTLS credentials.
                // No cross-origin access is enabled for these endpoints.
                if (!HttpMethods.IsGet(context.Request.Method) &&
                    (context.Request.Headers["X-VFido-Admin"] != "1" ||
                     context.Request.Headers["Sec-Fetch-Site"] == "cross-site"))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return;
                }
            }
            await next(context);
        });

        app.MapGet("/admin", () => Asset("index.html", "text/html"));
        app.MapGet("/admin/dashboard.css", () => Asset("dashboard.css", "text/css"));
        app.MapGet("/admin/dashboard.js", () => Asset("dashboard.js", "text/javascript"));
        app.MapPost("/admin/api/users", (CreateDashboardUser request, DashboardUserManagement management, ILoggerFactory logging) =>
            Mutation(() =>
            {
                var pfx = management.Create(request);
                logging.CreateLogger("ManagementDashboard").LogInformation("Dashboard created user {Username}.", request.Username);
                return Results.File(pfx, "application/x-pkcs12", request.Username + ".pfx");
            }));
        app.MapPost("/admin/api/users/{username}/revoke", (string username, RevokeDashboardCertificate request,
            HttpContext context, DashboardUserManagement management, ILoggerFactory logging) =>
            Mutation(() =>
            {
                management.Revoke(username, request.PfxPassword, context.Connection.ClientCertificate?.Thumbprint);
                logging.CreateLogger("ManagementDashboard").LogInformation("Dashboard revoked certificate for {Username}.", username);
                return Results.Ok(new { message = "Certificate revoked. Subsequent requests are blocked immediately." });
            }));
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
                                credentialCount = options.StorageProvider == ServerStorageProvider.Memory
                                    ? app.Services.GetRequiredService<UserDirectoryResolver>().GetMemoryCredentialCount(name)
                                    : Directory.Exists(credentials) ? Directory.EnumerateFiles(credentials, "*.cred").Count() : 0,
                                activeSessions = counts.GetValueOrDefault(name),
                                certificateIssued = File.Exists(Path.Combine(path, "client.pfx")),
                                certificateRevoked = app.Services.GetRequiredService<DashboardUserManagement>().IsRevoked(path),
                                revocationPasswordRequired = !File.Exists(Path.Combine(path, "client.cer"))
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

    private static IResult Mutation(Func<IResult> action)
    {
        try { return action(); }
        catch (ArgumentException exception) { return Results.Problem(exception.Message, statusCode: 400); }
        catch (InvalidOperationException exception) { return Results.Problem(exception.Message, statusCode: 409); }
        catch (VFido.SecretManager.FileBasedSecretStore.InvalidCredentialsException)
        { return Results.Problem("Incorrect CA passphrase.", statusCode: 400); }
        catch (CryptographicException) { return Results.Problem("Unable to open certificate. Check the supplied passphrase or PFX password.", statusCode: 400); }
        catch (FileNotFoundException) { return Results.Problem("The required certificate file was not found.", statusCode: 404); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        { return Results.Problem("Unable to save the change. Check server storage and permissions.", statusCode: 503); }
    }

    private static IResult Asset(string name, string contentType)
    {
        var stream = typeof(ManagementDashboard).Assembly.GetManifestResourceStream(
            $"VFido.SecretManager.MtlsBasedSecretStoreServer.Dashboard.{name}")!;
        return Results.Stream(stream, contentType);
    }
}
