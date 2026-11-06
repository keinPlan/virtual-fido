using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer;

/// <summary>A local, capability-protected bootstrap host, stopped before the mTLS host starts.</summary>
public static class FirstRunSetup
{
    public static bool IsFreshInstallation(MtlsBasedSecretStoreServerOptions options) =>
        !File.Exists(options.ServerCertificatePath) && !File.Exists(options.ClientCaCertificatePath)
        && !HasEntries(options.PkiRootPath) && !HasEntries(options.SecretsRootPath);

    private static bool HasEntries(string path) =>
        Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any();

    public static async Task<bool> RunAsync(MtlsBasedSecretStoreServerOptions options, string configurationPath,
        Action<string>? openBrowser = null, CancellationToken cancellationToken = default)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [] });
        // Never inherit a public URL, HTTPS setting, or request logging from the normal host.
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(IPAddress.Loopback, 0);
            kestrel.Limits.MaxRequestBodySize = 2 * 1024 * 1024;
        });
        await using var app = builder.Build();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var prefix = "/setup/" + token;
        var gate = new SemaphoreSlim(1, 1);
        var configured = false;
        var startServer = false;
        byte[]? adminPfx = null;
        byte[]? rootCertificate = null;
        var recoveryDownloaded = false;
        string? origin = null;

        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            // Browser form POSTs can acquire an opaque ("null") Origin with no-referrer.
            // Keep the origin for same-origin forms without leaking the capability URL elsewhere.
            context.Response.Headers["Referrer-Policy"] = "same-origin";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
            if (!IPAddress.IsLoopback(context.Connection.RemoteIpAddress ?? IPAddress.Any)
                || $"{context.Request.Scheme}://{context.Request.Host}" != origin
                || !context.Request.Path.StartsWithSegments(prefix)
                || (context.Request.Headers.Origin.Count > 0 && context.Request.Headers.Origin.ToString() != origin))
            {
                context.Response.StatusCode = 403;
                return;
            }
            await next(context);
        });

        app.MapGet(prefix, () => Results.Content(Page(configured
            ? Completed.Replace("{{recovery}}", options.StorageProvider == ServerStorageProvider.Tpm ? RecoveryDownload : "") : Form, prefix), "text/html"));
        app.MapPost(prefix, async (HttpContext context) =>
        {
            if (!context.Request.HasFormContentType) return Results.BadRequest("Expected a setup form.");
            var form = await context.Request.ReadFormAsync();
            var request = new SetupRequest(form["hostname"].ToString(), form["username"].ToString(),
                form["caPassword"].ToString(), form["certificatePassword"].ToString(),
                form["provider"].ToString(), int.TryParse(form["port"], out var port) ? port : 0,
                form["recoveryPassword"].ToString());
            var upload = form.Files.GetFile("recoveryPfx");
            if (request.Provider.Equals("Tpm", StringComparison.OrdinalIgnoreCase) && upload is { Length: > 0 })
            {
                if (upload.Length > 1_048_576) return Results.BadRequest("Recovery PFX must be at most 1 MiB.");
                using var memory = new MemoryStream();
                await upload.CopyToAsync(memory);
                request = request with { RecoveryPfx = memory.ToArray() };
            }
            var error = Validate(request);
            if (error is not null) return Results.BadRequest(error);
            await gate.WaitAsync();
            try
            {
                if (configured || !IsFreshInstallation(options))
                    return Results.Conflict("Setup has already run. Existing installation files will not be overwritten.");
                var result = Initialize(options, configurationPath, request);
                adminPfx = result.AdminPfx;
                rootCertificate = result.RootCertificate;
                configured = true;
                return Results.Redirect(prefix);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException or Tpm2Lib.TpmException)
            {
                Console.Error.WriteLine($"Setup could not complete ({exception.GetType().Name}). Check file permissions. Use the init CLI to repair a partial installation.");
                return Results.Problem("Setup could not complete. Check the server console. Existing files have not been overwritten.");
            }
            finally { gate.Release(); }
        });
        app.MapGet(prefix + "/administrator.pfx", () => adminPfx is null
            ? Results.NotFound() : Results.File(adminPfx, "application/x-pkcs12", "vfido-administrator.pfx"));
        app.MapGet(prefix + "/root.crt", () => rootCertificate is null
            ? Results.NotFound() : Results.File(rootCertificate, "application/pkix-cert", "vfido-root.crt"));
        app.MapGet(prefix + "/vfido-tpm-recovery.pfx", (HttpContext context) =>
        {
            if (!configured || options.StorageProvider != ServerStorageProvider.Tpm) return Results.NotFound();
            context.Response.OnCompleted(() => { recoveryDownloaded = true; return Task.CompletedTask; });
            return Results.File(ServerTpmMaster.RecoveryPath(options), "application/x-pkcs12", "vfido-tpm-recovery.pfx");
        });
        app.MapPost(prefix + "/start", (HttpContext context) =>
        {
            if (!configured) return Results.Conflict("Complete setup first.");
            if (options.StorageProvider == ServerStorageProvider.Tpm && !recoveryDownloaded)
                return Results.Conflict("Download vfido-tpm-recovery.pfx before starting. The server copy is deleted on startup.");
            startServer = true;
            context.Response.OnCompleted(() => { app.Lifetime.StopApplication(); return Task.CompletedTask; });
            return Results.Content(Page("<h1>Server is starting</h1><p>Setup is closed. Import the administrator PFX into your browser and trust the downloaded root CA, then open your server's HTTPS address followed by /admin.</p>", prefix), "text/html");
        });

        await app.StartAsync();
        origin = app.Urls.Single().TrimEnd('/');
        var url = origin + prefix;
        Console.WriteLine($"First-run setup (local machine only): {url}");
        try
        {
            if (openBrowser is not null) openBrowser(url);
            else Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        { Console.WriteLine("Open the setup URL above in a browser on this machine."); }
        await app.WaitForShutdownAsync(cancellationToken);
        if (adminPfx is not null) CryptographicOperations.ZeroMemory(adminPfx);
        return startServer;
    }

    public sealed record SetupRequest(string Hostname, string Username, string CaPassword,
        string CertificatePassword, string Provider, int Port, string? RecoveryPassword = null, byte[]? RecoveryPfx = null);
    public sealed record SetupResult(byte[] AdminPfx, byte[] RootCertificate);

    public static string? Validate(SetupRequest request)
    {
        if (Uri.CheckHostName(request.Hostname) == UriHostNameType.Unknown || request.Hostname.Length > 253)
            return "Enter a valid server DNS name or IP address without a scheme or port.";
        if (!Regex.IsMatch(request.Username, "^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$"))
            return "Administrator name must contain 1–64 letters, digits, underscores, or hyphens and start with a letter or digit.";
        if (request.CaPassword.Length < 12 || request.CertificatePassword.Length < 12)
            return "Use at least 12 characters for both passwords.";
        if (!Enum.TryParse<ServerStorageProvider>(request.Provider, true, out var provider) || !Enum.IsDefined(provider))
            return "Choose File, Tpm, or Memory storage.";
        if (provider == ServerStorageProvider.Tpm && (request.RecoveryPassword?.Length ?? 0) < 12)
            return "TPM mode requires a recovery PFX password of at least 12 characters.";
        return request.Port is < 1 or > 65535 ? "Choose a port between 1 and 65535." : null;
    }

    public static SetupResult Initialize(MtlsBasedSecretStoreServerOptions options, string configurationPath, SetupRequest request)
    {
        var error = Validate(request);
        if (error is not null) throw new ArgumentException(error);
        if (!IsFreshInstallation(options)) throw new InvalidOperationException("An installation already exists.");
        // Read configuration before writing PKI so malformed JSON fails without provisioning anything.
        var json = File.Exists(configurationPath)
            ? JsonNode.Parse(File.ReadAllText(configurationPath)) as JsonObject ?? throw new InvalidDataException("Expected a configuration object.")
            : new JsonObject();
        var section = json["MtlsBasedSecretStoreServer"] as JsonObject ?? new JsonObject();
        // Validate an uploaded recovery file before any installation files are written.
        if (request.Provider.Equals("Tpm", StringComparison.OrdinalIgnoreCase) && request.RecoveryPfx is not null)
        {
            using var imported = TpmMasterKey.ImportPfx(request.RecoveryPfx, request.RecoveryPassword!);
        }
        var ca = new CaManager(options.PkiRootPath);
        ca.EnsureRootAndIntermediate(request.CaPassword);
        ca.EnsureMasterProtectionCertificate();
        options.StorageProvider = Enum.Parse<ServerStorageProvider>(request.Provider, true);
        if (options.StorageProvider == ServerStorageProvider.Tpm)
        {
            byte[] recovery;
            if (request.RecoveryPfx is not null) recovery = request.RecoveryPfx.ToArray();
            else
            {
                using var generated = TpmMasterKey.Generate();
                recovery = generated.ExportPfx(request.RecoveryPassword!);
            }
            try
            {
                ServerTpmMaster.Create(options, recovery, request.RecoveryPassword!);
                ServerTpmMaster.CopyToUser(options, Path.Combine(options.SecretsRootPath, request.Username));
            }
            finally { CryptographicOperations.ZeroMemory(recovery); }
        }
        WriteNew(options.ServerCertificatePath, ca.IssueServerCertificate(request.CaPassword, request.Hostname, options.ServerCertificatePassword));
        WriteNew(options.ClientCaCertificatePath, ca.ExportIntermediateCertificate());
        var pfx = ca.IssueClientCertificate(request.Username, request.CaPassword, request.CertificatePassword);
        WriteNew(Path.Combine(options.SecretsRootPath, request.Username, "client.pfx"), pfx);
        using var certificate = new X509Certificate2(pfx, request.CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
        options.AdminCertificateThumbprints = [certificate.Thumbprint];
        options.StorageProvider = Enum.Parse<ServerStorageProvider>(request.Provider, true);
        options.ListenPort = request.Port;
        section["ListenPort"] = options.ListenPort;
        section["StorageProvider"] = options.StorageProvider.ToString();
        section["ServerCertificatePath"] = options.ServerCertificatePath;
        section["ClientCaCertificatePath"] = options.ClientCaCertificatePath;
        section["PkiRootPath"] = options.PkiRootPath;
        section["SecretsRootPath"] = options.SecretsRootPath;
        section["AdminCertificateThumbprints"] = new JsonArray(JsonValue.Create(certificate.Thumbprint));
        json["MtlsBasedSecretStoreServer"] = section;
        var temporary = configurationPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, configurationPath, overwrite: true);
        }
        finally { File.Delete(temporary); }
        return new SetupResult(pfx, File.ReadAllBytes(Path.Combine(options.PkiRootPath, "root.crt")));
    }

    private static void WriteNew(string path, byte[] bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes);
    }

    private static string Page(string content, string prefix) =>
        ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>VFido setup</title>" +
        "<style>body{font:16px system-ui;background:#101827;color:#e5edf8;max-width:640px;margin:5vh auto;padding:24px}h1{font-size:30px}label{display:block;margin:18px 0 6px}input,select,button{box-sizing:border-box;width:100%;padding:12px;border-radius:8px;border:1px solid #65738b}button{margin-top:24px;background:#86b6ff;color:#10203a;font-weight:bold;cursor:pointer}a{color:#a8ccff}p{line-height:1.6}small{color:#afbdd0}</style><main>" + content + "</main></html>")
        .Replace("{{prefix}}", prefix, StringComparison.Ordinal);

    private const string Form = """
        <p>VFido · First-run setup</p><h1>Set up your key server</h1>
        <p>Create your server certificates and first administrator. Setup is available only on this machine and closes when you start the server.</p>
        <form method="post" action="{{prefix}}" enctype="multipart/form-data">
        <label for="hostname">Server DNS name or IP address</label><input id="hostname" name="hostname" value="localhost" required maxlength="253">
        <label for="port">HTTPS port</label><input id="port" name="port" type="number" value="5443" min="1" max="65535" required>
        <label for="provider">Key storage</label><select id="provider" name="provider"><option value="File">File — encrypted on disk</option><option value="Tpm">TPM — hardware signing, encrypted metadata on disk</option><option value="Memory">Memory — credentials lost when the server stops</option></select>
        <small>TPM mode checks hardware during setup and creates a recoverable master. Each user receives a copy of master.json.</small>
        <label for="recoveryPfx">Existing TPM recovery PFX (optional, TPM mode only)</label><input id="recoveryPfx" name="recoveryPfx" type="file" accept=".pfx">
        <small>Upload an existing vfido-tpm-recovery.pfx, or leave blank to generate a new one.</small>
        <label for="recoveryPassword">TPM recovery PFX password</label><input id="recoveryPassword" name="recoveryPassword" type="password" autocomplete="new-password">
        <small>Required for TPM mode, at least 12 characters. Use the existing PFX password when importing. Keep it with your offline backup.</small>
        <label for="caPassword">CA passphrase</label><input id="caPassword" name="caPassword" type="password" minlength="12" required autocomplete="new-password">
        <small>Keep this safe. You will need it to issue more client certificates.</small>
        <label for="username">Administrator name</label><input id="username" name="username" value="admin" pattern="[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}" required>
        <label for="certificatePassword">Administrator certificate password</label><input id="certificatePassword" name="certificatePassword" type="password" minlength="12" required autocomplete="new-password">
        <small>The administrator signs in with this client certificate. No separate login password is created.</small>
        <button type="submit">Create server and administrator</button></form>
        """;

    private const string Completed = """
        <h1>Your server is configured</h1>
        <p>Download both files before starting the server. Import the administrator certificate into your browser using the certificate password you chose. Trust the root CA on devices that will connect to this server.</p>
        <p><a href="{{prefix}}/administrator.pfx">Download administrator certificate</a></p>
        <p><a href="{{prefix}}/root.crt">Download root CA certificate</a></p>
        <p>The password-protected administrator certificate is also saved in its user directory. Keep it private.</p>
        {{recovery}}
        <form method="post" action="{{prefix}}/start"><button type="submit">Close setup and start server</button></form>
        """;

    private const string RecoveryDownload = """
        <p><a href="{{prefix}}/vfido-tpm-recovery.pfx">Download vfido-tpm-recovery.pfx</a></p>
        <p>Save the recovery PFX and its password offline before starting. The temporary server copy is deleted when the normal server starts. Keep backups of user credential files too.</p>
        """;
}
