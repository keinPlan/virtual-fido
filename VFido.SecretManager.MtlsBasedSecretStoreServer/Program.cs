using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using VFido.SecretManager;
using VFido.SecretManager.MtlsBasedSecretStoreServer;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Cli;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;

var configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: true)
    .Build();

var serverOptions = configuration.GetSection("MtlsBasedSecretStoreServer").Get<MtlsBasedSecretStoreServerOptions>()
    ?? throw new InvalidOperationException("Missing \"MtlsBasedSecretStoreServer\" configuration section.");

if (args.Length > 0)
    return AdminCommands.Run(args, serverOptions);

var serverCertificate = new X509Certificate2(serverOptions.ServerCertificatePath, serverOptions.ServerCertificatePassword);
var clientCaCertificate = new X509Certificate2(serverOptions.ClientCaCertificatePath);
var revocations = RevocationStore.Load(serverOptions.PkiRootPath);
var masterProtectionCertificate = new CaManager(serverOptions.PkiRootPath).LoadMasterProtectionCertificate();

using var bootstrapLoggerFactory = LoggerFactory.Create(logging => logging
    .AddConfiguration(configuration.GetSection("Logging"))
    .AddConsole());
var mtlsLogger = bootstrapLoggerFactory.CreateLogger("MtlsClientCertificateValidation");

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(serverOptions.ListenPort, listen =>
    {
        listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, chain, errors) =>
                ValidateClientCertificate(certificate, clientCaCertificate, revocations, mtlsLogger);
        });
    });
});

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(serverOptions.PkiRootPath, "keyring")))
    .ProtectKeysWithCertificate(masterProtectionCertificate);

builder.Services.AddSingleton(serverOptions);
builder.Services.AddSingleton(new SessionTokenService(TimeSpan.FromMinutes(serverOptions.TokenLifetimeMinutes)));
builder.Services.AddSingleton<UserSessionCache>();
builder.Services.AddSingleton<UserKeyProtector>();
builder.Services.AddSingleton<UserDirectoryResolver>();

var app = builder.Build();

app.MapPost(SecretManagerRoutes.Login, (LoginRequest request, HttpContext http, SessionTokenService sessions, UserSessionCache cache, UserDirectoryResolver users, ILogger<Program> logger) =>
{
    var certUsername = http.Connection.ClientCertificate?.GetNameInfo(X509NameType.SimpleName, false);
    if (!string.Equals(certUsername, request.Username, StringComparison.Ordinal))
    {
        logger.LogWarning("Login rejected: client certificate CN {CertUsername} does not match requested username {RequestedUsername}.", certUsername, request.Username);
        return Results.Unauthorized();
    }

    if (!users.UserExists(request.Username) || !users.RequiresPassword(request.Username))
    {
        logger.LogWarning("Login rejected for {Username}: user does not exist or does not require a password.", request.Username);
        return Results.Unauthorized();
    }

    IFido2SecretManager manager;
    try
    {
        manager = users.BuildManagerFromPassword(request.Username, request.Password);
    }
    catch (VFido.SecretManager.FileBasedSecretStore.InvalidCredentialsException)
    {
        logger.LogWarning("Login rejected for {Username}: invalid password.", request.Username);
        return Results.Unauthorized();
    }

    var response = sessions.IssueToken(request.Username);
    cache.SetForToken(response.Token, manager);
    logger.LogInformation("Login succeeded for {Username}.", request.Username);
    return Results.Ok(response);
});

var api = app.MapGroup("").AddEndpointFilter<IdentityResolutionFilter>();

api.MapPost(SecretManagerRoutes.CreateCredential, async (CreateCredentialRequest request, HttpContext http) =>
    Results.Ok(await Manager(http).CreateCredentialAsync(request.RpId, request.UserId, request.UserName, request.UserDisplayName, request.IsResident, request.CredProtect)));

api.MapPost(SecretManagerRoutes.CredentialExists, async (CredentialExistsRequest request, HttpContext http) =>
    Results.Ok(new CredentialExistsResponse(await Manager(http).CredentialExistsAsync(request.CredentialId, request.RpId))));

api.MapPost(SecretManagerRoutes.FindCredential, async (FindCredentialRequest request, HttpContext http) =>
    Results.Ok(new FindCredentialResponse(await Manager(http).FindCredentialAsync(request.CredentialId, request.RpId))));

api.MapPost(SecretManagerRoutes.FindResidentCredentials, async (FindResidentCredentialsRequest request, HttpContext http) =>
    Results.Ok(new FindResidentCredentialsResponse(await Manager(http).FindResidentCredentialsAsync(request.RpId))));

api.MapPost(SecretManagerRoutes.FindAllCredentials, async (HttpContext http) =>
{
    // Deliberately block-bodied: an expression-bodied async lambda whose only parameter is
    // HttpContext resolves to a Task<Ok<T>> that ASP.NET Core's RequestDelegateFactory fails to
    // recognize as an IResult here, silently producing a 200 with an empty body instead of the
    // serialized JSON. An explicit `return` avoids it.
    return Results.Ok(new FindAllCredentialsResponse(await Manager(http).FindAllCredentialsAsync()));
});

api.MapPost(SecretManagerRoutes.DeleteCredential, async (DeleteCredentialRequest request, HttpContext http) =>
{
    await Manager(http).DeleteCredentialAsync(request.CredentialId);
    return Results.Ok(new DeleteCredentialResponse());
});

api.MapPost(SecretManagerRoutes.IncrementSignCount, async (IncrementSignCountRequest request, HttpContext http) =>
    Results.Ok(new IncrementSignCountResponse(await Manager(http).IncrementSignCountAsync(request.CredentialId))));

api.MapPost(SecretManagerRoutes.Sign, async (SignRequest request, HttpContext http) =>
    Results.Ok(new SignResponse(await Manager(http).SignAsync(request.CredentialId, request.Data))));

api.MapPost(SecretManagerRoutes.GetAttestationCertificate, async (HttpContext http) =>
{
    // See the comment on FindAllCredentials above: same HttpContext-only-parameter pitfall.
    return Results.Ok(new GetAttestationCertificateChainResponse(await Manager(http).GetAttestationCertificateChainAsync()));
});

api.MapPost(SecretManagerRoutes.GetAaguid, async (HttpContext http) =>
{
    // See the comment on FindAllCredentials above: same HttpContext-only-parameter pitfall.
    return Results.Ok(new GetAaguidResponse(await Manager(http).GetAaguidAsync()));
});

api.MapPost(SecretManagerRoutes.SignWithAttestationKey, async (SignWithAttestationKeyRequest request, HttpContext http) =>
    Results.Ok(new SignWithAttestationKeyResponse(await Manager(http).SignWithAttestationKeyAsync(request.Data))));

api.MapPost(SecretManagerRoutes.GetPinState, async (HttpContext http) =>
{
    // See the comment on FindAllCredentials above: same HttpContext-only-parameter pitfall.
    return Results.Ok(new GetPinStateResponse(await Manager(http).LoadPinStateAsync()));
});

api.MapPost(SecretManagerRoutes.SavePinState, async (SavePinStateRequest request, HttpContext http) =>
{
    await Manager(http).SavePinStateAsync(request.State);
    return Results.Ok(new SavePinStateResponse());
});

app.Run();
return 0;

static IFido2SecretManager Manager(HttpContext http) =>
    (IFido2SecretManager)http.Items[IdentityResolutionFilter.ManagerItemKey]!;

static bool ValidateClientCertificate(X509Certificate2 certificate, X509Certificate2 ca, RevocationStore revocations, ILogger logger)
{
    var subject = certificate.GetNameInfo(X509NameType.SimpleName, false);

    if (revocations.IsRevoked(certificate.SerialNumber))
    {
        logger.LogWarning("Rejected client certificate for {Subject} (serial {Serial}): certificate is revoked.", subject, certificate.SerialNumber);
        return false;
    }

    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(ca);
    chain.ChainPolicy.ExtraStore.Add(ca);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    // "ca" here is the intermediate CA (see CaManager), not a self-signed root - its own issuer
    // (the offline root) is deliberately never installed anywhere, so chain building would
    // otherwise report the intermediate's issuer as unknown even though the intermediate itself
    // is the trusted anchor.
    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

    if (chain.Build(certificate))
        return true;

    var statusSummary = string.Join(", ", chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}"));
    logger.LogWarning("Rejected client certificate for {Subject} (serial {Serial}): chain build failed [{Status}].", subject, certificate.SerialNumber, statusSummary);
    return false;
}
