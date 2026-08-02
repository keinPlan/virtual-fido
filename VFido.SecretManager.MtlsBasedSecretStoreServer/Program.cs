using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using VFido.SecretManager;
using VFido.SecretManager.MemoryBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer;

var builder = WebApplication.CreateBuilder(args);

var serverOptions = builder.Configuration.GetSection("MtlsBasedSecretStoreServer").Get<MtlsBasedSecretStoreServerOptions>()
    ?? throw new InvalidOperationException("Missing \"MtlsBasedSecretStoreServer\" configuration section.");

var serverCertificate = new X509Certificate2(serverOptions.ServerCertificatePath, serverOptions.ServerCertificatePassword);
var clientCaCertificate = new X509Certificate2(serverOptions.ClientCaCertificatePath);

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(serverOptions.ListenPort, listen =>
    {
        listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, chain, errors) =>
                ValidateClientCertificate(certificate, clientCaCertificate);
        });
    });
});

builder.Services.AddSingleton(serverOptions);
builder.Services.AddSingleton(new SessionTokenService(TimeSpan.FromMinutes(serverOptions.TokenLifetimeMinutes)));
builder.Services.AddSingleton<IUserCredentialStore>(_ =>
{
    var store = new InMemoryUserCredentialStore();
    store.AddUser(serverOptions.SeedUsername, serverOptions.SeedPassword);
    return store;
});

// In-process key/credential storage; swap for a persisted IKeyStore/ICredentialStore without
// touching anything above the Fido2SecretManager seam.
builder.Services.AddSingleton<IKeyStore, MemoryBasedSecretStore>();
builder.Services.AddSingleton<ICredentialStore, InMemoryCredentialStore>();
builder.Services.AddSingleton<IFido2SecretManager, Fido2SecretManager>();

var app = builder.Build();

app.MapPost(SecretManagerRoutes.Login, (LoginRequest request, IUserCredentialStore users, SessionTokenService sessions) =>
    users.Validate(request.Username, request.Password)
        ? Results.Ok(sessions.IssueToken(request.Username))
        : Results.Unauthorized());

var api = app.MapGroup("").AddEndpointFilter<BearerAuthFilter>();

api.MapPost(SecretManagerRoutes.CreateCredential, async (CreateCredentialRequest request, IFido2SecretManager manager) =>
    Results.Ok(await manager.CreateCredentialAsync(request.RpId, request.UserId, request.UserName, request.UserDisplayName, request.IsResident, request.CredProtect)));

api.MapPost(SecretManagerRoutes.CredentialExists, async (CredentialExistsRequest request, IFido2SecretManager manager) =>
    Results.Ok(new CredentialExistsResponse(await manager.CredentialExistsAsync(request.CredentialId, request.RpId))));

api.MapPost(SecretManagerRoutes.FindCredential, async (FindCredentialRequest request, IFido2SecretManager manager) =>
    Results.Ok(new FindCredentialResponse(await manager.FindCredentialAsync(request.CredentialId, request.RpId))));

api.MapPost(SecretManagerRoutes.FindResidentCredentials, async (FindResidentCredentialsRequest request, IFido2SecretManager manager) =>
    Results.Ok(new FindResidentCredentialsResponse(await manager.FindResidentCredentialsAsync(request.RpId))));

api.MapPost(SecretManagerRoutes.FindAllCredentials, async (IFido2SecretManager manager) =>
    Results.Ok(new FindAllCredentialsResponse(await manager.FindAllCredentialsAsync())));

api.MapPost(SecretManagerRoutes.DeleteCredential, async (DeleteCredentialRequest request, IFido2SecretManager manager) =>
{
    await manager.DeleteCredentialAsync(request.CredentialId);
    return Results.Ok(new DeleteCredentialResponse());
});

api.MapPost(SecretManagerRoutes.IncrementSignCount, async (IncrementSignCountRequest request, IFido2SecretManager manager) =>
    Results.Ok(new IncrementSignCountResponse(await manager.IncrementSignCountAsync(request.CredentialId))));

api.MapPost(SecretManagerRoutes.Sign, async (SignRequest request, IFido2SecretManager manager) =>
    Results.Ok(new SignResponse(await manager.SignAsync(request.CredentialId, request.Data))));

app.Run();

static bool ValidateClientCertificate(X509Certificate2 certificate, X509Certificate2 ca)
{
    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(ca);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    return chain.Build(certificate);
}
