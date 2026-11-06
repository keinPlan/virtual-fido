using System.Security.Cryptography.X509Certificates;
using VFido.SecretManager.MtlsBasedSecretStoreServer;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;
using VFido.SecretManager.Protection;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace VirtualFido.Tests;

public sealed class DashboardUserManagementTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "vfido-dashboard-" + Guid.NewGuid().ToString("N"));
    private readonly MtlsBasedSecretStoreServerOptions options;
    private readonly RevocationStore revocations;
    private readonly DashboardUserManagement management;

    public DashboardUserManagementTests()
    {
        options = new() { SecretsRootPath = Path.Combine(root, "users"), PkiRootPath = Path.Combine(root, "pki") };
        Directory.CreateDirectory(options.PkiRootPath);
        revocations = RevocationStore.Load(options.PkiRootPath);
        management = new(options, revocations);
    }

    [Theory]
    [InlineData("../outside")]
    [InlineData("..\\outside")]
    [InlineData("C:\\outside")]
    [InlineData("alice,OU=admin")]
    [InlineData("alice.")]
    [InlineData("CON")]
    [InlineData("lpt1")]
    [InlineData("")]
    public void UnsafeUsernamesAreRejected(string username) =>
        Assert.Throws<ArgumentException>(() => management.UserPath(username));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CreateAndRevokePreservesIdentityAndPersistsRevocation(bool noPassword)
    {
        new CaManager(options.PkiRootPath).EnsureRootAndIntermediate("ca-password");
        var request = new CreateDashboardUser("alice", "ca-password", "login-password", "pfx-password", noPassword);
        var pfx = management.Create(request);
        var directory = management.UserPath("alice");
        using var certificate = new X509Certificate2(pfx, "pfx-password", X509KeyStorageFlags.EphemeralKeySet);
        Assert.Equal("alice", certificate.GetNameInfo(X509NameType.SimpleName, false));
        Assert.True(certificate.HasPrivateKey);
        Assert.Equal(!noPassword, File.Exists(Path.Combine(directory, "verifier.bin")));
        if (!noPassword)
        {
            using var protection = PasswordStorageProtection.Open(directory, "alice", "login-password");
        }
        Assert.Throws<InvalidOperationException>(() => management.Create(request));
        Assert.Equal(pfx, File.ReadAllBytes(Path.Combine(directory, "client.pfx")));
        Assert.False(management.IsRevoked(directory));
        Assert.Throws<InvalidOperationException>(() => management.Revoke("alice", null, certificate.Thumbprint));
        Assert.False(revocations.IsRevoked(certificate.SerialNumber));
        management.Revoke("alice", null, "another-admin");
        Assert.True(revocations.IsRevoked(certificate.SerialNumber));
        Assert.True(RevocationStore.Load(options.PkiRootPath).IsRevoked(certificate.SerialNumber));
        Assert.True(management.IsRevoked(directory));
        Assert.True(Directory.Exists(directory));
    }

    [Fact]
    public void IncorrectCaPassphraseDoesNotPublishUser()
    {
        new CaManager(options.PkiRootPath).EnsureRootAndIntermediate("correct-password");
        Assert.ThrowsAny<Exception>(() => management.Create(new("alice", "wrong-password", null, null, true)));
        Assert.False(Directory.Exists(management.UserPath("alice")));
    }

    [Fact]
    public void LegacyEncryptedPfxNeedsPasswordAndGainsPublicMetadataOnRevocation()
    {
        new CaManager(options.PkiRootPath).EnsureRootAndIntermediate("ca-password");
        management.Create(new("alice", "ca-password", null, "pfx-password", true));
        var directory = management.UserPath("alice");
        File.Delete(Path.Combine(directory, "client.cer"));
        Assert.Null(management.IsRevoked(directory));
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => management.Revoke("alice", "wrong", null));
        management.Revoke("alice", "pfx-password", null);
        Assert.True(management.IsRevoked(directory));
    }

    [Fact]
    public async Task DashboardEndpointsRequireAdministratorAndExplicitMutationHeader()
    {
        var ca = new CaManager(options.PkiRootPath);
        ca.EnsureRootAndIntermediate("ca-password");
        using var admin = new X509Certificate2(ca.IssueClientCertificate("admin", "ca-password", null),
            (string?)null, X509KeyStorageFlags.EphemeralKeySet);
        options.AdminCertificateThumbprints = [admin.Thumbprint];
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddSingleton(management);
        builder.Services.AddSingleton(new SessionTokenService(TimeSpan.FromMinutes(30)));
        await using var app = builder.Build();
        // Simulate the certificate supplied by Kestrel after TLS validation.
        app.Use((context, next) =>
        {
            if (context.Request.Headers["Test-Administrator"] == "1")
                context.Connection.ClientCertificate = admin;
            return next(context);
        });
        app.MapManagementDashboard(options, admin);
        await app.StartAsync();
        using var client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };
        var request = new CreateDashboardUser("alice", "ca-password", null, "export-password", true);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/admin")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/admin/api/users", request)).StatusCode);
        client.DefaultRequestHeaders.Add("Test-Administrator", "1");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/admin")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/admin/api/users", request)).StatusCode);
        client.DefaultRequestHeaders.Add("X-VFido-Admin", "1");
        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/admin/api/users", request)).StatusCode);
        client.DefaultRequestHeaders.Remove("Sec-Fetch-Site");
        var created = await client.PostAsJsonAsync("/admin/api/users", request);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Equal("no-store", created.Headers.CacheControl?.ToString());
        Assert.Equal("application/x-pkcs12", created.Content.Headers.ContentType?.MediaType);
        using var issued = new X509Certificate2(await created.Content.ReadAsByteArrayAsync(), "export-password", X509KeyStorageFlags.EphemeralKeySet);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync("/admin/api/users", request)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/admin/api/users/alice/revoke", new RevokeDashboardCertificate(null))).StatusCode);
        Assert.True(revocations.IsRevoked(issued.SerialNumber));
        await app.StopAsync();
    }

    public void Dispose() => Directory.Delete(root, recursive: true);
}
