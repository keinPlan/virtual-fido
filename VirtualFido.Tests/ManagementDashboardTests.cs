using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using VFido.SecretManager.MtlsBasedSecretStoreServer;

namespace VirtualFido.Tests;

public class ManagementDashboardTests
{
    [Fact]
    public void AdministratorAccessRequiresAnExplicitlyAllowedCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=dashboard-admin", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));

        Assert.False(ManagementDashboard.IsAdministrator(null, [certificate.Thumbprint]));
        Assert.False(ManagementDashboard.IsAdministrator(certificate, []));
        Assert.False(ManagementDashboard.IsAdministrator(certificate, [new string('0', 40)]));
        Assert.True(ManagementDashboard.IsAdministrator(certificate, [certificate.Thumbprint.ToLowerInvariant()]));
        Assert.True(ManagementDashboard.IsAdministrator(certificate,
            [string.Join(":", certificate.Thumbprint.Chunk(2).Select(chunk => new string(chunk)))]));
    }

    [Fact]
    public void SessionInventoryCountsByIdentityWithoutExposingTokens()
    {
        var sessions = new SessionTokenService(TimeSpan.FromMinutes(30));
        sessions.IssueToken("alice");
        sessions.IssueToken("alice");
        sessions.IssueToken("bob");
        var counts = sessions.GetActiveSessionCounts();
        Assert.Equal(2, counts["alice"]);
        Assert.Equal(1, counts["bob"]);
        Assert.Equal(2, counts.Count);
    }

    [Fact]
    public void ExpiredSessionsAreExcludedFromInventory()
    {
        var sessions = new SessionTokenService(TimeSpan.FromSeconds(-1));
        sessions.IssueToken("alice");
        Assert.Empty(sessions.GetActiveSessionCounts());
    }

    [Theory]
    [InlineData("index.html")]
    [InlineData("dashboard.css")]
    [InlineData("dashboard.js")]
    public void DashboardAssetsAreIncludedInTheServerAssembly(string name)
    {
        using var asset = typeof(ManagementDashboard).Assembly.GetManifestResourceStream(
            $"VFido.SecretManager.MtlsBasedSecretStoreServer.Dashboard.{name}");
        Assert.NotNull(asset);
        Assert.True(asset.Length > 0);
    }
}
