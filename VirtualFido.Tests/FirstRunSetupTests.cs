using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using VFido.SecretManager.MtlsBasedSecretStoreServer;

namespace VirtualFido.Tests;

public class FirstRunSetupTests
{
    [Fact]
    public async Task BrowserFlowRejectsOtherOriginsAndClosesAfterSetup()
    {
        var root = Path.Combine(Path.GetTempPath(), "vfido-setup-http-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var address = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new MtlsBasedSecretStoreServerOptions { PkiRootPath = "pki", SecretsRootPath = "users" };
        options.ResolvePaths(root);
        var running = FirstRunSetup.RunAsync(options, Path.Combine(root, "appsettings.json"),
            url => address.SetResult(url), cancellation.Token);
        try
        {
            var url = await address.Task.WaitAsync(cancellation.Token);
            using var client = new HttpClient();
            using var page = await client.GetAsync(url);
            Assert.Contains("Set up your key server", await page.Content.ReadAsStringAsync());
            Assert.Equal("same-origin", Assert.Single(page.Headers.GetValues("Referrer-Policy")));
            Assert.Equal(System.Net.HttpStatusCode.Forbidden, (await client.GetAsync(new Uri(new Uri(url), "/"))).StatusCode);
            using var foreign = new HttpRequestMessage(HttpMethod.Post, url);
            foreign.Headers.Add("Origin", "https://untrusted.example");
            foreign.Content = new FormUrlEncodedContent([]);
            Assert.Equal(System.Net.HttpStatusCode.Forbidden, (await client.SendAsync(foreign)).StatusCode);
            using var opaque = new HttpRequestMessage(HttpMethod.Post, url);
            opaque.Headers.Add("Origin", "null");
            opaque.Content = new FormUrlEncodedContent([]);
            Assert.Equal(System.Net.HttpStatusCode.Forbidden, (await client.SendAsync(opaque)).StatusCode);
            using var create = new HttpRequestMessage(HttpMethod.Post, url);
            create.Headers.Add("Origin", new Uri(url).GetLeftPart(UriPartial.Authority));
            create.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["hostname"] = "localhost", ["username"] = "admin", ["port"] = "5443",
                ["provider"] = "Memory", ["caPassword"] = "ca-passphrase-123", ["certificatePassword"] = "certificate-pass-123"
            });
            using var submitted = await client.SendAsync(create);
            Assert.True(submitted.IsSuccessStatusCode);
            Assert.Contains("Your server is configured", await submitted.Content.ReadAsStringAsync());
            Assert.NotEmpty(await client.GetByteArrayAsync(url + "/administrator.pfx"));
            Assert.NotEmpty(await client.GetByteArrayAsync(url + "/root.crt"));
            using var start = await client.PostAsync(url + "/start", new FormUrlEncodedContent([]));
            Assert.True(start.IsSuccessStatusCode);
            Assert.True(await running.WaitAsync(cancellation.Token));
        }
        finally
        {
            await cancellation.CancelAsync();
            try { await running; } catch (OperationCanceledException) { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("File")]
    [InlineData("Memory")]
    public void FreshInstallationCreatesCertificatesAdminAndPreservesConfiguration(string provider)
    {
        var root = Path.Combine(Path.GetTempPath(), "vfido-setup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = new MtlsBasedSecretStoreServerOptions { PkiRootPath = "pki", SecretsRootPath = "users" };
            options.ResolvePaths(root);
            var configuration = Path.Combine(root, "appsettings.json");
            File.WriteAllText(configuration, """{"Logging":{"LogLevel":{"Default":"Warning"}},"MtlsBasedSecretStoreServer":{"TokenLifetimeMinutes":42}}""");
            Assert.True(FirstRunSetup.IsFreshInstallation(options));
            var request = new FirstRunSetup.SetupRequest("localhost", "admin", "ca-passphrase-123", "certificate-pass-123", provider, 5443);
            var result = FirstRunSetup.Initialize(options, configuration, request);

            Assert.False(FirstRunSetup.IsFreshInstallation(options));
            using var admin = new X509Certificate2(result.AdminPfx, request.CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
            Assert.True(admin.HasPrivateKey);
            Assert.Equal("admin", admin.GetNameInfo(X509NameType.SimpleName, false));
            Assert.Contains(admin.Thumbprint, options.AdminCertificateThumbprints);
            using var server = new X509Certificate2(options.ServerCertificatePath, options.ServerCertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
            Assert.Equal("localhost", server.GetNameInfo(X509NameType.DnsName, false));
            Assert.Contains(server.Extensions.Cast<X509Extension>(), extension => extension.Oid?.Value == "2.5.29.17");
            using var ca = new X509Certificate2(result.RootCertificate);
            Assert.False(ca.HasPrivateKey);
            var json = JsonNode.Parse(File.ReadAllText(configuration))!;
            Assert.Equal(provider, json["MtlsBasedSecretStoreServer"]!["StorageProvider"]!.GetValue<string>());
            Assert.Equal(42, json["MtlsBasedSecretStoreServer"]!["TokenLifetimeMinutes"]!.GetValue<int>());
            Assert.Equal("Warning", json["Logging"]!["LogLevel"]!["Default"]!.GetValue<string>());
            Assert.DoesNotContain(request.CaPassword, File.ReadAllText(configuration));
            Assert.DoesNotContain(request.CertificatePassword, File.ReadAllText(configuration));
            var certificateBytes = File.ReadAllBytes(options.ServerCertificatePath);
            Assert.Throws<InvalidOperationException>(() => FirstRunSetup.Initialize(options, configuration, request));
            Assert.Equal(certificateBytes, File.ReadAllBytes(options.ServerCertificatePath));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("../admin", "localhost", "File", 5443)]
    [InlineData("admin", "https://localhost", "File", 5443)]
    [InlineData("admin", "localhost", "unknown", 5443)]
    [InlineData("admin", "localhost", "File", 0)]
    public void InvalidSetupInputIsRejected(string username, string hostname, string provider, int port)
    {
        Assert.NotNull(FirstRunSetup.Validate(new(hostname, username, "ca-passphrase-123", "certificate-pass-123", provider, port)));
    }

    [Fact]
    public void PartialInstallationDoesNotEnableSetup()
    {
        var root = Path.Combine(Path.GetTempPath(), "vfido-setup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = new MtlsBasedSecretStoreServerOptions { PkiRootPath = "pki", SecretsRootPath = "users" };
            options.ResolvePaths(root);
            Directory.CreateDirectory(options.PkiRootPath);
            File.WriteAllText(Path.Combine(options.PkiRootPath, "salt.bin"), "existing state");
            Assert.False(FirstRunSetup.IsFreshInstallation(options));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
