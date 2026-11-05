using VFido.SecretManager.MtlsBasedSecretStoreServer;

namespace VirtualFido.Tests;

public class ServerPathTests
{
    [Fact]
    public void RelativePathsUseTheExecutableDirectoryAndAbsolutePathsArePreserved()
    {
        var serverDirectory = Path.Combine(Path.GetTempPath(), "vfido-server");
        var absoluteCaPath = Path.Combine(Path.GetTempPath(), "existing-ca", "ca.crt");
        var options = new MtlsBasedSecretStoreServerOptions
        {
            ServerCertificatePath = "certs/server.pfx",
            ClientCaCertificatePath = absoluteCaPath,
            PkiRootPath = "pki",
            SecretsRootPath = "users"
        };

        options.ResolvePaths(serverDirectory);

        Assert.Equal(Path.Combine(serverDirectory, "certs", "server.pfx"), options.ServerCertificatePath);
        Assert.Equal(absoluteCaPath, options.ClientCaCertificatePath);
        Assert.Equal(Path.Combine(serverDirectory, "pki"), options.PkiRootPath);
        Assert.Equal(Path.Combine(serverDirectory, "users"), options.SecretsRootPath);
    }
}
