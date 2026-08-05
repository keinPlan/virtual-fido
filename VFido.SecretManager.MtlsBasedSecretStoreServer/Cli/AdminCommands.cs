using System.Security.Cryptography.X509Certificates;
using System.Text;
using VFido.SecretManager.FileBasedSecretStore;
using VFido.SecretManager.MtlsBasedSecretStoreServer.Pki;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer.Cli
{
    /// <summary>
    /// The repeatable admin workflow (init/create-user/revoke-user) run from the command line
    /// instead of interactively at every server startup. Secrets are always prompted for on the
    /// console (masked) rather than accepted as argv, so they never end up in shell history or a
    /// process list.
    /// </summary>
    public static class AdminCommands
    {
        public static int Run(string[] args, MtlsBasedSecretStoreServerOptions options)
        {
            switch (args[0].ToLowerInvariant())
            {
                case "init":
                    return Init(options);
                case "create-user":
                    return CreateUser(args, options);
                case "revoke-user":
                    return RevokeUser(args, options);
                default:
                    Console.Error.WriteLine($"Unknown command '{args[0]}'.");
                    PrintUsage();
                    return 1;
            }
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  <no args>                          start the server");
            Console.Error.WriteLine("  init                                generate the CA, server certificate and master protection certificate");
            Console.Error.WriteLine("  create-user <username> [--no-password]   provision a user's login and mTLS client certificate");
            Console.Error.WriteLine("  revoke-user <username>              revoke a previously issued client certificate");
        }

        private static int Init(MtlsBasedSecretStoreServerOptions options)
        {
            var ca = new CaManager(options.PkiRootPath);
            var caAlreadyInitialized = ca.IsInitialized;
            var needsServerCertificate = !File.Exists(ResolvePath(options.ServerCertificatePath)) || !File.Exists(ResolvePath(options.ClientCaCertificatePath));

            if (caAlreadyInitialized)
                Console.WriteLine("CA already initialized; skipping root/intermediate generation.");

            if (!caAlreadyInitialized || needsServerCertificate)
            {
                var passphrase = caAlreadyInitialized ? ReadPasswordPrompt("CA passphrase") : ReadAndConfirmPassphrase("CA passphrase");
                if (passphrase is null)
                    return 1;

                try
                {
                    if (!caAlreadyInitialized)
                    {
                        ca.EnsureRootAndIntermediate(passphrase);
                        Console.WriteLine("Root and intermediate CA created.");
                    }

                    if (needsServerCertificate)
                        IssueServerCertificate(options, ca, passphrase);
                    else
                        Console.WriteLine("Server certificate already present; skipping.");
                }
                catch (VFido.SecretManager.FileBasedSecretStore.InvalidCredentialsException)
                {
                    Console.Error.WriteLine("Wrong CA passphrase.");
                    return 1;
                }
            }

            ca.EnsureMasterProtectionCertificate();
            Console.WriteLine("Master protection certificate ready.");
            Console.WriteLine("Initialization complete.");
            return 0;
        }

        private static void IssueServerCertificate(MtlsBasedSecretStoreServerOptions options, CaManager ca, string passphrase)
        {
            // Unprotected on purpose, like the master protection cert: the running server must load
            // this unattended on every startup, so there's no operator around to type a password -
            // and a password recorded in appsettings.json wouldn't add any real protection anyway.
            // At-rest protection here is the same file-permissions story the original single-tier
            // setup already relied on (ServerCertificatePassword defaulted to "").
            var serverPfx = ca.IssueServerCertificate(passphrase, "localhost", pfxPassword: null);
            var serverCertPath = ResolvePath(options.ServerCertificatePath);
            Directory.CreateDirectory(Path.GetDirectoryName(serverCertPath)!);
            File.WriteAllBytes(serverCertPath, serverPfx);

            var caCertPath = ResolvePath(options.ClientCaCertificatePath);
            Directory.CreateDirectory(Path.GetDirectoryName(caCertPath)!);
            File.WriteAllBytes(caCertPath, ca.ExportIntermediateCertificate());

            Console.WriteLine($"Server certificate written to {serverCertPath}");
            Console.WriteLine($"Client CA certificate written to {caCertPath}");
        }

        private static int CreateUser(string[] args, MtlsBasedSecretStoreServerOptions options)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: create-user <username> [--no-password]");
                return 1;
            }

            var username = args[1];
            var noPassword = args.Contains("--no-password", StringComparer.OrdinalIgnoreCase);

            var ca = new CaManager(options.PkiRootPath);
            if (!ca.IsInitialized)
            {
                Console.Error.WriteLine("Run 'init' first.");
                return 1;
            }

            var caPassphrase = ReadPasswordPrompt("CA passphrase");

            var userDirectory = Path.Combine(options.SecretsRootPath, username);
            Directory.CreateDirectory(userDirectory);

            if (!noPassword)
            {
                var loginPassword = ReadAndConfirmPassphrase("Login password");
                if (loginPassword is null)
                    return 1;

                // Establishes salt.bin/verifier.bin for this identity - the presence of verifier.bin
                // is what IdentityResolutionFilter/UserDirectoryResolver use to tell a password user
                // from a passwordless one.
                _ = new VFido.SecretManager.FileBasedSecretStore.FileBasedSecretStore(
                    Path.Combine(userDirectory, "keys"), username, loginPassword, Path.Combine(userDirectory, "certs"), userDirectory);
            }

            Console.Write("Client certificate PFX password (blank for none): ");
            var clientPfxPassword = ReadPassword();

            var clientPfx = ca.IssueClientCertificate(username, caPassphrase, string.IsNullOrEmpty(clientPfxPassword) ? null : clientPfxPassword);
            var clientPfxPath = Path.Combine(userDirectory, "client.pfx");
            File.WriteAllBytes(clientPfxPath, clientPfx);

            Console.WriteLine($"User '{username}' created ({(noPassword ? "passwordless" : "password-protected")}).");
            Console.WriteLine($"Client certificate written to {clientPfxPath} - hand this off to the user's client machine.");
            return 0;
        }

        private static int RevokeUser(string[] args, MtlsBasedSecretStoreServerOptions options)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: revoke-user <username>");
                return 1;
            }

            var username = args[1];
            var clientPfxPath = Path.Combine(options.SecretsRootPath, username, "client.pfx");
            if (!File.Exists(clientPfxPath))
            {
                Console.Error.WriteLine($"No issued client certificate found for '{username}' at {clientPfxPath}.");
                return 1;
            }

            var clientPfxPassword = ReadPasswordPrompt("Client certificate PFX password (blank if none)");
            using var cert = new X509Certificate2(clientPfxPath, clientPfxPassword);

            var ca = new CaManager(options.PkiRootPath);
            ca.Revoke(cert.SerialNumber);

            Console.WriteLine($"Certificate for '{username}' (serial {cert.SerialNumber}) revoked.");
            Console.WriteLine("Restart the server for the revocation to take effect.");
            return 0;
        }

        private static string ResolvePath(string path) =>
            Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);

        private static string? ReadAndConfirmPassphrase(string label)
        {
            var value = ReadPasswordPrompt(label);
            Console.Write($"Confirm {label.ToLowerInvariant()}: ");
            var confirmation = ReadPassword();
            if (value != confirmation)
            {
                Console.Error.WriteLine("Values did not match.");
                return null;
            }

            return value;
        }

        private static string ReadPasswordPrompt(string label)
        {
            Console.Write($"{label}: ");
            return ReadPassword();
        }

        private static string ReadPassword()
        {
            var buffer = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (buffer.Length > 0)
                    {
                        buffer.Length--;
                        Console.Write("\b \b");
                    }
                    continue;
                }

                if (!char.IsControl(key.KeyChar))
                {
                    buffer.Append(key.KeyChar);
                    Console.Write("*");
                }
            }

            return buffer.ToString();
        }
    }
}
