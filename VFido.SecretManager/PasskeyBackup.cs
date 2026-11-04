using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace VFido.SecretManager;

public sealed record TransferIdentity(byte[] Certificate, byte[] PasswordProtectedPfx, string Fingerprint);

/// <summary>
/// Certificate-encrypted CXF structure with VirtualFido metadata and counter extensions.
/// Nonzero counters are preserved; this profile does not claim strict CXF/CXP conformance.
/// AES-256-GCM protects the payload; RSA-OAEP-SHA256 wraps its fresh random key.
/// </summary>
public static class PasskeyBackup
{
    public const int MaximumFileSize = 64 * 1024 * 1024;
    private const int MaximumPlaintextSize = 32 * 1024 * 1024;
    private const string Format = "VirtualFido.EncryptedCxf";
    private const string Algorithm = "RSA-OAEP-SHA256+A256GCM";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 16 };

    public static TransferIdentity CreateIdentity(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("A non-empty password is required for the private-key file.", nameof(password));
        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest("CN=VirtualFido Passkey Backup", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));
        return new(certificate.Export(X509ContentType.Cert), certificate.Export(X509ContentType.Pfx, password), Fingerprint(certificate));
    }

    public static string Fingerprint(X509Certificate2 certificate) => certificate.GetCertHashString(HashAlgorithmName.SHA256);

    public static void ValidateRecipient(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa == null || rsa.KeySize < 2048)
            throw new InvalidOperationException("Select an RSA recipient certificate with at least a 2048-bit key.");
        if (DateTime.UtcNow < certificate.NotBefore.ToUniversalTime() || DateTime.UtcNow > certificate.NotAfter.ToUniversalTime())
            throw new InvalidOperationException("The recipient certificate is not currently valid. Create a new transfer certificate.");
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (usage != null && (usage.KeyUsages & X509KeyUsageFlags.KeyEncipherment) == 0)
            throw new InvalidOperationException("The recipient certificate does not permit key encipherment.");
    }

    internal static byte[] Encrypt(IReadOnlyList<BackupCredential> credentials, X509Certificate2 recipient)
    {
        ValidateRecipient(recipient);
        var plaintext = CxfPasskeyFormat.Serialize(credentials);
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            if (plaintext.Length > MaximumPlaintextSize)
                throw new InvalidOperationException("The selected passkeys exceed the backup size limit.");
            using var rsa = recipient.GetRSAPublicKey()!;
            var wrappedKey = rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
            var envelope = new Envelope(Format, 1, Algorithm, Fingerprint(recipient), wrappedKey,
                RandomNumberGenerator.GetBytes(12), new byte[plaintext.Length], new byte[16]);
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(envelope.Nonce, plaintext, envelope.Ciphertext, envelope.Tag, AssociatedData(envelope));
            return JsonSerializer.SerializeToUtf8Bytes(envelope, Json);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    internal static IReadOnlyList<BackupCredential> Decrypt(byte[] backup, X509Certificate2 recipient)
    {
        if (backup.Length == 0 || backup.Length > MaximumFileSize)
            throw new InvalidDataException("The backup file is empty or exceeds 64 MiB.");
        var envelope = JsonSerializer.Deserialize<Envelope>(backup, Json)
            ?? throw new InvalidDataException("The backup file is empty.");
        if (envelope.Format != Format || envelope.Version != 1 || envelope.Algorithm != Algorithm)
            throw new InvalidDataException("Unsupported passkey backup format, version, or encryption algorithm.");
        if (!string.Equals(envelope.Recipient, Fingerprint(recipient), StringComparison.Ordinal))
            throw new CryptographicException("This backup was encrypted for a different certificate.");
        using var rsa = recipient.GetRSAPrivateKey()
            ?? throw new CryptographicException("The selected certificate has no RSA private key. Select its password-protected PFX file.");
        if (rsa.KeySize < 2048 || envelope.WrappedKey?.Length != rsa.KeySize / 8 ||
            envelope.Nonce?.Length != 12 || envelope.Tag?.Length != 16 ||
            envelope.Ciphertext == null || envelope.Ciphertext.Length > MaximumPlaintextSize)
            throw new InvalidDataException("Invalid encrypted backup fields.");
        // Expired certificates can still decrypt old backups.
        var key = rsa.Decrypt(envelope.WrappedKey, RSAEncryptionPadding.OaepSHA256);
        var plaintext = new byte[envelope.Ciphertext.Length];
        IReadOnlyList<BackupCredential>? credentials = null;
        try
        {
            if (key.Length != 32) throw new InvalidDataException("Invalid backup encryption key.");
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, AssociatedData(envelope));
            credentials = CxfPasskeyFormat.Deserialize(plaintext);
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var credential in credentials)
            {
                if (credential == null) throw new InvalidDataException("Missing credential.");
                credential.Validate();
                if (!ids.Add(Convert.ToHexString(credential.Metadata.CredentialId)))
                    throw new InvalidDataException("The backup contains duplicate credential IDs.");
            }
            return credentials;
        }
        catch
        {
            Clear(credentials);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static void Clear(IEnumerable<BackupCredential>? credentials)
    {
        if (credentials == null) return;
        foreach (var entry in credentials)
            if (entry?.PrivateKeyPkcs8 != null) CryptographicOperations.ZeroMemory(entry.PrivateKeyPkcs8);
    }

    private static byte[] AssociatedData(Envelope e) => Encoding.UTF8.GetBytes(
        $"{e.Format}\n{e.Version}\n{e.Algorithm}\n{e.Recipient}\n{Convert.ToBase64String(e.WrappedKey)}");

    private sealed record Envelope(string Format, int Version, string Algorithm, string Recipient,
        byte[] WrappedKey, byte[] Nonce, byte[] Ciphertext, byte[] Tag);
}

internal sealed record BackupCredential(CredentialInfo Metadata, byte[] PrivateKeyPkcs8)
{
    public void Validate()
    {
        if (Metadata == null || Metadata.CredentialId == null || Metadata.CredentialId.Length is < 1 or > 1023 ||
            Metadata.UserId == null || Metadata.UserId.Length is < 1 or > 64 ||
            string.IsNullOrWhiteSpace(Metadata.RpId) || Metadata.RpId.Length > 253 ||
            Metadata.UserName == null || Metadata.UserName.Length > 4096 ||
            Metadata.UserDisplayName == null || Metadata.UserDisplayName.Length > 4096 ||
            Metadata.CredProtect is < 1 or > 3 || PrivateKeyPkcs8 == null || PrivateKeyPkcs8.Length is < 1 or > 4096)
            throw new InvalidDataException("Invalid credential metadata or private key.");
        using var key = LoadP256(PrivateKeyPkcs8);
    }

    public static ECDsa LoadP256(byte[] privateKey)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportPkcs8PrivateKey(privateKey, out var read);
            if (read != privateKey.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new InvalidDataException("Only ES256 / P-256 private keys are supported.");
            return key;
        }
        catch { key.Dispose(); throw; }
    }
}
