using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VFido.SecretManager;

public sealed record TransferIdentity(byte[] Certificate, byte[] PasswordProtectedPfx, string Fingerprint);

/// <summary>
/// Certificate-encrypted CXF structure with VirtualFido metadata and counter extensions.
/// Nonzero counters are preserved; this profile does not claim strict CXF/CXP conformance.
/// CXP response layout with certificate-addressed RFC 9180 HPKE base mode.
/// </summary>
public static class PasskeyBackup
{
    public const int MaximumFileSize = 64 * 1024 * 1024;

    public static TransferIdentity CreateIdentity(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("A non-empty password is required for the private-key file.", nameof(password));
        using var agreement = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var parameters = agreement.ExportParameters(true);
        using var key = ECDsa.Create();
        try { key.ImportParameters(parameters); }
        finally { CryptographicOperations.ZeroMemory(parameters.D!); }
        var request = new CertificateRequest("CN=VirtualFido Credential Transfer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyAgreement, true));
        // CreateSelfSigned attaches an ECDSA key, which Windows rejects for a key-agreement-only
        // certificate. Sign the certificate explicitly, then attach the matching ECDH private key.
        using var publicCertificate = request.Create(request.SubjectName, X509SignatureGenerator.CreateForECDsa(key),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5), RandomNumberGenerator.GetBytes(16));
        using var certificate = publicCertificate.CopyWithPrivateKey(agreement);
        return new(certificate.Export(X509ContentType.Cert), certificate.Export(X509ContentType.Pfx, password), Fingerprint(certificate));
    }

    public static string Fingerprint(X509Certificate2 certificate) => certificate.GetCertHashString(HashAlgorithmName.SHA256);

    public static void ValidateRecipient(X509Certificate2 certificate)
    {
        using var key = certificate.GetECDiffieHellmanPublicKey();
        if (key == null || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new InvalidOperationException("Select a P-256 key-agreement certificate. Create a new transfer certificate to replace an old RSA certificate.");
        if (DateTime.UtcNow < certificate.NotBefore.ToUniversalTime() || DateTime.UtcNow > certificate.NotAfter.ToUniversalTime())
            throw new InvalidOperationException("The recipient certificate is not currently valid. Create a new transfer certificate.");
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (usage != null && (usage.KeyUsages & X509KeyUsageFlags.KeyAgreement) == 0)
            throw new InvalidOperationException("The recipient certificate does not permit key agreement.");
    }

    internal static byte[] Encrypt(IReadOnlyList<BackupCredential> credentials, X509Certificate2 recipient)
    {
        ValidateRecipient(recipient);
        var plaintext = CxfPasskeyFormat.Serialize(credentials);
        try { return CxpTransport.EncryptPayload(plaintext, recipient); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal static IReadOnlyList<BackupCredential> Decrypt(byte[] backup, X509Certificate2 recipient)
    {
        var plaintext = CxpTransport.DecryptPayload(backup, recipient);
        IReadOnlyList<BackupCredential>? credentials = null;
        try
        {
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
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static void Clear(IEnumerable<BackupCredential>? credentials)
    {
        if (credentials == null) return;
        foreach (var entry in credentials)
            if (entry?.PrivateKeyPkcs8 != null) CryptographicOperations.ZeroMemory(entry.PrivateKeyPkcs8);
    }
}

internal sealed record BackupCredential(CredentialInfo Metadata, byte[] PrivateKeyPkcs8, bool DisableSignCount = false)
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
        if (DisableSignCount && Metadata.SignCount != 0)
            throw new InvalidDataException("A disabled signature counter must be zero.");
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
