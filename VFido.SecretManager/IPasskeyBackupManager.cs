using System.Security.Cryptography.X509Certificates;

namespace VFido.SecretManager;

/// <summary>Optional management capability. CTAP signing never needs private-key export.</summary>
public interface IPasskeyBackupManager
{
    bool SupportsPasskeyBackup { get; }
    Task<byte[]> ExportPasskeysAsync(IReadOnlyList<byte[]> credentialIds, X509Certificate2 recipient);
    Task<PasskeyImportPreview> PreviewPasskeyImportAsync(byte[] backup, X509Certificate2 recipient);
    Task<PasskeyImportResult> ImportPasskeysAsync(byte[] backup, X509Certificate2 recipient);
}

public sealed record PasskeyImportPreview(IReadOnlyList<CredentialInfo> Credentials, int AlreadyPresent);
public sealed record PasskeyImportResult(int Imported, int Skipped);

/// <summary>Opt-in backend capability; handles must never be interpreted by the caller.</summary>
public interface ICredentialKeyTransfer
{
    byte[] ExportPkcs8(byte[] handle);
    byte[] ImportPkcs8(byte[] privateKey);
}
