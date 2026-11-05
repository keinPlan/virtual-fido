using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VFido.SecretManager;

public sealed partial class Fido2SecretManager
{
    public bool SupportsPasskeyBackup => _keys is ICredentialKeyTransfer;
    public bool SupportsPasskeyImport => _keys is ICredentialKeyImporter;

    public Task<byte[]> ExportPasskeysAsync(IReadOnlyList<byte[]> credentialIds, X509Certificate2 recipient)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var transfer = RequireKeyTransfer();
            if (credentialIds.Count is < 1 or > 10000)
                throw new InvalidOperationException("Select between 1 and 10000 passkeys to export.");
            var entries = new List<BackupCredential>();
            try
            {
                var ids = new HashSet<string>();
                foreach (var id in credentialIds)
                {
                    if (!ids.Add(Convert.ToHexString(id))) throw new InvalidOperationException("Duplicate export selection.");
                    var credential = RequireCredential(id);
                    var entry = new BackupCredential(ToInfo(credential), transfer.ExportPkcs8(credential.KeyHandle), credential.DisableSignCount);
                    entries.Add(entry);
                    entry.Validate();
                }
                return Task.FromResult(PasskeyBackup.Encrypt(entries, recipient));
            }
            finally { PasskeyBackup.Clear(entries); }
        }
    }

    public Task<PasskeyImportPreview> PreviewPasskeyImportAsync(byte[] backup, X509Certificate2 recipient)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            RequireKeyImporter();
            var entries = PasskeyBackup.Decrypt(backup, recipient);
            try
            {
                var pending = PlanImport(entries);
                return Task.FromResult(new PasskeyImportPreview(entries.Select(e => e.Metadata).ToList(), entries.Count - pending.Count));
            }
            finally { PasskeyBackup.Clear(entries); }
        }
    }

    public Task<PasskeyImportResult> ImportPasskeysAsync(byte[] backup, X509Certificate2 recipient)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var transfer = RequireKeyImporter();
            var entries = PasskeyBackup.Decrypt(backup, recipient);
            var created = new List<(byte[] Id, byte[] Handle)>();
            try
            {
                // Validate every collision before writing any keys or metadata.
                var pending = PlanImport(entries);
                foreach (var entry in pending)
                {
                    var handle = transfer.ImportPkcs8(entry.PrivateKeyPkcs8);
                    created.Add((entry.Metadata.CredentialId, handle));
                    var info = entry.Metadata;
                    _credentials.Save(new StoredCredential
                    {
                        CredentialId = info.CredentialId, RpId = info.RpId, UserId = info.UserId,
                        KeyHandle = handle, SignCount = info.SignCount, DisableSignCount = entry.DisableSignCount, IsResident = info.IsResident,
                        UserName = info.UserName, UserDisplayName = info.UserDisplayName, CredProtect = info.CredProtect,
                    });
                }
                return Task.FromResult(new PasskeyImportResult(pending.Count, entries.Count - pending.Count));
            }
            catch (Exception failure)
            {
                var errors = new List<Exception> { failure };
                foreach (var (id, handle) in created.AsEnumerable().Reverse())
                {
                    try { _credentials.Delete(id); } catch (Exception e) { errors.Add(e); }
                    try { _keys.DeleteKey(handle); } catch (Exception e) { errors.Add(e); }
                }
                if (errors.Count > 1)
                    throw new AggregateException("Import failed and cleanup was incomplete. Inspect the destination credentials before retrying.", errors);
                throw;
            }
            finally { PasskeyBackup.Clear(entries); }
        }
    }

    private List<BackupCredential> PlanImport(IReadOnlyList<BackupCredential> entries)
    {
        var pending = new List<BackupCredential>();
        foreach (var entry in entries)
        {
            var info = entry.Metadata;
            var existing = _credentials.Find(info.CredentialId);
            if (existing == null) { pending.Add(entry); continue; }
            using var key = BackupCredential.LoadP256(entry.PrivateKeyPkcs8);
            var publicKey = Crypto.CoseKeyEncoder.Encode(key.ExportParameters(false));
            if (existing.RpId != info.RpId || !existing.UserId.AsSpan().SequenceEqual(info.UserId) ||
                existing.IsResident != info.IsResident || existing.CredProtect != info.CredProtect ||
                !CryptographicOperations.FixedTimeEquals(_keys.LoadKey(existing.KeyHandle).ExportCosePublicKey(), publicKey))
                throw new InvalidDataException("A credential ID conflicts with an existing destination credential. No passkeys were imported.");
            // Keep destination metadata and counter on an identical duplicate.
        }
        return pending;
    }

    private ICredentialKeyImporter RequireKeyImporter() => _keys as ICredentialKeyImporter
        ?? throw new NotSupportedException("This backend does not support passkey import.");

    private ICredentialKeyTransfer RequireKeyTransfer() => _keys as ICredentialKeyTransfer
        ?? throw new NotSupportedException("This backend does not support passkey backup or import.");
}
