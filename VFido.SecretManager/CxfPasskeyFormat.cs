using System.Security.Cryptography;
using System.Text.Json;

namespace VFido.SecretManager;

/// <summary>CXF 1.0 structure with a VirtualFido extension preserving counters and protection.</summary>
internal static class CxfPasskeyFormat
{
    internal const string ExporterRpId = "virtualfido.local";
    internal const string MetadataExtension = ExporterRpId + "/CredentialMetadata";

    internal static string Encode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static byte[] Serialize(IReadOnlyList<BackupCredential> credentials)
    {
        if (credentials.Count is < 1 or > 10000)
            throw new InvalidDataException("Select between 1 and 10000 passkeys.");
        foreach (var entry in credentials) entry.Validate();
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = new { major = 1, minor = 0 },
            exporterRpId = ExporterRpId,
            exporterDisplayName = "VirtualFido",
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            accounts = new[]
            {
                new
                {
                    id = Encode(RandomNumberGenerator.GetBytes(16)),
                    username = "",
                    email = "",
                    collections = Array.Empty<object>(),
                    items = credentials.Select(entry => new
                    {
                        id = Encode(SHA256.HashData(entry.Metadata.CredentialId)),
                        title = entry.Metadata.RpId,
                        credentials = new[]
                        {
                            new
                            {
                                type = "passkey",
                                credentialId = Encode(entry.Metadata.CredentialId),
                                rpId = entry.Metadata.RpId,
                                username = entry.Metadata.UserName,
                                userDisplayName = entry.Metadata.UserDisplayName,
                                userHandle = Encode(entry.Metadata.UserId),
                                key = Encode(entry.PrivateKeyPkcs8),
                            },
                        },
                        extensions = new[]
                        {
                            new
                            {
                                name = MetadataExtension,
                                credentialId = Encode(entry.Metadata.CredentialId),
                                isResident = entry.Metadata.IsResident,
                                credProtect = entry.Metadata.CredProtect,
                                signCount = entry.Metadata.SignCount,
                                disableSignCount = entry.DisableSignCount,
                            },
                        },
                    }),
                },
            },
        });
    }

    internal static IReadOnlyList<BackupCredential> Deserialize(byte[] plaintext)
    {
        var entries = new List<BackupCredential>();
        try
        {
            using var document = JsonDocument.Parse(plaintext, new JsonDocumentOptions { MaxDepth = 32 });
            var root = document.RootElement;
            var version = root.GetProperty("version");
            if (version.GetProperty("major").GetInt32() != 1 || version.GetProperty("minor").GetUInt32() > 255)
                throw new InvalidDataException("Unsupported CXF version.");
            _ = Text(root, "exporterRpId", 253);
            _ = Text(root, "exporterDisplayName", 4096);
            _ = root.GetProperty("timestamp").GetUInt64();
            foreach (var account in root.GetProperty("accounts").EnumerateArray())
            {
                _ = Binary(account, "id", 1, 64);
                _ = Text(account, "username", 4096);
                _ = Text(account, "email", 4096);
                _ = account.GetProperty("collections").EnumerateArray();
                foreach (var item in account.GetProperty("items").EnumerateArray())
                {
                    _ = Binary(item, "id", 1, 64);
                    _ = Text(item, "title", 4096);
                    var metadata = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                    if (item.TryGetProperty("extensions", out var extensions))
                    {
                        foreach (var extension in extensions.EnumerateArray())
                        {
                            if (Text(extension, "name", 4096) != MetadataExtension) continue;
                            var id = Encode(Binary(extension, "credentialId", 1, 1023));
                            if (!metadata.TryAdd(id, extension))
                                throw new InvalidDataException("Duplicate credential metadata extension.");
                        }
                    }
                    foreach (var credential in item.GetProperty("credentials").EnumerateArray())
                    {
                        if (Text(credential, "type", 4096) != "passkey") continue;
                        if (entries.Count >= 10000) throw new InvalidDataException("Too many passkeys.");
                        // Do not silently lose extension secrets or authentication requirements.
                        if (credential.TryGetProperty("fido2Extensions", out var fidoExtensions))
                        {
                            foreach (var field in fidoExtensions.EnumerateObject())
                                if (field.Name is "hmacCredentials" or "credBlob" or "largeBlob" or "payments")
                                    throw new InvalidDataException("This passkey requires an unsupported FIDO2 extension.");
                        }
                        var credentialId = Binary(credential, "credentialId", 1, 1023);
                        var hasMetadata = metadata.Remove(Encode(credentialId), out var settings);
                        var info = new CredentialInfo(credentialId,
                            Text(credential, "rpId", 253),
                            Binary(credential, "userHandle", 1, 64),
                            Text(credential, "username", 4096),
                            Text(credential, "userDisplayName", 4096),
                            hasMetadata ? settings.GetProperty("isResident").GetBoolean() : true,
                            hasMetadata ? settings.GetProperty("signCount").GetUInt32() : 0,
                            hasMetadata ? settings.GetProperty("credProtect").GetInt32() : 1);
                        var disableSignCount = !hasMetadata || settings.GetProperty("disableSignCount").GetBoolean();
                        var entry = new BackupCredential(info, Binary(credential, "key", 1, 4096), disableSignCount);
                        entries.Add(entry); // Track key bytes before validation for cleanup on every failure.
                        entry.Validate();
                    }
                    if (metadata.Count != 0)
                        throw new InvalidDataException("Credential metadata does not match an enclosed passkey.");
                }
            }
            if (entries.Count == 0) throw new InvalidDataException("The payload contains no supported passkeys.");
            return entries;
        }
        catch (Exception error)
        {
            PasskeyBackup.Clear(entries);
            if (error is JsonException or InvalidOperationException or KeyNotFoundException or
                FormatException or OverflowException or CryptographicException)
                throw new InvalidDataException("Invalid CXF passkey payload.", error);
            throw;
        }
    }

    private static string Text(JsonElement parent, string name, int maximum)
    {
        var value = parent.GetProperty(name).GetString();
        if (value == null || value.Length > maximum)
            throw new InvalidDataException("Invalid CXF " + name + ".");
        return value;
    }

    private static byte[] Binary(JsonElement parent, string name, int minimum, int maximum)
    {
        var value = Text(parent, name, (maximum * 4 + 2) / 3);
        if (value.Any(c => !(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            throw new InvalidDataException("Invalid base64url in " + name + ".");
        var decoded = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') +
            new string('=', (4 - value.Length % 4) % 4));
        if (decoded.Length < minimum || decoded.Length > maximum || Encode(decoded) != value)
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidDataException("Invalid CXF " + name + ".");
        }
        return decoded;
    }
}
