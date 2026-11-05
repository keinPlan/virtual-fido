using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace VFido.SecretManager;

/// <summary>Request-free certificate profile of the October 2024 CXP ExportResponse layout.</summary>
internal static class CxpTransport
{
    internal const int MaximumPlaintextSize = 32 * 1024 * 1024;
    private const int MaximumJweSize = 45 * 1024 * 1024;
    private const string IndexName = "CXP-Export/index.jwe";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 16 };

    internal sealed record Jwk(string Kty, string Crv, string X, string Y);
    internal sealed record Parameters(string Mode, int Kem, int Kdf, int Aead, Jwk Key);
    internal sealed record Metadata(int Version, Parameters Hpke, string Archive, string Exporter);
    internal sealed record Response(int Version, Parameters Hpke, string Archive, string Exporter, string Payload);
    private sealed record ProtectedHeader(string Alg, string Enc, string Kid);

    internal static byte[] EncryptPayload(byte[] plaintext, X509Certificate2 certificate)
    {
        if (plaintext.Length > MaximumPlaintextSize) throw new InvalidDataException("CXF payload exceeds 32 MiB.");
        using var recipient = certificate.GetECDiffieHellmanPublicKey()
            ?? throw new CryptographicException("Select a P-256 key-agreement certificate.");
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var enc = HpkeBase.PublicKey(ephemeral);
        var metadata = new Metadata(0, new Parameters("base", 16, 1, 1,
            new Jwk("EC", "P-256", Encode(enc[1..33]), Encode(enc[33..65]))), "deflate", CxfPasskeyFormat.ExporterRpId);
        using var context = HpkeBase.Sender(ephemeral, recipient, Info(metadata));
        var header = Encode(JsonSerializer.SerializeToUtf8Bytes(new ProtectedHeader("dir", "A128GCM", PasskeyBackup.Fingerprint(certificate)), Json));
        var encrypted = context.Seal(plaintext, Encoding.ASCII.GetBytes(header));
        var jwe = string.Join('.', header, "", Encode(context.Nonce), Encode(encrypted[..^16]), Encode(encrypted[^16..]));
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, true))
        {
            var entry = archive.CreateEntry(IndexName, CompressionLevel.Optimal);
            using var stream = entry.Open();
            stream.Write(Encoding.ASCII.GetBytes(jwe));
        }
        return JsonSerializer.SerializeToUtf8Bytes(new Response(metadata.Version, metadata.Hpke, metadata.Archive, metadata.Exporter, Encode(buffer.ToArray())), Json);
    }

    internal static byte[] DecryptPayload(byte[] bytes, X509Certificate2 certificate)
    {
        if (bytes.Length == 0 || bytes.Length > PasskeyBackup.MaximumFileSize)
            throw new InvalidDataException("The CXP response is empty or exceeds 64 MiB.");
        try
        {
            var response = JsonSerializer.Deserialize<Response>(bytes, Json)
                ?? throw new InvalidDataException("Missing CXP response.");
            var p = response.Hpke;
            if (response.Version != 0 || p == null || p.Mode != "base" || p.Kem != 16 || p.Kdf != 1 || p.Aead != 1 ||
                p.Key == null || p.Key.Kty != "EC" || p.Key.Crv != "P-256" || response.Archive != "deflate" ||
                string.IsNullOrWhiteSpace(response.Exporter) || response.Exporter.Length > 253)
                throw new InvalidDataException("Unsupported CXP version, HPKE parameters, archive, or exporter.");
            byte[] enc = [4, .. Decode(p.Key.X, 32, 32), .. Decode(p.Key.Y, 32, 32)];
            using var recipient = certificate.GetECDiffieHellmanPrivateKey()
                ?? throw new CryptographicException("Select the matching P-256 private PFX.");
            var metadata = new Metadata(response.Version, p, response.Archive, response.Exporter);
            using var context = HpkeBase.Receiver(recipient, enc, Info(metadata));
            using var buffer = new MemoryStream(Decode(response.Payload, 1, MaximumJweSize));
            using var archive = new ZipArchive(buffer, ZipArchiveMode.Read);
            if (archive.Entries.Count != 1 || archive.Entries[0].FullName != IndexName)
                throw new InvalidDataException("Expected a single CXP-Export/index.jwe entry.");
            var entry = archive.Entries[0];
            if (entry.Length > MaximumJweSize) throw new InvalidDataException("JWE exceeds size limit.");
            using var stream = entry.Open();
            using var content = new MemoryStream();
            var chunk = new byte[81920];
            int read;
            while ((read = stream.Read(chunk)) != 0)
            {
                if (content.Length + read > MaximumJweSize) throw new InvalidDataException("JWE exceeds size limit.");
                content.Write(chunk, 0, read);
            }
            var parts = Encoding.ASCII.GetString(content.ToArray()).Split('.');
            if (parts.Length != 5 || parts[1] != "") throw new InvalidDataException("Invalid compact JWE.");
            var header = JsonSerializer.Deserialize<ProtectedHeader>(Decode(parts[0], 1, 1024), Json);
            if (header == null || header.Alg != "dir" || header.Enc != "A128GCM")
                throw new InvalidDataException("Unsupported JWE header.");
            if (header.Kid != PasskeyBackup.Fingerprint(certificate))
                throw new CryptographicException("The response was encrypted for a different certificate.");
            var nonce = Decode(parts[2], 12, 12);
            if (!CryptographicOperations.FixedTimeEquals(nonce, context.Nonce))
                throw new CryptographicException("Invalid HPKE nonce.");
            var ciphertext = Decode(parts[3], 0, MaximumPlaintextSize);
            var tag = Decode(parts[4], 16, 16);
            return context.Open([.. ciphertext, .. tag], Encoding.ASCII.GetBytes(parts[0]));
        }
        catch (Exception error) when (error is JsonException or FormatException or ArgumentException or OverflowException)
        {
            throw new InvalidDataException("Malformed CXP response.", error);
        }
    }

    // Bind the response metadata to HPKE. Canonical property order is defined by Metadata/Parameters/Jwk.
    // This context and the single-index JWE layout are explicit choices of the request-free profile.
    private static byte[] Info(Metadata metadata) =>
        [.. "VirtualFido/CXP/certificate-base/v1\n"u8, .. JsonSerializer.SerializeToUtf8Bytes(metadata, Json)];

    internal static string Encode(byte[] value) => CxfPasskeyFormat.Encode(value);
    internal static byte[] Decode(string value, int minimum = 0, int maximum = MaximumJweSize)
    {
        if (value == null || value.Length > ((long)maximum * 4 + 2) / 3 ||
            value.Any(c => !(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            throw new InvalidDataException("Invalid base64url field.");
        var decoded = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        if (decoded.Length < minimum || decoded.Length > maximum || Encode(decoded) != value)
            throw new InvalidDataException("Invalid base64url field size or encoding.");
        return decoded;
    }
}
