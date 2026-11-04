using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Tpm2Lib;

namespace VFido.SecretManager.TpmBasedSecretStore;

/// <summary>Password-protected portable RSA storage parent, including its child-wrapping seed.</summary>
public sealed class TpmMasterKey : IDisposable
{
    // Application-specific UUID OID; payload is a versioned DER sequence, not a certificate extension.
    private const string RecoveryOid = "2.25.283804781146552502253219919921438285001";
    private readonly RSA _rsa;
    private readonly byte[] _seed;
    private readonly byte[] _public;
    private bool _disposed;
    private static readonly PbeParameters Protection = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 200_000);

    private TpmMasterKey(RSA rsa, byte[] seed, byte[] publicArea)
    {
        _rsa = rsa;
        _seed = seed;
        _public = publicArea;
    }

    public byte[] PublicArea { get { ThrowIfDisposed(); return _public.ToArray(); } }
    public byte[] Name => Public.GetName();
    internal TpmPublic Public => Marshaller.FromTpmRepresentation<TpmPublic>(PublicArea);

    public static TpmMasterKey Generate()
    {
        var rsa = RSA.Create(2048);
        return FromRsa(rsa, RandomNumberGenerator.GetBytes(32));
    }

    /// <summary>Copies caller-owned RSA-2048 material and a 32-byte SHA-256 storage seed.</summary>
    public static TpmMasterKey FromExternal(RSA rsa, ReadOnlySpan<byte> seed)
    {
        if (rsa.KeySize != 2048 || seed.Length != 32)
            throw new ArgumentException("An RSA-2048 private key and 32-byte seed are required.");
        var copy = RSA.Create();
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        try { copy.ImportPkcs8PrivateKey(pkcs8, out _); return FromRsa(copy, seed.ToArray()); }
        catch { copy.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(pkcs8); }
    }

    private static TpmMasterKey FromRsa(RSA rsa, byte[] seed)
    {
        var p = rsa.ExportParameters(false);
        if (!p.Exponent!.AsSpan().SequenceEqual(new byte[] { 1, 0, 1 }))
            throw new ArgumentException("RSA exponent must be 65537.");
        return new TpmMasterKey(rsa, seed, StorageTemplate(p.Modulus!).GetTpmRepresentation());
    }

    internal static TpmPublic StorageTemplate(byte[] modulus, bool primary = false) => new(
        TpmAlgId.Sha256,
        ObjectAttr.Restricted | ObjectAttr.Decrypt | ObjectAttr.UserWithAuth | ObjectAttr.AdminWithPolicy | ObjectAttr.NoDA |
        (primary ? ObjectAttr.FixedTPM | ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin : 0),
        Array.Empty<byte>(),
        new RsaParms(new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb), new NullAsymScheme(), 2048, 0),
        new Tpm2bPublicKeyRsa(modulus));

    public byte[] ExportPfx(string password)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        var request = new CertificateRequest("CN=VirtualFido TPM recovery master", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(20));
        var payload = new AsnWriter(AsnEncodingRules.DER);
        payload.PushSequence();
        payload.WriteInteger(1);
        payload.WriteOctetString(_seed);
        payload.WriteOctetString(_public);
        payload.PopSequence();
        var encoded = payload.Encode();
        try
        {
            var contents = new Pkcs12SafeContents();
            contents.AddCertificate(certificate);
            contents.AddShroudedKey(_rsa, password, Protection);
            contents.AddSecret(new Oid(RecoveryOid), encoded);
            var builder = new Pkcs12Builder();
            builder.AddSafeContentsEncrypted(contents, password, Protection);
            builder.SealWithMac(password, HashAlgorithmName.SHA256, 200_000);
            return builder.Encode();
        }
        finally { CryptographicOperations.ZeroMemory(encoded); payload.Reset(); }
    }

    public static TpmMasterKey ImportPfx(byte[] pfx, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (pfx.Length > 1_048_576) throw new InvalidDataException("Recovery PFX is too large.");
        var info = Pkcs12Info.Decode(pfx, out var consumed);
        if (consumed != pfx.Length || info.IntegrityMode != Pkcs12IntegrityMode.Password || !info.VerifyMac(password))
            throw new CryptographicException("Invalid recovery PFX or password.");
        RSA? rsa = null;
        byte[]? seed = null;
        byte[]? publicArea = null;
        X509Certificate2? cert = null;
        try
        {
            foreach (var safe in info.AuthenticatedSafe)
            {
                if (safe.ConfidentialityMode != Pkcs12ConfidentialityMode.Password)
                    throw new InvalidDataException("All recovery safe contents must be password encrypted.");
                safe.Decrypt(password);
                foreach (var bag in safe.GetBags())
                {
                    if (bag is Pkcs12ShroudedKeyBag key)
                    {
                        if (rsa != null) throw new InvalidDataException("Duplicate master key.");
                        rsa = RSA.Create();
                        rsa.ImportEncryptedPkcs8PrivateKey(password, key.EncryptedPkcs8PrivateKey.Span, out var read);
                        if (read != key.EncryptedPkcs8PrivateKey.Length || rsa.KeySize != 2048)
                            throw new InvalidDataException("Expected one RSA-2048 private key.");
                    }
                    else if (bag is Pkcs12SecretBag secret && secret.GetSecretType().Value == RecoveryOid)
                    {
                        if (seed != null) throw new InvalidDataException("Duplicate master metadata.");
                        var reader = new AsnReader(secret.SecretValue, AsnEncodingRules.DER);
                        var sequence = reader.ReadSequence();
                        if (sequence.ReadInteger() != 1) throw new InvalidDataException("Unsupported master format.");
                        seed = sequence.ReadOctetString();
                        publicArea = sequence.ReadOctetString();
                        sequence.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
                    }
                    else if (bag is Pkcs12CertBag certificate)
                    {
                        if (cert != null) throw new InvalidDataException("Duplicate recovery certificate.");
                        cert = certificate.GetCertificate();
                    }
                    else throw new InvalidDataException("Unexpected recovery bag.");
                }
            }
            if (rsa == null || seed?.Length != 32 || publicArea == null || cert == null)
                throw new InvalidDataException("Incomplete master recovery PFX.");
            var expected = StorageTemplate(rsa.ExportParameters(false).Modulus!).GetTpmRepresentation();
            using var certKey = cert.GetRSAPublicKey();
            if (!expected.AsSpan().SequenceEqual(publicArea) || certKey == null ||
                !certKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(rsa.ExportSubjectPublicKeyInfo()))
                throw new InvalidDataException("Master template, certificate, and private key do not match.");
            var result = new TpmMasterKey(rsa, seed, publicArea);
            rsa = null; seed = null;
            return result;
        }
        finally
        {
            rsa?.Dispose(); cert?.Dispose();
            if (seed != null) CryptographicOperations.ZeroMemory(seed);
        }
    }

    internal TssObject ToImportObject()
    {
        ThrowIfDisposed();
        var p = _rsa.ExportParameters(true);
        try { return new TssObject(Public, new Sensitive(Array.Empty<byte>(), _seed.ToArray(), new Tpm2bPrivateKeyRsa(p.P!)), null!); }
        finally
        {
            // P is owned by the returned sensitive structure and cleared by the importer.
            foreach (var value in new[] { p.D, p.Q, p.DP, p.DQ, p.InverseQ })
                if (value != null) CryptographicOperations.ZeroMemory(value);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _rsa.Dispose(); CryptographicOperations.ZeroMemory(_seed);
    }
}

