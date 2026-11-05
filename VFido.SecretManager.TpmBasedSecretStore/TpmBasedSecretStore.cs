using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Tpm2Lib;
using VFido.SecretManager.Crypto;

namespace VFido.SecretManager.TpmBasedSecretStore;

/// <summary>Externally provisioned, portable storage parent with TPM-only runtime signing.</summary>
public sealed class TpmBasedSecretStore : IKeyStore, ICredentialKeyImporter, IDisposable
{
    private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
    private const string MasterFile = "master.json";
    // One shared cache for this application's deterministic owner primary. Never evict an occupant.
    private const uint PrimaryCacheHandle = 0x81015646;
    private readonly object _sync = new();
    private readonly string _directory;
    private readonly Tpm2 _tpm;
    private readonly TpmHandle _primary;
    private readonly bool _primaryIsTransient;
    private readonly TpmHandle _master;
    private readonly byte[] _masterName;
    private readonly TpmPublic _masterPublic;
    private readonly byte[] _masterAuthorization;
    private bool _disposed;
    private static readonly Guid ModelId = new("d7e3ebc2-38a2-4589-b903-ae19686c5dc8");
    public byte[] MasterName => _masterName.ToArray();
    public byte[] Aaguid => ModelId.ToByteArray(bigEndian: true);

    /// <summary>Evict this store's verified shared primary cache. Does not delete credential files.</summary>
    public static void DeleteCachedPrimary(string directory, Func<Tpm2Device>? deviceFactory = null,
        byte[]? ownerAuthorization = null)
    {
        var local = Read<LocalMaster>(Path.Combine(directory, MasterFile));
        if (local.Version is not (1 or 2) || local.PrimaryName == null)
            throw new InvalidDataException("Unsupported local master format.");
        using var tpm = Connect(deviceFactory);
        var handle = new TpmHandle(PrimaryCacheHandle);
        var pub = tpm.ReadPublic(handle, out _, out _);
        if (!pub.GetName().AsSpan().SequenceEqual(local.PrimaryName))
            throw new CryptographicException("The cached primary does not match this store. It was not deleted.");
        var owner = new TpmHandle(TpmRh.Owner) { Auth = ownerAuthorization ?? Array.Empty<byte>() };
        try
        {
            tpm.EvictControl(owner, handle, handle);
            Logger.Info("Deleted shared TPM primary cache at 0x{0:X8}.", PrimaryCacheHandle);
        }
        catch (TpmException)
        {
            Logger.Warn("Deleting TPM primary cache failed (TPM response: {0}).", tpm._GetLastResponseCode());
            throw;
        }
    }

    /// <summary>Import the recovery master once on this TPM. Does not overwrite existing provisioning.</summary>
    public static void Provision(string directory, TpmMasterKey master,
        Func<Tpm2Device>? deviceFactory = null, byte[]? ownerAuthorization = null, string? masterPassword = null)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, MasterFile);
        if (File.Exists(path)) throw new IOException("This directory already contains a local master. Use a new destination for recovery.");
        var authorization = Array.Empty<byte>();
        var protection = masterPassword == null ? null : TpmMasterProtection.Create(masterPassword, out authorization);
        try
        {
            var timer = Stopwatch.StartNew();
            Logger.Info("Provisioning TPM-wrapped master.");
            using var tpm = Connect(deviceFactory);
            var primary = CreatePrimary(tpm, ownerAuthorization, out var primaryPublic);
            try
            {
                TryCachePrimary(tpm, primary, primaryPublic.GetName(), ownerAuthorization);
                var source = master.ToImportObject(authorization);
                try
                {
                    var duplicate = TpmImportWrapping.Wrap(source, primaryPublic, out var secret);
                    try
                    {
                        var imported = tpm.Import(primary, Array.Empty<byte>(), source.Public, duplicate, secret, new SymDefObject());
                        var loaded = tpm.Load(primary, imported, source.Public);
                        tpm.FlushContext(loaded);
                        WriteNew(path, new LocalMaster(protection == null ? 1 : 2, primaryPublic.GetName(), source.Public.GetTpmRepresentation(), imported.buffer, protection));
                        Logger.Info("TPM master provisioned in {0} ms.", timer.ElapsedMilliseconds);
                    }
                    finally { CryptographicOperations.ZeroMemory(secret); }
                }
                finally { ClearSensitive(source.Sensitive); }
            }
            finally { tpm.FlushContext(primary); }
        }
        finally { CryptographicOperations.ZeroMemory(authorization); }
    }

    /// <summary>Open using the local TPM-wrapped master; the recovery PFX is not required.</summary>
    public TpmBasedSecretStore(string directory, Func<Tpm2Device>? deviceFactory = null, byte[]? ownerAuthorization = null,
        string? masterPassword = null)
    {
        var timer = Stopwatch.StartNew();
        Logger.Info("Opening TPM secret store.");
        _directory = directory;
        var local = Read<LocalMaster>(Path.Combine(directory, MasterFile));
        if (local.Version is not (1 or 2) || (local.Version == 2) != (local.Protection != null))
            throw new InvalidDataException("Unsupported or incomplete local master format.");
        _masterPublic = Marshaller.FromTpmRepresentation<TpmPublic>(local.Public);
        _masterName = _masterPublic.GetName();
        _masterAuthorization = local.Protection?.Unlock(masterPassword) ?? Array.Empty<byte>();
        if (local.Version == 1)
            Logger.Warn("This legacy TPM master has no object password protection. Restore with a master password to enable it.");
        try { _tpm = Connect(deviceFactory); }
        catch { CryptographicOperations.ZeroMemory(_masterAuthorization); throw; }
        TpmHandle? primary = null;
        try
        {
            primary = FindCachedPrimary(_tpm, local.PrimaryName);
            if (primary == null)
            {
                Logger.Info("No matching cached TPM primary; creating a transient primary.");
                primary = CreatePrimary(_tpm, ownerAuthorization, out var primaryPublic);
                _primaryIsTransient = true;
                if (!primaryPublic.GetName().AsSpan().SequenceEqual(local.PrimaryName))
                    throw new CryptographicException("Local master belongs to a different TPM or hierarchy. Restore from the recovery PFX.");
                TryCachePrimary(_tpm, primary, local.PrimaryName, ownerAuthorization);
            }
            var loadTimer = Stopwatch.StartNew();
            Logger.Debug("Loading TPM-wrapped master.");
            _master = _tpm.Load(primary, new TpmPrivate(local.Private), _masterPublic);
            _master.Auth = _masterAuthorization;
            Logger.Debug("TPM master loaded in {0} ms.", loadTimer.ElapsedMilliseconds);
            _primary = primary;
            Logger.Info("TPM secret store opened in {0} ms (cached primary: {1}).", timer.ElapsedMilliseconds, !_primaryIsTransient);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_masterAuthorization);
            Logger.Error("Opening TPM secret store failed after {0} ms (TPM response: {1}).", timer.ElapsedMilliseconds, _tpm._GetLastResponseCode());
            try { if (primary != null && _primaryIsTransient) _tpm.FlushContext(primary); }
            finally { _tpm.Dispose(); }
            throw;
        }
    }

    public ISigningKey CreateEs256Key()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var template = new TpmPublic(TpmAlgId.Sha256,
                ObjectAttr.Sign | ObjectAttr.UserWithAuth | ObjectAttr.AdminWithPolicy | ObjectAttr.NoDA |
                ObjectAttr.SensitiveDataOrigin,
                Array.Empty<byte>(),
                new EccParms(new SymDefObject(), new SchemeEcdsa(TpmAlgId.Sha256), EccCurve.TpmEccNistP256, new NullKdfScheme()),
                new EccPoint(Array.Empty<byte>(), Array.Empty<byte>()));
            // Leave FixedTPM/FixedParent unset so recovery under the portable master remains possible.
            var privateBlob = _tpm.Create(_master,
                new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
                template, Array.Empty<byte>(), Array.Empty<PcrSelection>(),
                out var publicArea, out _, out _, out _);
            var blob = new WrappedKey(1, _masterName, publicArea.GetTpmRepresentation(), privateBlob.buffer);
            ValidateLoad(blob);
            var handle = SaveKey(blob);
            return new TpmBasedSigningKey(this, handle, PublicParameters(blob));
        }
    }

    public byte[] ImportPkcs8(byte[] privateKey)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            using var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(privateKey, out var read);
            var publicParameters = key.ExportParameters(false);
            if (read != privateKey.Length || publicParameters.Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new InvalidDataException("Only P-256 PKCS#8 private keys are supported.");
            var p = key.ExportParameters(true);
            var pub = new TpmPublic(TpmAlgId.Sha256,
                ObjectAttr.Sign | ObjectAttr.UserWithAuth | ObjectAttr.AdminWithPolicy | ObjectAttr.NoDA,
                Array.Empty<byte>(),
                new EccParms(new SymDefObject(), new SchemeEcdsa(TpmAlgId.Sha256), EccCurve.TpmEccNistP256, new NullKdfScheme()),
                new EccPoint(p.Q.X!, p.Q.Y!));
            var sensitive = new Sensitive(Array.Empty<byte>(), Array.Empty<byte>(), new Tpm2bEccParameter(p.D!));
            var source = new TssObject(pub, sensitive, null!);
            try
            {
                var duplicate = TpmImportWrapping.Wrap(source, _masterPublic, out var secret);
                try
                {
                    var imported = _tpm.Import(_master, Array.Empty<byte>(), pub, duplicate, secret, new SymDefObject());
                    var blob = new WrappedKey(1, _masterName, pub.GetTpmRepresentation(), imported.buffer);
                    ValidateLoad(blob);
                    return SaveKey(blob);
                }
                finally { CryptographicOperations.ZeroMemory(secret); }
            }
            finally { ClearSensitive(sensitive); }
        }
    }

    public ISigningKey LoadKey(byte[] handle)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var blob = ReadKey(handle);
            ValidateLoad(blob);
            return new TpmBasedSigningKey(this, handle.ToArray(), PublicParameters(blob));
        }
    }

    public void DeleteKey(byte[] handle)
    {
        lock (_sync) { ThrowIfDisposed(); File.Delete(KeyPath(handle)); }
    }

    /// <summary>Portable wrapped object. Does not expose PKCS#8/private plaintext.</summary>
    public byte[] ExportWrappedKey(byte[] handle)
    {
        lock (_sync) { ThrowIfDisposed(); return JsonSerializer.SerializeToUtf8Bytes(ReadKey(handle)); }
    }

    public byte[] ImportWrappedKey(byte[] wrappedKey)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (wrappedKey.Length > 16384) throw new InvalidDataException("Wrapped key is too large.");
            var blob = JsonSerializer.Deserialize<WrappedKey>(wrappedKey) ?? throw new InvalidDataException("Missing wrapped key.");
            ValidateLoad(blob);
            return SaveKey(blob);
        }
    }

    internal byte[] Sign(byte[] handle, byte[] data)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var blob = ReadKey(handle);
            CheckBlob(blob);
            var key = _tpm.Load(_master, new TpmPrivate(blob.Private), Marshaller.FromTpmRepresentation<TpmPublic>(blob.Public));
            try
            {
                var signature = (SignatureEcdsa)_tpm.Sign(key, SHA256.HashData(data), new SchemeEcdsa(TpmAlgId.Sha256),
                    new TkHashcheck(new TpmHandle(TpmRh.Null), Array.Empty<byte>()));
                var writer = new AsnWriter(AsnEncodingRules.DER);
                writer.PushSequence();
                writer.WriteIntegerUnsigned(signature.signatureR);
                writer.WriteIntegerUnsigned(signature.signatureS);
                writer.PopSequence();
                return writer.Encode();
            }
            finally { _tpm.FlushContext(key); }
        }
    }

    public AttestationCertificate GetOrCreateAttestationCertificate()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var path = Path.Combine(_directory, "attestation.json");
            if (File.Exists(path))
            {
                var saved = Read<AttestationCertificate>(path);
                var blob = ReadKey(saved.KeyHandle);
                ValidateLoad(blob);
                using var certificate = new X509Certificate2(saved.CertificateChainDer[0]);
                using var publicKey = certificate.GetECDsaPublicKey();
                var actual = publicKey?.ExportParameters(false);
                var expected = PublicParameters(blob);
                if (actual == null || !actual.Value.Q.X!.AsSpan().SequenceEqual(expected.Q.X) ||
                    !actual.Value.Q.Y!.AsSpan().SequenceEqual(expected.Q.Y))
                    throw new InvalidDataException("Attestation key and certificate do not match.");
                return saved;
            }
            using var root = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var rootCert = AttestationCertificateFactory.CreateSelfSignedRoot(root);
            using var intermediate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var intermediateCert = AttestationCertificateFactory.CreateIntermediate(intermediate, root, rootCert);
            using var leaf = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var leafCert = AttestationCertificateFactory.CreateAttestationLeaf(leaf, intermediate, intermediateCert, Aaguid);
            var pkcs8 = leaf.ExportPkcs8PrivateKey();
            byte[]? handle = null;
            try
            {
                handle = ImportPkcs8(pkcs8);
                var certificate = new AttestationCertificate(handle, new[] { leafCert, intermediateCert });
                WriteNew(path, certificate);
                return certificate;
            }
            catch { if (handle != null) DeleteKey(handle); throw; }
            finally { CryptographicOperations.ZeroMemory(pkcs8); }
        }
    }

    private byte[] SaveKey(WrappedKey key)
    {
        var handle = Guid.NewGuid().ToByteArray();
        WriteNew(KeyPath(handle), key);
        return handle;
    }
    private WrappedKey ReadKey(byte[] handle) => Read<WrappedKey>(KeyPath(handle));
    private string KeyPath(byte[] handle)
    {
        if (handle.Length != 16) throw new InvalidDataException("A TPM key handle must be a 16-byte ID.");
        return Path.Combine(_directory, new Guid(handle).ToString("N") + ".tpmkey");
    }
    private void CheckBlob(WrappedKey blob)
    {
        if (blob.Version != 1 || blob.MasterName == null || blob.Public == null || blob.Private == null ||
            !blob.MasterName.AsSpan().SequenceEqual(_masterName))
            throw new InvalidDataException("Wrapped credential belongs to another master or format.");
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(blob.Public);
        if (pub.nameAlg != TpmAlgId.Sha256 || (pub.objectAttributes & ~ObjectAttr.SensitiveDataOrigin) !=
            (ObjectAttr.Sign | ObjectAttr.UserWithAuth | ObjectAttr.AdminWithPolicy | ObjectAttr.NoDA) ||
            pub.authPolicy.Length != 0 || pub.parameters is not EccParms ecc ||
            ecc.curveID != EccCurve.TpmEccNistP256 || ecc.scheme is not SigSchemeEcdsa scheme || scheme.hashAlg != TpmAlgId.Sha256)
            throw new InvalidDataException("Unexpected credential key template.");
    }
    private void ValidateLoad(WrappedKey blob)
    {
        CheckBlob(blob);
        var handle = _tpm.Load(_master, new TpmPrivate(blob.Private), Marshaller.FromTpmRepresentation<TpmPublic>(blob.Public));
        _tpm.FlushContext(handle);
    }
    private static ECParameters PublicParameters(WrappedKey blob)
    {
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(blob.Public);
        var point = (EccPoint)pub.unique;
        return new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = Pad(point.x), Y = Pad(point.y) } };
    }
    private static byte[] Pad(byte[] value)
    {
        if (value.Length > 32) throw new InvalidDataException("Invalid P-256 coordinate.");
        var result = new byte[32]; value.CopyTo(result, 32 - value.Length); return result;
    }
    private static Tpm2 Connect(Func<Tpm2Device>? factory)
    {
        var timer = Stopwatch.StartNew();
        var device = factory?.Invoke() ?? new TbsDevice();
        Logger.Debug("Connecting TPM transport {0}.", device.GetType().Name);
        try
        {
            device.Connect();
            Logger.Debug("TPM transport connected in {0} ms.", timer.ElapsedMilliseconds);
            return new Tpm2(device);
        }
        catch
        {
            Logger.Error("TPM transport connection failed after {0} ms.", timer.ElapsedMilliseconds);
            device.Dispose();
            throw;
        }
    }
    private static TpmHandle CreatePrimary(Tpm2 tpm, byte[]? ownerAuthorization, out TpmPublic pub)
    {
        var owner = new TpmHandle(TpmRh.Owner) { Auth = ownerAuthorization ?? Array.Empty<byte>() };
        var timer = Stopwatch.StartNew();
        Logger.Info("Starting TPM2_CreatePrimary (RSA-2048); this may take tens of seconds.");
        try
        {
            var primary = tpm.CreatePrimary(owner, new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
                TpmMasterKey.StorageTemplate(Array.Empty<byte>(), primary: true), Array.Empty<byte>(), Array.Empty<PcrSelection>(),
                out pub, out _, out _, out _);
            Logger.Info("TPM2_CreatePrimary completed in {0} ms.", timer.ElapsedMilliseconds);
            return primary;
        }
        catch
        {
            Logger.Error("TPM2_CreatePrimary failed after {0} ms (TPM response: {1}).", timer.ElapsedMilliseconds, tpm._GetLastResponseCode());
            throw;
        }
    }
    private static TpmHandle? FindCachedPrimary(Tpm2 tpm, byte[] expectedName)
    {
        var handle = new TpmHandle(PrimaryCacheHandle);
        try
        {
            // Never trust a persistent handle alone: another application may have reused it.
            var pub = tpm.ReadPublic(handle, out _, out _);
            if (pub.GetName().AsSpan().SequenceEqual(expectedName))
            {
                Logger.Info("Verified persistent TPM primary at 0x{0:X8}.", PrimaryCacheHandle);
                return handle;
            }
            Logger.Debug("Persistent TPM handle 0x{0:X8} does not match this store's primary; leaving it intact.", PrimaryCacheHandle);
            return null;
        }
        catch (TpmException)
        {
            // Missing handle or a TPM that does not permit access to persistent objects.
            Logger.Debug("TPM primary unavailable at 0x{0:X8} (TPM response: {1}).", PrimaryCacheHandle, tpm._GetLastResponseCode());
            return null;
        }
    }
    private static void TryCachePrimary(Tpm2 tpm, TpmHandle primary, byte[] expectedName, byte[]? ownerAuthorization)
    {
        if (FindCachedPrimary(tpm, expectedName) != null) return;
        try
        {
            Logger.Debug("Persisting TPM primary at 0x{0:X8}.", PrimaryCacheHandle);
            var owner = new TpmHandle(TpmRh.Owner) { Auth = ownerAuthorization ?? Array.Empty<byte>() };
            // primary is always transient. EvictControl therefore only adds a persistent copy;
            // an occupied destination (including a concurrent creator) fails without replacing it.
            tpm.EvictControl(owner, primary, new TpmHandle(PrimaryCacheHandle));
            Logger.Info("TPM primary cached at 0x{0:X8}; future connections can skip TPM2_CreatePrimary.", PrimaryCacheHandle);
        }
        catch (TpmException)
        {
            // Caching is optional: owner authorization, OS policy, or NV space may prevent it.
            Logger.Warn("TPM primary caching failed (TPM response: {0}); continuing with transient primary. Future connections may remain slow.", tpm._GetLastResponseCode());
            if (tpm._GetLastResponseCode() == TpmRc.TbsCommandBlocked)
                Logger.Warn("Windows TBS blocked TPM2_EvictControl. Retry primary caching from an elevated process; TPM owner authorization is also required. Modern Windows TPM 2.0 command restrictions cannot be changed through registry allow lists.");
        }
    }
    private static void ClearSensitive(Sensitive sensitive)
    {
        CryptographicOperations.ZeroMemory(sensitive.seedValue);
        CryptographicOperations.ZeroMemory(sensitive.authValue);
        if (sensitive.sensitive is Tpm2bPrivateKeyRsa rsa) CryptographicOperations.ZeroMemory(rsa.buffer);
        if (sensitive.sensitive is Tpm2bEccParameter ecc) CryptographicOperations.ZeroMemory(ecc.buffer);
    }
    private static T Read<T>(string path)
    {
        if (new FileInfo(path).Length > 65536) throw new InvalidDataException("TPM state file is too large.");
        return JsonSerializer.Deserialize<T>(File.ReadAllBytes(path)) ?? throw new InvalidDataException("Invalid TPM state file.");
    }
    private static void WriteNew<T>(string path, T data)
    {
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { JsonSerializer.Serialize(stream, data); stream.Flush(flushToDisk: true); }
            File.Move(temp, path, overwrite: false);
        }
        finally { File.Delete(temp); }
    }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            try { _tpm.FlushContext(_master); }
            finally
            {
                CryptographicOperations.ZeroMemory(_master.Auth);
                CryptographicOperations.ZeroMemory(_masterAuthorization);
                try { if (_primaryIsTransient) _tpm.FlushContext(_primary); } finally { _tpm.Dispose(); }
            }
        }
    }
    private sealed record LocalMaster(int Version, byte[] PrimaryName, byte[] Public, byte[] Private,
        TpmMasterProtection? Protection = null);
    private sealed record WrappedKey(int Version, byte[] MasterName, byte[] Public, byte[] Private);
}

public sealed class TpmBasedSigningKey : ISigningKey
{
    private readonly TpmBasedSecretStore _store;
    private readonly byte[] _handle;
    private readonly ECParameters _public;
    internal TpmBasedSigningKey(TpmBasedSecretStore store, byte[] handle, ECParameters publicKey)
    { _store = store; _handle = handle; _public = publicKey; }
    public int CoseAlgorithm => -7;
    public byte[] Sign(byte[] data) => _store.Sign(_handle, data);
    public byte[] ExportCosePublicKey() => CoseKeyEncoder.Encode(_public);
    public byte[] ExportHandle() => _handle.ToArray();
}



