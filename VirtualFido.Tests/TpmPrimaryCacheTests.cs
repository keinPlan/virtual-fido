using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tpm2Lib;
using VFido.SecretManager.TpmBasedSecretStore;

namespace VirtualFido.Tests;

public sealed class TpmPrimaryCacheTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void DeleteCache_OnlyEvictsMatchingPrimaryAndPreservesFiles(bool matches)
    {
        using var master = TpmMasterKey.Generate();
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(master.PublicArea);
        var name = pub.GetName();
        if (!matches) name[^1] ^= 1;
        WithStore(pub, name, device =>
        {
            device.AllowEviction = true;
            var path = Path.Combine(device.Directory, "master.json");
            var original = File.ReadAllBytes(path);
            if (matches)
            {
                TpmBasedSecretStore.DeleteCachedPrimary(device.Directory, () => device);
                Assert.Equal(new uint[] { 0x81015646, 0x81015646 }, device.EvictionHandles);
            }
            else
            {
                Assert.Throws<CryptographicException>(() => TpmBasedSecretStore.DeleteCachedPrimary(device.Directory, () => device));
                Assert.DoesNotContain(TpmCc.EvictControl, device.Commands);
            }
            Assert.Equal(original, File.ReadAllBytes(path));
            Assert.DoesNotContain(TpmCc.CreatePrimary, device.Commands);
            Assert.Empty(device.Flushed);
        });
    }

    [Fact]
    public void DeleteCache_ReportsTpmFailure()
    {
        using var master = TpmMasterKey.Generate();
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(master.PublicArea);
        WithStore(pub, pub.GetName(), device =>
        {
            Assert.Throws<TpmException>(() => TpmBasedSecretStore.DeleteCachedPrimary(device.Directory, () => device));
            Assert.Contains(TpmCc.EvictControl, device.Commands);
        });
    }

    [Fact]
    public void ProtectedMaster_SuppliesDerivedAuthorizationToTpmCommands()
    {
        using var master = TpmMasterKey.Generate();
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(master.PublicArea);
        var protection = TpmMasterProtection.Create("store password", out var expected);
        try
        {
            WithStore(pub, pub.GetName(), device =>
            {
                var path = Path.Combine(device.Directory, "master.json");
                var local = JsonNode.Parse(File.ReadAllBytes(path))!;
                local["Version"] = 2;
                local["Protection"] = JsonSerializer.SerializeToNode(protection);
                File.WriteAllText(path, local.ToJsonString());
                using var store = new TpmBasedSecretStore(device.Directory, () => device, masterPassword: "store password");
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var pkcs8 = key.ExportPkcs8PrivateKey();
                try
                {
                    // The fake rejects Import after capturing its password session authorization.
                    Assert.Throws<TpmException>(() => store.ImportPkcs8(pkcs8));
                    Assert.Equal(expected, device.MasterAuthorization);
                }
                finally { CryptographicOperations.ZeroMemory(pkcs8); }
            });
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    [Fact]
    public void Reconnect_UsesMatchingPersistentPrimaryWithoutCreatingOrFlushingIt()
    {
        using var master = TpmMasterKey.Generate();
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(master.PublicArea);
        WithStore(pub, pub.GetName(), device =>
        {
            using (var store = new TpmBasedSecretStore(device.Directory, () => device)) { }
            Assert.DoesNotContain(TpmCc.CreatePrimary, device.Commands);
            Assert.DoesNotContain(TpmCc.EvictControl, device.Commands);
            Assert.All(device.ReadPublicHandles, handle => Assert.Equal(0x81015646u, handle));
            Assert.Equal(new uint[] { 0x80000001 }, device.Flushed);
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingOrReplacedCache_FallsBackToCreatePrimary(bool missing)
    {
        using var master = TpmMasterKey.Generate();
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(master.PublicArea);
        var expected = pub.GetName();
        expected[^1] ^= 1;
        WithStore(missing ? null : pub, expected, device =>
        {
            // The fake rejects CreatePrimary, allowing us to observe fallback without real hardware.
            Assert.Throws<TpmException>(() => new TpmBasedSecretStore(device.Directory, () => device));
            Assert.Contains(TpmCc.CreatePrimary, device.Commands);
            Assert.All(device.ReadPublicHandles, handle => Assert.Equal(0x81015646u, handle));
            Assert.DoesNotContain(TpmCc.Load, device.Commands);
            Assert.Empty(device.Flushed);
        });
    }

    [Fact]
    public void FailedMasterLoad_DoesNotFlushPersistentPrimary()
    {
        using var master = TpmMasterKey.Generate();
        var pub = Marshaller.FromTpmRepresentation<TpmPublic>(master.PublicArea);
        WithStore(pub, pub.GetName(), device =>
        {
            device.FailLoad = true;
            Assert.Throws<TpmException>(() => new TpmBasedSecretStore(device.Directory, () => device));
            Assert.Empty(device.Flushed);
            Assert.DoesNotContain(TpmCc.CreatePrimary, device.Commands);
        });
    }

    private static void WithStore(TpmPublic? cached, byte[] expectedName, Action<CacheDevice> test)
    {
        var directory = Path.Combine(Path.GetTempPath(), "vfido-cache-test-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        try
        {
            using var master = TpmMasterKey.Generate();
            File.WriteAllBytes(Path.Combine(directory, "master.json"), JsonSerializer.SerializeToUtf8Bytes(new
            {
                Version = 1, PrimaryName = expectedName, Public = master.PublicArea, Private = new byte[] { 1 }
            }));
            test(new CacheDevice(directory, cached));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    // Minimal wire-level TPM: exercises actual TSS command serialization and store handle ownership.
    private sealed class CacheDevice(string directory, TpmPublic? cached) : Tpm2Device
    {
        public string Directory { get; } = directory;
        public List<TpmCc> Commands { get; } = new();
        public List<uint> Flushed { get; } = new();
        public List<uint> ReadPublicHandles { get; } = new();
        public bool FailLoad { get; set; }
        public uint PublicHandle { get; set; } = 0x81015646;
        public byte[]? MasterAuthorization { get; private set; }
        public bool AllowEviction { get; set; }
        public uint[]? EvictionHandles { get; private set; }
        public override void Connect() { NeedsHMAC = false; }
        public override void Close() { }

        public override void DispatchCommand(CommandModifier modifier, byte[] command, out byte[] response)
        {
            var code = (TpmCc)BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(6));
            Commands.Add(code);
            if (code == TpmCc.ReadPublic)
                ReadPublicHandles.Add(BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(10)));
            if (code == TpmCc.Import)
            {
                var size = BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(25));
                MasterAuthorization = command.AsSpan(27, size).ToArray();
            }
            using var body = new MemoryStream();
            if (code == TpmCc.ReadPublic && cached != null &&
                BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(10)) == PublicHandle)
            {
                WriteSized(body, cached.GetTpmRepresentation());
                WriteSized(body, cached.GetName());
                WriteSized(body, cached.GetName());
            }
            else if (code == TpmCc.Load && !FailLoad)
            {
                Write32(body, 0x80000001);
                Write32(body, (uint)(2 + cached!.GetName().Length));
                WriteSized(body, cached.GetName());
                body.Write(new byte[5]); // Empty response nonce, attributes, and HMAC.
            }
            else if (code == TpmCc.EvictControl && AllowEviction)
            {
                var authSize = BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(18));
                EvictionHandles = new[]
                {
                    BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(14)),
                    BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(22 + (int)authSize))
                };
                Write32(body, 0); // No response parameters.
                body.Write(new byte[5]);
            }
            else if (code == TpmCc.FlushContext)
            {
                Flushed.Add(BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(10)));
            }
            else
            {
                response = Convert.FromHexString("80010000000A00000101"); // TPM_RC_FAILURE
                return;
            }
            using var packet = new MemoryStream();
            packet.Write(code is TpmCc.Load or TpmCc.EvictControl ? new byte[] { 0x80, 0x02 } : new byte[] { 0x80, 0x01 });
            Write32(packet, (uint)(10 + body.Length));
            Write32(packet, 0);
            body.WriteTo(packet);
            response = packet.ToArray();
        }

        private static void Write32(Stream stream, uint value)
        {
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            stream.Write(bytes);
        }

        private static void WriteSized(Stream stream, byte[] value)
        {
            Span<byte> size = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(size, (ushort)value.Length);
            stream.Write(size);
            stream.Write(value);
        }
    }
}
