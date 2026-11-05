using System.IO.Compression;
using VFido.Gui.Configuration;
using VFido.Gui.Services;

namespace VirtualFido.Tests;

public sealed class TpmBackupTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "vfido-backup-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }

    [Fact]
    public void ZipExcludesLocalMasterAndPreservesRecoveryFiles()
    {
        var configs = new StickConfigStore(Path.Combine(_root, "source"));
        var config = configs.Create("TPM", "serial", new TpmSecretManagerConfig { Username = "alice", MasterName = "master" });
        var files = new[] { "salt.bin", "verifier.bin", "keys/master.json", "keys/credential.tpmkey", "keys/attestation.json", "credentials/account.bin", "pin.bin" };
        foreach (var file in files)
        {
            var path = Path.Combine(configs.GetStickDirectory(config.Name), file);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, new byte[] { 0, 1, 2, 255 });
        }
        File.WriteAllText(Path.Combine(_root, "recovery.pfx"), "not part of stick");
        using var zip = new MemoryStream(TpmStickProvisioning.ExportBackup(configs, config));
        using var archive = new ZipArchive(zip);
        Assert.Equal(files.Length + 1, archive.Entries.Count);
        Assert.Null(archive.GetEntry("TPM/keys/master.json"));
        Assert.NotNull(archive.GetEntry("RESTORE.txt"));
        var restored = Path.Combine(_root, "restored");
        archive.ExtractToDirectory(restored);
        Assert.Equal("TPM", Assert.Single(new StickConfigStore(restored).LoadAll()).Name);
        foreach (var file in files.Where(file => file != "keys/master.json"))
            Assert.Equal(File.ReadAllBytes(Path.Combine(configs.GetStickDirectory(config.Name), file)),
                File.ReadAllBytes(Path.Combine(restored, config.Name, file)));
    }

    [Fact]
    public void IncompleteStickIsRejected()
    {
        var configs = new StickConfigStore(_root);
        var config = configs.Create("TPM", "serial", new TpmSecretManagerConfig { Username = "alice", MasterName = "master" });
        Assert.Throws<InvalidDataException>(() => TpmStickProvisioning.ExportBackup(configs, config));
    }
}
