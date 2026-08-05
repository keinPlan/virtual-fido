using System.Text.Json.Serialization;

namespace VFido.Gui.Configuration;

/// <summary>
/// Which IFido2SecretManager backend a stick uses, and the (non-secret) settings needed to build
/// it. Login passwords / PFX passwords are deliberately never fields here - they're prompted at
/// connect time via ICredentialPrompt and never written to config.json.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(MemorySecretManagerConfig), "memory")]
[JsonDerivedType(typeof(FileSecretManagerConfig), "file")]
[JsonDerivedType(typeof(MtlsSecretManagerConfig), "mtls")]
public abstract class SecretManagerConfig
{
}

/// <summary>Fully in-memory - no credentials to prompt for, nothing persisted, lost on restart.</summary>
public sealed class MemorySecretManagerConfig : SecretManagerConfig
{
}

/// <summary>
/// Keys/credentials are encrypted to disk under the stick's own folder. The directory is derived
/// at connect time from the stick's config folder (never stored here), so the whole VFido/{Id}/
/// folder stays portable if moved.
/// </summary>
public sealed class FileSecretManagerConfig : SecretManagerConfig
{
    public required string Username { get; set; }
}

/// <summary>
/// Delegates to a server-hosted secret manager over mutual TLS. Certificate paths are resolved
/// relative to the stick's own folder if not rooted, mirroring MtlsBasedSecretStoreServerOptions'
/// path-based cert config.
/// </summary>
public sealed class MtlsSecretManagerConfig : SecretManagerConfig
{
    public required Uri ServerBaseAddress { get; set; }
    public required string ClientCertificatePath { get; set; }
    public string? ClientCertificatePassword { get; set; }
    public required string ServerCaCertificatePath { get; set; }

    /// <summary>
    /// Whether the server-side identity behind this stick needs a login password (mirrors
    /// UserDirectoryResolver.RequiresPassword on the server, established once at Create time).
    /// Defaults to true so configs written before this field existed keep prompting, matching
    /// their previous behavior.
    /// </summary>
    public bool RequiresLoginPassword { get; set; } = true;
}
