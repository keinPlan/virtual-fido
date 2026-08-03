using VFido.Gui.Configuration;
using VFido.SecretManager;

namespace VFido.Gui.Services;

public enum StickAttachOutcome
{
    Success,
    UnsupportedPlatform,
    Failed,
    Cancelled,
}

public sealed record StickAttachResult(StickAttachOutcome Outcome, string Busid, string? Error)
{
    public bool Success => Outcome == StickAttachOutcome.Success;

    /// <summary>VHCI port the device was attached on, set only on a successful ConnectAsync - needed by DisconnectAsync to detach.</summary>
    public int? Port { get; init; }
}

/// <summary>
/// Owns the lifetime of the (single, shared) USB/IP server and the configured virtual FIDO
/// sticks connected to it. Loading a stick's config doesn't attach it - the caller connects and
/// disconnects sticks individually by name (see <see cref="StickConfig.Name"/>, this stick's
/// unique identifier).
/// </summary>
public interface IStickManager
{
    IReadOnlyList<StickConfig> GetConfiguredSticks();

    bool IsConnected(string stickName);

    Task<StickAttachResult> ConnectAsync(string stickName);

    Task<StickAttachResult> DisconnectAsync(string stickName);

    /// <summary>
    /// Metadata-only view of every credential stored on a currently connected stick. Never
    /// exposes key handles or private key material. Throws if the stick isn't connected.
    /// </summary>
    Task<IReadOnlyList<CredentialInfo>> GetCredentialsAsync(string stickName);

    /// <summary>Permanently deletes a stored credential from a currently connected stick.</summary>
    Task DeleteCredentialAsync(string stickName, byte[] credentialId);
}
