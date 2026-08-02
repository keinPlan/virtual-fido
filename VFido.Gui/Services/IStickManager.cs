using VFido.Gui.Configuration;

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
/// disconnects sticks individually by id.
/// </summary>
public interface IStickManager
{
    IReadOnlyList<StickConfig> GetConfiguredSticks();

    bool IsConnected(Guid stickId);

    Task<StickAttachResult> ConnectAsync(Guid stickId);

    Task<StickAttachResult> DisconnectAsync(Guid stickId);
}
