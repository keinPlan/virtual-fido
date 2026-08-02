namespace VFido.Gui.Services;

public enum StickAttachOutcome
{
    Success,
    UnsupportedPlatform,
    Failed,
}

public sealed record StickAttachResult(StickAttachOutcome Outcome, string Busid, string? Error)
{
    public bool Success => Outcome == StickAttachOutcome.Success;
}

/// <summary>
/// Owns the lifetime of the USB/IP server and the virtual FIDO sticks attached to it -
/// starting the server, spinning up the configured sticks, and attaching them (or a
/// manually requested busid) to the local VHCI.
/// </summary>
public interface IStickManager
{
    Task<IReadOnlyList<StickAttachResult>> StartAsync();

    Task<StickAttachResult> AttachAsync(string busid);
}
