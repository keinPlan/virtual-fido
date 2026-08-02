using VFido.Core.Device.Ctap2.Authenticator.Pin;

namespace VFido.Gui.Configuration;

/// <summary>
/// Everything persisted for one configured virtual stick, at
/// &lt;exe-dir&gt;/VFido/{Id}/config.json. <see cref="Id"/> also names the stick's folder, but
/// <see cref="Aaguid"/> is independently editable/rotatable rather than derived from it.
/// </summary>
public sealed class StickConfig
{
    public required Guid Id { get; set; }
    public required string Name { get; set; }
    public required string SerialNumberIdentifier { get; set; }
    public required Guid Aaguid { get; set; }
    public PinUsagePreference PinUsage { get; set; } = PinUsagePreference.Prefer;
    public required SecretManagerConfig SecretManager { get; set; }
}
