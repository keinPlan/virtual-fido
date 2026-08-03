namespace VFido.Gui.Configuration;

/// <summary>
/// Everything persisted for one configured virtual stick, at
/// &lt;exe-dir&gt;/VFido/{Name}/config.json. <see cref="Name"/> is this stick's unique identifier
/// and also names its folder (see <see cref="StickConfigStore.IsValidStickName"/> for the
/// character/length rules that keeps it a safe folder name), so it's fixed at creation time - no
/// separate id, and no rename after the fact. The AAGUID is not stored here either - it's fixed
/// per secret manager backend (see each <c>IKeyStore</c>/<c>IFido2SecretManager</c>
/// implementation's <c>Aaguid</c>), not per stick.
/// </summary>
public sealed class StickConfig
{
    public required string Name { get; set; }
    public required string SerialNumberIdentifier { get; set; }
    public required SecretManagerConfig SecretManager { get; set; }
}
