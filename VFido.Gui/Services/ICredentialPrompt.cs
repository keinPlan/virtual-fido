namespace VFido.Gui.Services;

/// <summary>
/// Asks the user for a username/password at connect time, for secret-manager backends that need
/// one but never have it persisted to config.json. Kept as an abstraction so StickManager doesn't
/// depend on Avalonia dialogs directly.
/// </summary>
public interface ICredentialPrompt
{
    /// <summary>
    /// Returns null if the user cancelled. When <paramref name="requireUsername"/> is false (e.g. mTLS,
    /// where identity comes from the client certificate's CN) no username is collected and the returned
    /// Username is empty.
    /// </summary>
    Task<(string Username, string Password)?> RequestCredentialsAsync(string stickName, bool requireUsername, string? prefilledUsername);
}
