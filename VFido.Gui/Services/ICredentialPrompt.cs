namespace VFido.Gui.Services;

/// <summary>
/// Asks the user for a username/password at connect time, for secret-manager backends that need
/// one but never have it persisted to config.json. Kept as an abstraction so StickManager doesn't
/// depend on Avalonia dialogs directly.
/// </summary>
public interface ICredentialPrompt
{
    /// <summary>Returns null if the user cancelled.</summary>
    Task<(string Username, string Password)?> RequestCredentialsAsync(string stickName, string? prefilledUsername);
}
