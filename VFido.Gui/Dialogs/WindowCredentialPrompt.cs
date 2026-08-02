using Avalonia.Controls.ApplicationLifetimes;
using VFido.Gui.Services;

namespace VFido.Gui.Dialogs;

/// <summary>Shows PasswordPromptWindow owned by the app's current main window.</summary>
public sealed class WindowCredentialPrompt : ICredentialPrompt
{
    public Task<(string Username, string Password)?> RequestCredentialsAsync(string stickName, string? prefilledUsername)
    {
        var owner = (Avalonia.Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
        return owner == null
            ? Task.FromResult<(string, string)?>(null)
            : PasswordPromptWindow.ShowAsync(owner, stickName, prefilledUsername);
    }
}
