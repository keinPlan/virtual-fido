namespace VFido.SecretManager
{
    /// <summary>Username/password credentials presented once the mTLS channel is established.</summary>
    public sealed record LoginRequest(string Username, string Password);

    /// <summary>Opaque bearer token the client attaches to every subsequent call, plus its expiry.</summary>
    public sealed record LoginResponse(string Token, DateTimeOffset ExpiresAt);
}
