namespace VFido.SecretManager
{
    /// <summary>Password presented once the mTLS channel is established; the username is taken from the client certificate's CN.</summary>
    public sealed record LoginRequest(string Password);

    /// <summary>Opaque bearer token the client attaches to every subsequent call, plus its expiry.</summary>
    public sealed record LoginResponse(string Token, DateTimeOffset ExpiresAt);
}
