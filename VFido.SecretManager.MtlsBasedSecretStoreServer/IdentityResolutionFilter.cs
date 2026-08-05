using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Logging;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>
    /// Gates every non-login endpoint and resolves which user's <see cref="IFido2SecretManager"/>
    /// the request is for. The client certificate itself is already enforced at the Kestrel/TLS layer
    /// before a request ever reaches here; this filter reads its <c>CN</c> (the username it was
    /// issued for) and then branches on whether that identity requires a password:
    /// <list type="bullet">
    /// <item>Password-required users must also present a valid <c>Authorization: Bearer</c> session
    /// token from <see cref="SessionTokenService.IssueToken"/> (the second factor, authenticating the
    /// human) - the manager is fetched from <see cref="UserSessionCache"/> by that token.</item>
    /// <item>Passwordless users skip the bearer check entirely - the mTLS certificate alone is
    /// sufficient, and the manager is fetched/built by username directly.</item>
    /// </list>
    /// Either way, the resolved manager is stashed in <c>HttpContext.Items</c> for the route handlers.
    /// </summary>
    public sealed class IdentityResolutionFilter : IEndpointFilter
    {
        public const string ManagerItemKey = "Fido2SecretManager";

        private const string BearerPrefix = "Bearer ";

        private readonly SessionTokenService _sessions;
        private readonly UserSessionCache _cache;
        private readonly UserDirectoryResolver _users;
        private readonly ILogger<IdentityResolutionFilter> _logger;

        public IdentityResolutionFilter(SessionTokenService sessions, UserSessionCache cache, UserDirectoryResolver users, ILogger<IdentityResolutionFilter> logger)
        {
            _sessions = sessions;
            _cache = cache;
            _users = users;
            _logger = logger;
        }

        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            var username = context.HttpContext.Connection.ClientCertificate?.GetNameInfo(X509NameType.SimpleName, false);
            if (string.IsNullOrEmpty(username))
            {
                _logger.LogWarning("Request to {Path} rejected: no client certificate CN present.", context.HttpContext.Request.Path);
                return Results.Unauthorized();
            }

            if (!_users.UserExists(username))
            {
                _logger.LogWarning("Request to {Path} rejected: certificate CN {Username} has no matching user directory.", context.HttpContext.Request.Path, username);
                return Results.Unauthorized();
            }

            IFido2SecretManager manager;
            if (_users.RequiresPassword(username))
            {
                var token = ExtractToken(context.HttpContext.Request.Headers.Authorization);
                if (token is null || !_sessions.TryValidate(token, out var sessionUsername) || sessionUsername != username)
                {
                    _logger.LogWarning("Request to {Path} rejected for {Username}: missing, invalid or expired session token.", context.HttpContext.Request.Path, username);
                    return Results.Unauthorized();
                }

                if (!_cache.TryGetForToken(token, out manager!))
                {
                    _logger.LogWarning("Request to {Path} rejected for {Username}: no cached secret manager for session token.", context.HttpContext.Request.Path, username);
                    return Results.Unauthorized();
                }
            }
            else
            {
                manager = _cache.GetOrAddForUsername(username, () => _users.BuildPasswordlessManager(username));
            }

            context.HttpContext.Items[ManagerItemKey] = manager;
            return await next(context).ConfigureAwait(false);
        }

        private static string? ExtractToken(StringValues authorizationHeader)
        {
            var value = authorizationHeader.ToString();
            return value.StartsWith(BearerPrefix, StringComparison.Ordinal) ? value[BearerPrefix.Length..] : null;
        }
    }
}
