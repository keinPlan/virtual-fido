using Microsoft.Extensions.Primitives;

namespace VFido.SecretManager.MtlsBasedSecretStoreServer
{
    /// <summary>
    /// Gates every non-login endpoint on a valid session token from <see cref="SessionTokenService.IssueToken"/>.
    /// The client certificate itself is already enforced at the Kestrel/TLS layer before a request
    /// ever reaches here - this filter is the second factor, authenticating the human user.
    /// </summary>
    public sealed class BearerAuthFilter : IEndpointFilter
    {
        private const string BearerPrefix = "Bearer ";

        private readonly SessionTokenService _sessions;

        public BearerAuthFilter(SessionTokenService sessions) => _sessions = sessions;

        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            var token = ExtractToken(context.HttpContext.Request.Headers.Authorization);

            if (!_sessions.TryValidate(token, out _))
                return Results.Unauthorized();

            return await next(context).ConfigureAwait(false);
        }

        private static string? ExtractToken(StringValues authorizationHeader)
        {
            var value = authorizationHeader.ToString();
            return value.StartsWith(BearerPrefix, StringComparison.Ordinal) ? value[BearerPrefix.Length..] : null;
        }
    }
}
