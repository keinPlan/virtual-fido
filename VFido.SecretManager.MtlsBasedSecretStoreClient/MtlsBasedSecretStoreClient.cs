using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using VFido.SecretManager;

namespace VFido.SecretManager.MtlsBasedSecretStoreClient
{
    /// <summary>
    /// <see cref="IFido2SecretManager"/> implementation that forwards every call to a
    /// server-hosted secret manager over mutual TLS: the server's certificate must chain to the
    /// configured CA, and this client presents its own CA-issued leaf certificate in turn. Once
    /// the channel is established, a username/password login exchanges a bearer token that is
    /// attached to every subsequent request and transparently renewed on expiry or a 401.
    /// </summary>
    public sealed class MtlsBasedSecretStoreClient : IFido2SecretManager, IDisposable
    {
        private readonly HttpClient _http;
        private readonly MtlsBasedSecretStoreClientOptions _options;
        private readonly SemaphoreSlim _loginLock = new(1, 1);

        private string? _token;
        private DateTimeOffset _tokenExpiresAt = DateTimeOffset.MinValue;

        public MtlsBasedSecretStoreClient(MtlsBasedSecretStoreClientOptions options)
        {
            _options = options;

            var handler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                ServerCertificateCustomValidationCallback = ValidateServerCertificate,
            };
            handler.ClientCertificates.Add(options.ClientCertificate);

            _http = new HttpClient(handler) { BaseAddress = options.ServerBaseAddress };
        }

        private bool ValidateServerCertificate(HttpRequestMessage request, X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            if (certificate is null || chain is null)
                return false;

            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Clear();
            chain.ChainPolicy.CustomTrustStore.Add(_options.ServerCaCertificate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            return chain.Build(certificate);
        }

        public async Task<CredentialRegistration> CreateCredentialAsync(string rpId, byte[] userId, string userName, string userDisplayName, bool isResident)
        {
            var request = new CreateCredentialRequest(rpId, userId, userName, userDisplayName, isResident);
            return await PostAsync<CreateCredentialRequest, CredentialRegistration>(SecretManagerRoutes.CreateCredential, request).ConfigureAwait(false);
        }

        public async Task<bool> CredentialExistsAsync(byte[] credentialId, string rpId)
        {
            var request = new CredentialExistsRequest(credentialId, rpId);
            var response = await PostAsync<CredentialExistsRequest, CredentialExistsResponse>(SecretManagerRoutes.CredentialExists, request).ConfigureAwait(false);
            return response.Exists;
        }

        public async Task<CredentialInfo?> FindCredentialAsync(byte[] credentialId, string rpId)
        {
            var request = new FindCredentialRequest(credentialId, rpId);
            var response = await PostAsync<FindCredentialRequest, FindCredentialResponse>(SecretManagerRoutes.FindCredential, request).ConfigureAwait(false);
            return response.Credential;
        }

        public async Task<IReadOnlyList<CredentialInfo>> FindResidentCredentialsAsync(string rpId)
        {
            var request = new FindResidentCredentialsRequest(rpId);
            var response = await PostAsync<FindResidentCredentialsRequest, FindResidentCredentialsResponse>(SecretManagerRoutes.FindResidentCredentials, request).ConfigureAwait(false);
            return response.Credentials;
        }

        public async Task<uint> IncrementSignCountAsync(byte[] credentialId)
        {
            var request = new IncrementSignCountRequest(credentialId);
            var response = await PostAsync<IncrementSignCountRequest, IncrementSignCountResponse>(SecretManagerRoutes.IncrementSignCount, request).ConfigureAwait(false);
            return response.SignCount;
        }

        public async Task<byte[]> SignAsync(byte[] credentialId, byte[] data)
        {
            var request = new SignRequest(credentialId, data);
            var response = await PostAsync<SignRequest, SignResponse>(SecretManagerRoutes.Sign, request).ConfigureAwait(false);
            return response.Signature;
        }

        private async Task<TResponse> PostAsync<TRequest, TResponse>(string route, TRequest body)
        {
            await EnsureLoggedInAsync().ConfigureAwait(false);

            var response = await SendAsync(route, body).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // Token may have expired server-side ahead of our local clock; force one re-login and retry.
                await LoginAsync().ConfigureAwait(false);
                response = await SendAsync(route, body).ConfigureAwait(false);
            }

            response.EnsureSuccessStatusCode();
            return (await response.Content.ReadFromJsonAsync<TResponse>().ConfigureAwait(false))!;
        }

        private async Task<HttpResponseMessage> SendAsync<TRequest>(string route, TRequest body)
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, route)
            {
                Content = JsonContent.Create(body),
            };
            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            return await _http.SendAsync(message).ConfigureAwait(false);
        }

        private async Task EnsureLoggedInAsync()
        {
            if (_token is not null && DateTimeOffset.UtcNow < _tokenExpiresAt)
                return;

            await LoginAsync().ConfigureAwait(false);
        }

        private async Task LoginAsync()
        {
            await _loginLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_token is not null && DateTimeOffset.UtcNow < _tokenExpiresAt)
                    return;

                var request = new LoginRequest(_options.Username, _options.Password);
                using var response = await _http.PostAsJsonAsync(SecretManagerRoutes.Login, request).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                var login = (await response.Content.ReadFromJsonAsync<LoginResponse>().ConfigureAwait(false))!;
                _token = login.Token;
                _tokenExpiresAt = login.ExpiresAt;
            }
            finally
            {
                _loginLock.Release();
            }
        }

        public void Dispose()
        {
            _http.Dispose();
            _loginLock.Dispose();
        }
    }
}
