using System;
using System.Formats.Cbor;
using System.Linq;
using NLog;
using VFido.Core.Device.Ctap2.Authenticator.Pin;
using VFido.Core.Device.Ctap2.Errors;
using VFido.Core.Device.Ctap2.Model;
using VFido.SecretManager;

namespace VFido.Core.Device.Ctap2.Authenticator
{
    internal class Fido2Authenticator : IAuthenticator
    {
        private const int AlgEs256 = -7;

        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly IFido2SecretManager _secrets;
        private readonly IUserPresenceGate _presence;
        private readonly PinManager _pin;
        private readonly byte[] _aaguid;

        // authenticatorGetNextAssertion session state: the remaining discoverable credentials
        // (beyond the one already returned by GetAssertion) for the most recent RP/request.
        private IReadOnlyList<CredentialInfo>? _pendingAssertions;
        private int _pendingAssertionIndex;
        private string? _pendingRpId;
        private byte[]? _pendingClientDataHash;
        private bool _pendingUserVerified;

        internal Fido2Authenticator(IFido2SecretManager secrets, byte[] aaguid, IUserPresenceGate? presence = null, IPinStateStore? pinStateStore = null)
        {
            _secrets = secrets;
            _pin = new PinManager(pinStateStore);
            _aaguid = aaguid;
            _presence = presence ?? AlwaysApproveUserPresenceGate.Instance;
        }

        public bool IsPinSet => _pin.IsPinSet;
        public byte[] Aaguid => _aaguid;

        public async Task<MakeCredentialResult> MakeCredentialAsync(MakeCredentialRequest request)
        {
            if (!request.PubKeyCredParams.Any(p => p.Algorithm == AlgEs256))
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrUnsupportedAlgorithm);

            if (request.ExcludeList != null)
            {
                foreach (var excludedId in request.ExcludeList)
                {
                    if (await _secrets.CredentialExistsAsync(excludedId, request.RelyingParty.Id))
                        throw new Ctap2Exception(Ctap2Constants.Ctap2ErrCredentialExcluded);
                }
            }

            // credProtect level 3 (userVerificationRequired) mandates UV at creation time too, not
            // just for later assertions.
            var credProtect = request.CredProtect is >= 1 and <= 3 ? request.CredProtect.Value : 1;
            var userVerified = RequireUserVerification(request.RequireUserVerification, request.PinUvAuthParam, request.ClientDataHash, forceUv: credProtect == 3);

            if (!_presence.RequestApproval($"Register a new key for {request.RelyingParty.Id}", request.RelyingParty.Id))
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrOperationDenied);

            var registration = await _secrets.CreateCredentialAsync(
                request.RelyingParty.Id, request.User.Id, request.User.Name, request.User.DisplayName, request.RequireResidentKey, credProtect);

            // Only echo the extension back if the platform actually requested it.
            var extensions = request.CredProtect != null ? EncodeCredProtectExtension(credProtect) : null;
            var authenticatorData = AuthenticatorDataBuilder.BuildWithAttestedCredential(
                request.RelyingParty.Id, _aaguid, registration.CredentialId, registration.CosePublicKey, signCount: 0, userVerified, extensions);

            // Batch attestation: sign with this stick's self-signed attestation key (shared across
            // all its credentials) rather than the credential's own key, so the response's attStmt
            // carries a verifiable x5c chain (leaf + issuing CA) instead of falling back to
            // self-attestation.
            var attestationCertificateChain = await _secrets.GetAttestationCertificateChainAsync();
            var signature = await _secrets.SignWithAttestationKeyAsync(Combine(authenticatorData, request.ClientDataHash));

            return new MakeCredentialResult(authenticatorData, registration.CoseAlgorithm, signature, attestationCertificateChain);
        }

        public async Task<GetAssertionResult> GetAssertionAsync(GetAssertionRequest request)
        {
            CredentialInfo? credential = null;
            var foundViaAllowList = false;
            foreach (var credentialId in request.AllowList)
            {
                var candidate = await _secrets.FindCredentialAsync(credentialId, request.RpId);
                if (candidate != null)
                {
                    credential = candidate;
                    foundViaAllowList = true;
                    break;
                }
            }

            _pendingAssertions = null;
            int? numberOfCredentials = null;

            // Empty allowList: fall back to discoverable (resident) credentials for the RP so
            // passwordless/usernameless login flows work; non-resident credentials are only
            // reachable via an explicit allowList entry above. When more than one account is
            // discoverable, the rest are kept for authenticatorGetNextAssertion to enumerate.
            IReadOnlyList<CredentialInfo>? resident = null;
            if (credential == null && request.AllowList.Count == 0)
            {
                resident = await _secrets.FindResidentCredentialsAsync(request.RpId);
                if (resident.Count > 0)
                    credential = resident[0];
            }

            if (credential == null)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrNoCredentials);

            // credProtect (CTAP2 §11.3): level 3 always requires UV; level 2 only requires it when
            // the credential was discovered via an empty allowList rather than explicitly named by
            // the platform.
            var forceUv = credential.CredProtect switch
            {
                3 => true,
                2 => !foundViaAllowList,
                _ => false,
            };
            var userVerified = RequireUserVerification(request.RequireUserVerification, request.PinUvAuthParam, request.ClientDataHash, forceUv);

            if (resident is { Count: > 1 })
            {
                _pendingAssertions = resident;
                _pendingAssertionIndex = 1;
                _pendingRpId = request.RpId;
                _pendingClientDataHash = request.ClientDataHash;
                _pendingUserVerified = userVerified;
                numberOfCredentials = resident.Count;
            }

            // up=false is a silent credential probe (e.g. WebAuthn conditional mediation/autofill
            // discovery): the platform just wants to know whether a matching credential exists, and
            // must not see any prompt for it. Only gate on user presence for a real (up=true) request.
            if (request.RequireUserPresence && !_presence.RequestApproval($"Sign in to {request.RpId}", request.RpId))
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrOperationDenied);

            // numberOfCredentials is only reported in this first response (per CTAP2 6.2), but
            // whether to disclose name/displayName must stay true for every subsequent
            // authenticatorGetNextAssertion call too, since the platform still needs to
            // distinguish between the multiple discoverable accounts it's enumerating.
            return await BuildAssertionResult(credential, request.RpId, request.ClientDataHash, userVerified, numberOfCredentials, includeUserDetails: numberOfCredentials > 1);
        }

        public async Task<GetAssertionResult> GetNextAssertionAsync()
        {
            if (_pendingAssertions == null || _pendingAssertionIndex >= _pendingAssertions.Count)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrNotAllowed);

            var credential = _pendingAssertions[_pendingAssertionIndex++];
            var result = await BuildAssertionResult(credential, _pendingRpId!, _pendingClientDataHash!, _pendingUserVerified, null, includeUserDetails: true);

            if (_pendingAssertionIndex >= _pendingAssertions.Count)
                _pendingAssertions = null;

            return result;
        }

        private async Task<GetAssertionResult> BuildAssertionResult(CredentialInfo credential, string rpId, byte[] clientDataHash, bool userVerified, int? numberOfCredentials, bool includeUserDetails)
        {
            var signCount = await _secrets.IncrementSignCountAsync(credential.CredentialId);
            var authenticatorData = AuthenticatorDataBuilder.BuildWithoutAttestedCredential(rpId, signCount, userVerified);

            var signature = await _secrets.SignAsync(credential.CredentialId, Combine(authenticatorData, clientDataHash));

            var user = credential.IsResident
                ? new UserEntity(credential.UserId, credential.UserName, credential.UserDisplayName)
                : null;

            return new GetAssertionResult(credential.CredentialId, authenticatorData, signature, user, numberOfCredentials, includeUserDetails);
        }

        public Task<ClientPinResult> ClientPinAsync(ClientPinRequest request) => Task.FromResult(request.SubCommand switch
        {
            1 => new ClientPinResult(PinRetries: _pin.Retries), // getPinRetries
            2 => new ClientPinResult(KeyAgreementPublicKey: _pin.GetOrCreateKeyAgreementPublicKey()), // getKeyAgreement
            3 => HandleSetPin(request),
            4 => HandleChangePin(request),
            5 => HandleGetPinToken(request),
            _ => throw new Ctap2Exception(Ctap2Constants.Ctap1ErrInvalidCommand),
        });

        /// <summary>
        /// Once a PIN is set, every MakeCredential/GetAssertion must prove UV via a valid
        /// pinUvAuthParam over the request's clientDataHash. If no PIN is set yet but UV is
        /// required, the platform must run the ClientPIN setPIN ceremony first rather than
        /// silently proceeding without it. Returns whether UV was asserted, so callers can set
        /// the authData UV flag accordingly.
        /// </summary>
        /// <param name="forceUv">
        /// A hard per-credential requirement (credProtect level 3, or level 2 discovered via an
        /// empty allowList) that must be honored even if the platform's own request didn't ask for
        /// UV - this comes from the relying party and this stick has no discretion to ignore it.
        /// </param>
        private bool RequireUserVerification(bool uvRequested, byte[]? pinUvAuthParam, byte[] clientDataHash, bool forceUv = false)
        {
            uvRequested = uvRequested || forceUv;

            Logger.Debug(() => $"UV negotiation: uvRequested={uvRequested} forceUv={forceUv} pinIsSet={_pin.IsPinSet} pinUvAuthParamPresent={pinUvAuthParam != null} pinUvAuthParamLen={pinUvAuthParam?.Length ?? -1}");

            // CTAP2 6.1/6.2: a zero-length pinUvAuthParam is the platform probing whether it
            // needs to run ClientPIN before it can satisfy UV here, without committing to it.
            // The reply tells it whether to offer setPIN (not set) or ask for the PIN (already set).
            if (pinUvAuthParam is { Length: 0 })
            {
                Logger.Debug(() => "Zero-length pinUvAuthParam probe - signalling PIN state so platform can decide whether to run ClientPIN");
                throw new Ctap2Exception(_pin.IsPinSet ? Ctap2Constants.Ctap2ErrPinInvalid : Ctap2Constants.Ctap2ErrPinNotSet);
            }

            if (!_pin.IsPinSet)
            {
                if (uvRequested)
                {
                    Logger.Debug(() => "UV requested but no PIN set - rejecting with PIN_REQUIRED to force setPIN ceremony");
                    throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinRequired);
                }

                Logger.Debug(() => "UV not requested and no PIN set - proceeding without UV");
                return false;
            }

            if (pinUvAuthParam == null)
            {
                if (uvRequested)
                {
                    Logger.Debug(() => "PIN is set, UV requested, but request carries no pinUvAuthParam - rejecting with PIN_REQUIRED");
                    throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinRequired);
                }

                Logger.Debug(() => "PIN is set but UV not requested and no pinUvAuthParam supplied - proceeding without UV");
                return false;
            }

            if (!_pin.VerifyPinUvAuthParam(pinUvAuthParam, clientDataHash))
            {
                Logger.Debug(() => "pinUvAuthParam failed verification - rejecting with PIN_AUTH_INVALID");
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinAuthInvalid);
            }

            Logger.Debug(() => "UV asserted via valid pinUvAuthParam");
            return true;
        }

        private ClientPinResult HandleSetPin(ClientPinRequest request)
        {
            if (request.KeyAgreement is not { } keyAgreement || request.PinUvAuthParam is not { } pinUvAuthParam || request.NewPinEnc is not { } newPinEnc)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            _pin.SetPin(keyAgreement, pinUvAuthParam, newPinEnc);
            return new ClientPinResult();
        }

        private ClientPinResult HandleChangePin(ClientPinRequest request)
        {
            if (request.KeyAgreement is not { } keyAgreement || request.PinUvAuthParam is not { } pinUvAuthParam
                || request.NewPinEnc is not { } newPinEnc || request.PinHashEnc is not { } pinHashEnc)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            _pin.ChangePin(keyAgreement, pinUvAuthParam, newPinEnc, pinHashEnc);
            return new ClientPinResult();
        }

        private ClientPinResult HandleGetPinToken(ClientPinRequest request)
        {
            if (request.KeyAgreement is not { } keyAgreement || request.PinHashEnc is not { } pinHashEnc)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            var pinUvAuthTokenEnc = _pin.GetPinToken(keyAgreement, pinHashEnc);
            return new ClientPinResult(PinUvAuthTokenEnc: pinUvAuthTokenEnc);
        }

        private static byte[] EncodeCredProtectExtension(int credProtect)
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
            writer.WriteStartMap(1);
            writer.WriteTextString("credProtect");
            writer.WriteInt32(credProtect);
            writer.WriteEndMap();
            return writer.Encode();
        }

        private static byte[] Combine(byte[] first, byte[] second)
        {
            var result = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
            return result;
        }
    }
}
