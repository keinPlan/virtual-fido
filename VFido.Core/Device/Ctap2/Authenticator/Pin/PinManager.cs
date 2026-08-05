using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VFido.Core.Device.Ctap2.Errors;
using VFido.SecretManager;

namespace VFido.Core.Device.Ctap2.Authenticator.Pin
{
    /// <summary>
    /// PIN/UV Auth Protocol One state for one authenticator instance: the ephemeral key-agreement
    /// keypair, the stored PIN hash, retry counter, and the current pinUvAuthToken. The key-agreement
    /// keypair and token are always session-only (CTAP2 expects a fresh handshake each time anyway);
    /// the PIN hash and retry counter are persisted through the secret manager (see
    /// <see cref="IFido2SecretManager.LoadPinStateAsync"/>/<see cref="IFido2SecretManager.SavePinStateAsync"/>),
    /// so a stick backed by a durable one (e.g. file-based or the mTLS server) remembers its PIN
    /// across reconnects/restarts instead of resetting every time like a purely in-memory stick does.
    /// </summary>
    internal class PinManager
    {
        private const int MaxRetries = 8;

        private readonly IFido2SecretManager? _secrets;

        private ECDiffieHellman? _keyAgreementKey;
        private byte[]? _pinHash; // left 16 bytes of SHA-256(pin)
        private byte[]? _pinToken;
        private int _retries = MaxRetries;

        private PinManager(IFido2SecretManager? secrets, PinState? saved)
        {
            _secrets = secrets;

            if (saved is { } state)
            {
                _pinHash = state.PinHash;
                _retries = state.Retries;
            }
        }

        /// <summary>
        /// Loading PIN state may involve a network round trip (the mTLS secret manager), so this must
        /// complete before the authenticator processes its first CTAP2 command - authenticatorGetInfo
        /// reports <see cref="IsPinSet"/> synchronously and can't tolerate it lagging behind.
        /// </summary>
        internal static async Task<PinManager> CreateAsync(IFido2SecretManager? secrets)
        {
            var saved = secrets != null ? await secrets.LoadPinStateAsync().ConfigureAwait(false) : null;
            return new PinManager(secrets, saved);
        }

        internal bool IsPinSet => _pinHash != null;
        internal int Retries => _retries;

        internal ECParameters GetOrCreateKeyAgreementPublicKey()
        {
            // Reuse the same keypair across repeated getKeyAgreement calls within one ceremony -
            // CTAP2 only expects it to rotate after a failed PIN attempt (see VerifyPinHash below).
            // Regenerating here unconditionally would silently invalidate the ECDH shared secret
            // the platform already derived if it calls getKeyAgreement more than once before
            // sending setPIN/changePIN/getPinToken.
            _keyAgreementKey ??= ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            return _keyAgreementKey.ExportParameters(includePrivateParameters: false);
        }

        internal async Task SetPinAsync(ECParameters platformPublicKey, byte[] pinUvAuthParam, byte[] newPinEnc)
        {
            if (IsPinSet)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinAuthInvalid); // use changePIN instead

            var sharedSecret = DeriveSharedSecret(platformPublicKey);
            VerifyAuthParam(sharedSecret, newPinEnc, pinUvAuthParam);

            _pinHash = ComputePinHash(DecodePin(sharedSecret, newPinEnc));
            _retries = MaxRetries;
            await PersistAsync().ConfigureAwait(false);
        }

        internal async Task ChangePinAsync(ECParameters platformPublicKey, byte[] pinUvAuthParam, byte[] newPinEnc, byte[] pinHashEnc)
        {
            EnsurePinSetAndUnlocked();

            var sharedSecret = DeriveSharedSecret(platformPublicKey);
            VerifyAuthParam(sharedSecret, Combine(newPinEnc, pinHashEnc), pinUvAuthParam);
            await VerifyPinHashAsync(sharedSecret, pinHashEnc).ConfigureAwait(false);

            _pinHash = ComputePinHash(DecodePin(sharedSecret, newPinEnc));
            _retries = MaxRetries;
            await PersistAsync().ConfigureAwait(false);
        }

        internal async Task<byte[]> GetPinTokenAsync(ECParameters platformPublicKey, byte[] pinHashEnc)
        {
            EnsurePinSetAndUnlocked();

            var sharedSecret = DeriveSharedSecret(platformPublicKey);
            await VerifyPinHashAsync(sharedSecret, pinHashEnc).ConfigureAwait(false);

            _retries = MaxRetries;
            await PersistAsync().ConfigureAwait(false);
            _pinToken = RandomNumberGenerator.GetBytes(32);
            return PinProtocolOne.Encrypt(sharedSecret, _pinToken);
        }

        /// <summary>True if no PIN is configured (nothing to verify) or <paramref name="pinUvAuthParam"/> matches the current token.</summary>
        internal bool VerifyPinUvAuthParam(byte[]? pinUvAuthParam, byte[] message)
        {
            if (!IsPinSet)
                return true;

            if (_pinToken == null || pinUvAuthParam == null)
                return false;

            var expected = PinProtocolOne.Authenticate(_pinToken, message);
            return CryptographicOperations.FixedTimeEquals(expected, pinUvAuthParam);
        }

        private byte[] DeriveSharedSecret(ECParameters platformPublicKey)
        {
            if (_keyAgreementKey == null)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrMissingParameter);

            return PinProtocolOne.DeriveSharedSecret(_keyAgreementKey, platformPublicKey);
        }

        private static void VerifyAuthParam(byte[] sharedSecret, byte[] message, byte[] pinUvAuthParam)
        {
            var expected = PinProtocolOne.Authenticate(sharedSecret, message);
            if (!CryptographicOperations.FixedTimeEquals(expected, pinUvAuthParam))
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinAuthInvalid);
        }

        private async Task VerifyPinHashAsync(byte[] sharedSecret, byte[] pinHashEnc)
        {
            var providedHash = PinProtocolOne.Decrypt(sharedSecret, pinHashEnc);
            if (CryptographicOperations.FixedTimeEquals(providedHash, _pinHash!))
                return;

            _retries--;
            // Persisted immediately - a restart must not silently reset a locked-out PIN's retries.
            await PersistAsync().ConfigureAwait(false);
            // Force a fresh getKeyAgreement handshake before the next attempt, as CTAP2 requires.
            _keyAgreementKey?.Dispose();
            _keyAgreementKey = null;
            throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinInvalid);
        }

        private async Task PersistAsync()
        {
            if (_secrets != null)
                await _secrets.SavePinStateAsync(new PinState(_pinHash!, _retries)).ConfigureAwait(false);
        }

        private void EnsurePinSetAndUnlocked()
        {
            if (!IsPinSet)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinNotSet);
            if (_retries <= 0)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinBlocked);
        }

        private static byte[] ComputePinHash(byte[] pinUtf8) => SHA256.HashData(pinUtf8).AsSpan(0, 16).ToArray();

        private static byte[] DecodePin(byte[] sharedSecret, byte[] newPinEnc)
        {
            var padded = PinProtocolOne.Decrypt(sharedSecret, newPinEnc);
            var length = Array.IndexOf(padded, (byte)0);
            if (length < 0)
                length = padded.Length;

            if (length is < 4 or > 63)
                throw new Ctap2Exception(Ctap2Constants.Ctap2ErrPinPolicyViolation);

            return padded[..length];
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
