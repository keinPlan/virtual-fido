using System.Runtime.CompilerServices;

// The mTLS server reuses AesKeyProtector/PasswordVerifier as-is (same at-rest encryption and
// wrong-password detection) instead of re-implementing the same security-critical code twice.
[assembly: InternalsVisibleTo("VFido.SecretManager.MtlsBasedSecretStoreServer")]
