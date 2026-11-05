# Server FIDO storage

Set `MtlsBasedSecretStoreServer.StorageProvider` in `appsettings.json` to `File`, `Tpm`, or `Memory`, then restart the server. The default is `File`.

| Provider | Private keys | Credential metadata / PIN state |
| --- | --- | --- |
| File | AES-encrypted files in each user's `keys` directory | Encrypted files |
| Tpm | TPM-wrapped files in each user's `tpm/keys` directory; signing runs in the local TPM | Encrypted metadata in `tpm/credentials`; encrypted PIN state |
| Memory | Process memory | Process memory; lost when the server stops |

All modes retain the existing mTLS and optional login password requirements. Memory mode shares a user's credentials across sessions for the lifetime of the server; certificates, login verifiers, and server PKI still use disk storage.

TPM mode requires a supported local TPM accessible to the server account. It provisions a per-user master on first access and uses a Data Protection wrapped random authorization for unattended access. Keep the PKI/keyring and user directories together. Automatically provisioned masters have no exported recovery PFX: clearing or replacing the TPM makes their credentials unusable. See the TPM provider README for its explicit recovery provisioning API. There is no fallback to software signing when TPM access fails.

Changing the provider does not migrate or delete existing credentials. File and TPM credentials use separate directories; switching back restores access to that provider's data. Memory credentials disappear at shutdown. This setting controls FIDO keys, not TLS/CA certificates or ASP.NET Data Protection keys.

The management dashboard counts credentials for the selected provider.
