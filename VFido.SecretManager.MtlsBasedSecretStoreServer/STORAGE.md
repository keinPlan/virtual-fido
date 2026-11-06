# Server FIDO storage

On a fresh installation, start the server without arguments to open the local first-run setup wizard. It lets you choose the storage provider, server DNS name/IP, HTTPS port, CA passphrase, and first administrator. Download the administrator PFX and root CA, then select **Close setup and start server**. The administrator uses certificate-only authentication; the PFX has the password chosen during setup.

Setup listens on a random port on `127.0.0.1` and prints its private URL if the browser cannot open automatically. Run it on the server machine (or forward that loopback port through SSH). It never listens on the network, and existing or partial PKI/user installations are not overwritten. Repair partial installations with the existing `init` CLI. Configuration is saved to `appsettings.json` next to the server executable, which must be writable during setup. Once configured, subsequent starts go directly to the mTLS server.

Set `MtlsBasedSecretStoreServer.StorageProvider` in `appsettings.json` to `File`, `Tpm`, or `Memory`, then restart the server. The default is `File`.

| Provider | Private keys | Credential metadata / PIN state |
| --- | --- | --- |
| File | AES-encrypted files in each user's `keys` directory | Configurable credential encryption; encrypted PIN state |
| Tpm | TPM-wrapped files in each user's `keys` directory; signing runs in the local TPM | Configurable credential encryption; encrypted PIN state |
| Memory | Process memory | Process memory; lost when the server stops |

All modes retain the existing mTLS and optional login password requirements. Memory mode shares a user's credentials across sessions for the lifetime of the server; certificates, login verifiers, and server PKI still use disk storage.

TPM mode requires a supported local TPM accessible to the server account. During setup, upload an existing `vfido-tpm-recovery.pfx` or leave the upload empty to generate a new password-protected recovery PFX. Enter its recovery password (at least 12 characters). Setup imports that PFX to provision `<PkiRootPath>/tpm/master.json` and opens it immediately to verify TPM access. The PFX contains the portable parent key and wrapping seed; `master.json` is its TPM-bound representation.

The setup administrator and each subsequent `create-user` receive a copy of this master at `<SecretsRootPath>/<username>/keys/master.json`. Wrapped signing keys and attestation live in `keys`, with encrypted metadata in the sibling `credentials` folder. There is no per-user `tpm` folder. The master's common authorization stays once on the server in `<PkiRootPath>/tpm/wrapped.key`; it is not copied to users. A passwordless user's single top-level `wrapped.key` protects their metadata and PIN state; password users derive that encryption key from their login password. First access also copies the template for users that have not yet received it. Existing different user masters or the old nested `tpm` layout are rejected rather than overwritten; they need a separate migration.

After setup, download **vfido-tpm-recovery.pfx** before selecting **Close setup and start server**. The temporary export at `<PkiRootPath>/tpm/vfido-tpm-recovery.pfx` is deleted when the normal server starts, including on subsequent starts. The downloaded offline backup is not touched. Only the provisioned template, wrapped authorization, and per-user copies remain on the server. The recovery password is not saved in configuration.

Keep the recovery PFX and its password offline, and back up the PKI/keyring and user directories. The recovery PFX restores the TPM parent on replacement hardware; it does not contain users' credentials or their encrypted metadata. See the TPM provider README for its explicit recovery provisioning API. There is no fallback to software signing when TPM access fails. TPM installations created by the previous per-user auto-provisioning flow require migration; file/memory installations need TPM setup before switching to this provider.

Changing the provider does not migrate or delete existing credentials. File and TPM now use the same `keys` and `credentials` paths, but their key formats differ: switching providers for existing credentials requires migration. Memory credentials disappear at shutdown. This setting controls FIDO keys, not TLS/CA certificates or ASP.NET Data Protection keys.

The management dashboard counts credentials for the selected provider.

## Credential file encryption

`MtlsBasedSecretStoreServer.EncryptCredentialFiles` defaults to `true`, including when the setting is absent. First-run setup lets you select encrypted credential metadata or readable JSON. This setting applies to `.cred` files for both File and TPM providers; Memory does not persist credentials. Private keys and PIN state always retain their protection, and login password checks still run even when credentials are plaintext.

Plaintext `.cred` files expose RP IDs, usernames, user IDs, key handles, and signature counters. They have no cryptographic tamper detection. Protect access to their directory and backups accordingly.

New credential directories contain `credential-format.json`, which records the selected mode. Existing unmarked directories are treated as the original encrypted format. A mismatch is rejected; decryption errors never fall back to reading plaintext. Keep this marker with the credential files when backing up or restoring.

Changing `EncryptCredentialFiles` does not rewrite existing files. Existing credential directories must match the selected mode before the server starts using them.

## Code boundaries

`VFido.SecretManager.Protection` owns payload encryption and password unlocking. `PasswordStorageProtection.Create` provisions authentication metadata; `Open` verifies existing metadata without recreating missing files. `AesPayloadProtector` preserves the original PBKDF2 and AES-GCM format and owns a disposable copy of the unlocked key.

`FileBasedCredentialStore` accepts `IFileStorage`, selecting `PlainFileStorage` or `EncryptedFileStorage` in the composition code. The file layer performs atomic replacement; stores own serialization, filenames, and domain operations. `FilePinStateStore` is independent of the signing-key store. Server and GUI composition unlock once and share protection for the lifetime of their manager. TPM object wrapping and signing remain in the TPM backend. CA protection uses the protection project directly.

Older password/key constructors remain for source compatibility; new composition uses injected storage. File and TPM providers share `FileBasedCredentialStore`. The old combined key/PIN interface delegates to `FilePinStateStore`. Missing authentication metadata is now an error on open and must be restored from backup.

Local GUI File and TPM sticks have the same `EncryptCredentialFiles` option under their secret-manager configuration, defaulting to `true`. The Add stick dialog exposes it for new sticks. Changing an existing stick requires an explicit converted directory (the `FileBasedCredentialStore.ExportConverted` API), followed by replacing the directory and updating its configuration while disconnected. The edit dialog does not silently convert existing files.
