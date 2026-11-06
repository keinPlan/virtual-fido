# Server FIDO storage

On a fresh installation, start the server without arguments to open the local first-run setup wizard. It lets you choose the storage provider, server DNS name/IP, HTTPS port, CA passphrase, and first administrator. Download the administrator PFX and root CA, then select **Close setup and start server**. The administrator uses certificate-only authentication; the PFX has the password chosen during setup.

Setup listens on a random port on `127.0.0.1` and prints its private URL if the browser cannot open automatically. Run it on the server machine (or forward that loopback port through SSH). It never listens on the network, and existing or partial PKI/user installations are not overwritten. Repair partial installations with the existing `init` CLI. Configuration is saved to `appsettings.json` next to the server executable, which must be writable during setup. Once configured, subsequent starts go directly to the mTLS server.

Set `MtlsBasedSecretStoreServer.StorageProvider` in `appsettings.json` to `File`, `Tpm`, or `Memory`, then restart the server. The default is `File`.

| Provider | Private keys | Credential metadata / PIN state |
| --- | --- | --- |
| File | AES-encrypted files in each user's `keys` directory | Encrypted files |
| Tpm | TPM-wrapped files in each user's `keys` directory; signing runs in the local TPM | Encrypted metadata in `credentials`; encrypted PIN state |
| Memory | Process memory | Process memory; lost when the server stops |

All modes retain the existing mTLS and optional login password requirements. Memory mode shares a user's credentials across sessions for the lifetime of the server; certificates, login verifiers, and server PKI still use disk storage.

TPM mode requires a supported local TPM accessible to the server account. During setup, upload an existing `vfido-tpm-recovery.pfx` or leave the upload empty to generate a new password-protected recovery PFX. Enter its recovery password (at least 12 characters). Setup imports that PFX to provision `<PkiRootPath>/tpm/master.json` and opens it immediately to verify TPM access. The PFX contains the portable parent key and wrapping seed; `master.json` is its TPM-bound representation.

The setup administrator and each subsequent `create-user` receive a copy of this master at `<SecretsRootPath>/<username>/keys/master.json`. Wrapped signing keys and attestation live in `keys`, with encrypted metadata in the sibling `credentials` folder. There is no per-user `tpm` folder. The master's common authorization stays once on the server in `<PkiRootPath>/tpm/wrapped.key`; it is not copied to users. A passwordless user's single top-level `wrapped.key` protects their metadata and PIN state; password users derive that encryption key from their login password. First access also copies the template for users that have not yet received it. Existing different user masters or the old nested `tpm` layout are rejected rather than overwritten; they need a separate migration.

After setup, download **vfido-tpm-recovery.pfx** before selecting **Close setup and start server**. The temporary export at `<PkiRootPath>/tpm/vfido-tpm-recovery.pfx` is deleted when the normal server starts, including on subsequent starts. The downloaded offline backup is not touched. Only the provisioned template, wrapped authorization, and per-user copies remain on the server. The recovery password is not saved in configuration.

Keep the recovery PFX and its password offline, and back up the PKI/keyring and user directories. The recovery PFX restores the TPM parent on replacement hardware; it does not contain users' credentials or their encrypted metadata. See the TPM provider README for its explicit recovery provisioning API. There is no fallback to software signing when TPM access fails. TPM installations created by the previous per-user auto-provisioning flow require migration; file/memory installations need TPM setup before switching to this provider.

Changing the provider does not migrate or delete existing credentials. File and TPM now use the same `keys` and `credentials` paths, but their key formats differ: switching providers for existing credentials requires migration. Memory credentials disappear at shutdown. This setting controls FIDO keys, not TLS/CA certificates or ASP.NET Data Protection keys.

The management dashboard counts credentials for the selected provider.
