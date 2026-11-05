# TPM secret store

This backend imports an externally generated RSA storage master and generates new P-256 credential keys inside the TPM using TPM2_Create. Existing P-256 credential keys can also be imported. Newly generated credentials never expose plaintext private key material to the application during creation; wrapped recovery remains supported through the portable master. After import, credential and attestation signing runs through TPM2_Sign; runtime never loads a software credential private key. Windows TBS is the default transport. No TPM clear, hierarchy changes, eviction of existing persistent objects, or software fallback is performed.

## Connection performance

RSA primary creation can take tens of seconds on some TPMs. After creating and validating the deterministic owner primary, the backend attempts to keep a persistent copy at `0x81015646`. Subsequent connections read that object and verify its TPM Name against `master.json`, skipping `TPM2_CreatePrimary`. The cache is shared by local stores using the same primary and survives application restarts and reboots. Existing stores populate it on their first successful primary creation; no key-file migration is required.

Caching requires permission to persist an object under the owner hierarchy and available TPM NV space. If Windows policy, owner authorization, or an occupied handle prevents caching, connections retain the transient-primary behavior and its creation delay. The backend never replaces an occupied handle or evicts the cached primary on disconnect. A missing or mismatched cache falls back to recreating and validating the original primary; a TPM clear still requires recovery. The first setup or uncached connection can therefore remain slow.

Connection diagnostics use the application's NLog configuration. Info messages report primary creation and total opening time in milliseconds, cache verification, and successful persistence. Debug messages include transport and master-loading timings; warnings explain cache mismatches or persistence failures with TPM response codes. In the GUI these appear in `logs/<date>.log` beside the executable and in console/debugger output. Authorization bytes, passwords, key material, and credential data are not logged.

## Recovery PFX

```csharp
using VFido.SecretManager.TpmBasedSecretStore;

using (var master = TpmMasterKey.Generate())
{
    File.WriteAllBytes("recovery.pfx", master.ExportPfx(recoveryPassword));
    TpmBasedSecretStore.Provision(keyDirectory, master);
}

// Subsequent starts need only the local TPM-wrapped master.
using var keys = new TpmBasedSecretStore(keyDirectory);
var metadata = new TpmBasedCredentialStore(metadataDirectory, username, metadataPassword);
var manager = new Fido2SecretManager(keys, metadata);
```

For an existing RSA-2048 key, use `TpmMasterKey.FromExternal(rsa, seed)` with a cryptographically random 32-byte seed. RSA exponent 65537 is required. Input material remains caller-owned; clear or dispose it when finished.

The PFX contains a matching self-signed RSA certificate, a password-shrouded PKCS#8 RSA key, and a PKCS#12 secret bag with a DER sequence `{ version INTEGER, seed OCTET STRING, TPMT_PUBLIC OCTET STRING }`. The application secret type is `2.25.283804781146552502253219919921438285001`. All safe contents are encrypted with AES-256-CBC/PBKDF2-SHA256 (200,000 iterations), with a SHA-256 password MAC. The seed is never embedded in the certificate. Keep the original PFX: generic certificate import/export tools may discard custom secret bags.

Version 1 uses RSA-2048, SHA-256 and AES-128-CFB for the TPM storage parent. AES-128 is used for broad TPM compatibility; AES-256 protects the PFX. The exact parent template is preserved and validated on recovery. The master and credential objects have `adminWithPolicy` set with an empty policy, disabling administrative duplication; ordinary use uses empty object authorization and relies on OS access control over the store directory. Owner hierarchy authorization can be supplied separately to `Provision` and the constructor. Protect the directory with user-specific ACLs. CTAP PIN checks remain in the authenticator layer.

## Restore on another TPM

```csharp
var recoveryBytes = File.ReadAllBytes("recovery.pfx");
using (var master = TpmMasterKey.ImportPfx(recoveryBytes, recoveryPassword))
    TpmBasedSecretStore.Provision(destinationKeyDirectory, master);
```

Copy credential `.tpmkey` files and `attestation.json` to the destination, keeping filenames/handles unchanged, plus credential metadata and its separate encryption/password information. Do not copy `master.json`: it wraps the master under the source TPM's primary. Provision creates a new local `master.json` and refuses to overwrite an existing one. The same procedure works after a TPM clear, using a new destination directory. Neither recovery nor normal opening creates a missing master silently.

Alternatively, `ExportWrappedKey(handle)` and `ImportWrappedKey(blob)` move one opaque wrapped key. Import assigns a new handle, so update the destination credential metadata accordingly. Blobs include the master Name, public area, and TPM-protected private area. Private integrity is checked by TPM2_Load before accepting an import. The same RSA public identity with a different seed cannot load the original children.

The PFX alone does not contain credentials or their metadata. Conversely, anyone with its private master material and seed plus credential blobs can recover credential secrets in software. This design guarantees TPM signing in this implementation; it cannot enforce hardware-exclusive use against the holder of the recovery package. Deleting a local key file does not revoke backup copies.

## Integration and tests

`TpmBasedSecretStore` implements `IKeyStore`, `ICredentialKeyImporter`, and `IDisposable`. It supports certificate-encrypted CXF **import**, including VirtualFido counter metadata, but never PKCS#8 export. `Fido2SecretManager.SupportsPasskeyImport` is independent from `SupportsPasskeyBackup`. Wrapped blob recovery is a separate API. Dispose the key store after callers finish; signing wrappers own no TPM handles. Operations are serialized per store and transient credential handles are flushed after use.

The GUI supports TPM setup under **Add stick > TPM 2.0 (Windows)**. Choose an existing recovery PFX or use **Create recovery PFX...** to save a new master (existing files are never overwritten). Enter a separate metadata username/password; the PFX password is used only for setup or recovery and is not copied into the stick folder or configuration. **Connect** prompts for the metadata username/password. Credential management enables **Import passkeys** while private-key export stays disabled. The GUI persists PIN hashes and retry counts in password-encrypted `state/pin.bin`, sharing metadata authentication files, so locked PINs stay locked across reconnects.

For recovery, copy the complete stick folder into the configured VFido directory, disconnect the stick, open **Edit**, select the original PFX, and use **Restore master on this TPM**. Recovery checks the configured master identity and loads every existing wrapped credential under a staged master before atomically replacing `keys/master.json`. Wrong passwords, different masters, and wrong seeds leave existing key files intact. Keep `config.json`, credentials, wrapped keys, `state`, `salt.bin`, and `verifier.bin` together when backing up. The GUI uses the default Windows owner authorization; custom owner authorization is currently available only through the backend API.

`TpmBasedCredentialStore` reuses encrypted file metadata. `Fido2SecretManager` can accept an explicit PIN store and opt into owning/disposal of the key store, which the GUI does on connection. Standalone users still own their key store unless they pass `ownsKeyStore: true`. Attestation provisions an external ephemeral root/intermediate and imports its leaf private key; only the leaf/intermediate public certificates are retained. This is local packed attestation, not a manufacturer TPM attestation certificate.

GUI provisioning and recovery service tests are included in `TpmGuiProvisioningTests`, with local TPM tests enabled by the same environment flag. Run software tests with `dotnet test VirtualFido.Tests`. To exercise the local Windows TPM, set `VFIDO_TEST_TPM=1` and run `dotnet test VirtualFido.Tests --filter FullyQualifiedName~TpmSecretStoreIntegrationTests`. This creates temporary test directories and TPM objects, and may leave the shared persistent primary cache described above. It checks PFX-based master recovery, signing, restart, unchanged wrapped-key recovery, attestation, deletion, and wrong-seed rejection on the same TPM. A second independent physical TPM or simulator is still needed to validate cross-device compatibility.
