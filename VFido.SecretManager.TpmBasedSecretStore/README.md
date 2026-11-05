# TPM secret store

This backend imports an externally generated RSA storage master and generates new P-256 credential keys inside the TPM using TPM2_Create. Existing P-256 credential keys can also be imported. Newly generated credentials never expose plaintext private key material to the application during creation; wrapped recovery remains supported through the portable master. After import, credential and attestation signing runs through TPM2_Sign; runtime never loads a software credential private key. Windows TBS is the default transport. No TPM clear, hierarchy changes, or software fallback is performed. Persistent primary eviction is available only through the explicit cache-deletion action.

## Connection performance

RSA primary creation can take tens of seconds on some TPMs. The backend creates its own deterministic owner primary and attempts to keep a persistent copy at `0x81015646` using `TPM2_EvictControl`. Subsequent connections verify that object's TPM Name against `master.json` and reuse it without `TPM2_CreatePrimary`. The application does not use the Windows SRK. Existing stores using the application primary can populate the cache without migrating key files.

Caching requires available TPM NV space, owner hierarchy authorization, and permission from Windows TBS to execute `TPM2_EvictControl`. If caching fails, the store logs the TPM response and continues with a transient primary; future connections can remain slow. An occupied handle is never replaced, and the persistent primary is never evicted on disconnect.

In **Edit**, **Delete cached TPM primary (0x81015646)...** removes the shared cache after confirmation. Disconnect all TPM sticks first. The backend verifies the object Name against this store before calling `TPM2_EvictControl`; it refuses to delete a different occupant. This requires Windows command permission and owner authorization just like persistence. Credential files remain intact, and the next connection can recreate the same deterministic primary and cache it again. Cache deletion does not revoke credentials or backups.

### Windows reports TbsCommandBlocked

Close the GUI, run the rebuilt GUI **as administrator**, and connect once to retry caching with an elevated caller. If successful, the log reports `TPM primary cached at 0x81015646`; subsequent ordinary connections reuse that object. Elevation does not supply a nonempty owner authorization automatically. The backend API accepts `ownerAuthorization`; the GUI currently uses empty authorization.

Elevation is a diagnostic next step, not a guarantee: Windows can still deny the command. On Windows 10 version 1809 and later, the TPM 2.0 command allow list is fixed in the TPM driver and cannot be changed using registry allow-list settings. The `IgnoreDefaultList`/`IgnoreLocalList` guidance for TPM 1.2 does not unblock TPM 2.0 commands on these versions. See [Microsoft's TBS command-blocking documentation](https://learn.microsoft.com/en-us/windows/win32/tbs/command-blocking). The application does not modify system TPM policy or take ownership of the TPM.

If a stick was provisioned using the earlier Windows SRK implementation, restore its original recovery PFX through **Edit > Restore master on this TPM** to rewrap the master under the application's own primary. Credentials and metadata remain compatible. A TPM clear also requires recovery.

Connection diagnostics use the application's NLog configuration. Info messages report primary creation and total opening time in milliseconds, cache verification, and successful persistence. Debug messages include transport and master-loading timings; warnings explain cache mismatches or persistence failures with TPM response codes. In the GUI these appear in `logs/<date>.log` beside the executable and in console/debugger output. Authorization bytes, passwords, key material, and credential data are not logged.

## Master password protection

The GUI uses the metadata password to authorize each VFido master object, separately from TPM owner authorization and the recovery PFX password. PBKDF2-SHA256 derives a 32-byte `authValue` using 600,000 iterations, a fresh 32-byte per-store salt, and the `VFIDO_TPM_MASTER_AUTH_V1` context label. The master is imported with that authorization and its handle supplies it when loading, creating, or importing credential objects. The shared persistent primary remains unchanged.

Protected `master.json` files use version 2 and contain public KDF parameters and a SHA-256 verifier of the derived authorization, allowing missing or incorrect passwords to fail before accessing the TPM. The verifier permits offline password guesses, so use a strong password. Authorization bytes are never saved in plaintext or logged; runtime authorization buffers are cleared on disposal. The master Name, wrapping seed, credential blobs, and recovery PFX format remain unchanged.

Backend callers enable this by passing `masterPassword` to both `Provision` and the constructor. Omitting it during provisioning retains version 1 behavior for compatibility. Legacy stores remain readable and log a warning; to enable protection, disconnect and use **Edit > Restore master on this TPM** with the original recovery PFX and the existing metadata password. Recovery verifies the metadata password before provisioning and validates all credential blobs before replacing the master file. It does not change the metadata password. Changing a protected backend master's password likewise requires reimporting the recovery master into a new destination and validating existing children.

This authorization protects use of the locally wrapped master. It does not revoke older unprotected backups or restrict someone holding the recovery PFX and its password. Already loaded credential keys also retain their own authorization settings. Protect the store directory and recovery package with appropriate access controls.

## Recovery PFX

In **Credentials**, use the normal **Export TPM backup ZIP** button to export all wrapped keys, attestation, encrypted metadata, authentication files, configuration, PIN state, and restore instructions. Export pauses storage writes for a consistent snapshot while the stick stays connected. The ZIP has no additional password. The TPM-local `master.json` is excluded. Extract the stick folder into the configured VFido directory while disconnected, then use **Edit > Restore master on this TPM** with the original recovery PFX, its password, and the original metadata password before connecting, even on the original TPM. Keep that PFX separately. Restoring an older backup also restores its counters and PIN retry state. **Import passkeys** continues to accept certificate-encrypted CXP files.

```csharp
using VFido.SecretManager.TpmBasedSecretStore;

using (var master = TpmMasterKey.Generate())
{
    File.WriteAllBytes("recovery.pfx", master.ExportPfx(recoveryPassword));
    TpmBasedSecretStore.Provision(keyDirectory, master, masterPassword: storePassword);
}

// Subsequent starts need only the local TPM-wrapped master.
using var keys = new TpmBasedSecretStore(keyDirectory, masterPassword: storePassword);
var metadata = new TpmBasedCredentialStore(metadataDirectory, username, metadataPassword);
var manager = new Fido2SecretManager(keys, metadata);
```

For an existing RSA-2048 key, use `TpmMasterKey.FromExternal(rsa, seed)` with a cryptographically random 32-byte seed. RSA exponent 65537 is required. Input material remains caller-owned; clear or dispose it when finished.

The PFX contains a matching self-signed RSA certificate, a password-shrouded PKCS#8 RSA key, and a PKCS#12 secret bag with a DER sequence `{ version INTEGER, seed OCTET STRING, TPMT_PUBLIC OCTET STRING }`. The application secret type is `2.25.283804781146552502253219919921438285001`. All safe contents are encrypted with AES-256-CBC/PBKDF2-SHA256 (200,000 iterations), with a SHA-256 password MAC. The seed is never embedded in the certificate. Keep the original PFX: generic certificate import/export tools may discard custom secret bags.

Version 1 uses RSA-2048, SHA-256 and AES-128-CFB for the TPM storage parent. AES-128 is used for broad TPM compatibility; AES-256 protects the PFX. The exact parent template is preserved and validated on recovery. The master and credential objects have `adminWithPolicy` set with an empty policy, disabling administrative duplication; password-protected masters require their derived object authorization for ordinary use. Credential objects and the shared primary retain empty object authorization. Owner hierarchy authorization can be supplied separately to `Provision` and the constructor. Protect the directory with user-specific ACLs. CTAP PIN checks remain in the authenticator layer.

## Restore on another TPM

```csharp
var recoveryBytes = File.ReadAllBytes("recovery.pfx");
using (var master = TpmMasterKey.ImportPfx(recoveryBytes, recoveryPassword))
    TpmBasedSecretStore.Provision(destinationKeyDirectory, master, masterPassword: destinationStorePassword);
```

Copy credential `.tpmkey` files and `attestation.json` to the destination, keeping filenames/handles unchanged, plus credential metadata and its separate encryption/password information. Do not copy `master.json`: it wraps the master under the source TPM's primary. Provision creates a new local `master.json` and refuses to overwrite an existing one. The same procedure works after a TPM clear, using a new destination directory. Neither recovery nor normal opening creates a missing master silently.

Alternatively, `ExportWrappedKey(handle)` and `ImportWrappedKey(blob)` move one opaque wrapped key. Import assigns a new handle, so update the destination credential metadata accordingly. Blobs include the master Name, public area, and TPM-protected private area. Private integrity is checked by TPM2_Load before accepting an import. The same RSA public identity with a different seed cannot load the original children.

The PFX alone does not contain credentials or their metadata. Conversely, anyone with its private master material and seed plus credential blobs can recover credential secrets in software. This design guarantees TPM signing in this implementation; it cannot enforce hardware-exclusive use against the holder of the recovery package. Deleting a local key file does not revoke backup copies.

## Integration and tests

`TpmBasedSecretStore` implements `IKeyStore`, `ICredentialKeyImporter`, and `IDisposable`. It supports certificate-encrypted CXF **import**, including VirtualFido counter metadata, but never PKCS#8 export. `Fido2SecretManager.SupportsPasskeyImport` is independent from `SupportsPasskeyBackup`. Wrapped blob recovery is a separate API. Dispose the key store after callers finish; signing wrappers own no TPM handles. Operations are serialized per store and transient credential handles are flushed after use.

The GUI supports TPM setup under **Add stick > TPM 2.0 (Windows)**. Choose an existing recovery PFX or use **Create recovery PFX...** to save a new master (existing files are never overwritten). Enter a separate metadata username/password, also used to protect the TPM master; the PFX password is used only for setup or recovery and is not copied into the stick folder or configuration. **Connect** prompts for the metadata username/password. Credential management enables **Import passkeys** while private-key export stays disabled. The GUI persists PIN hashes and retry counts in password-encrypted `pin.bin`, sharing metadata authentication files, so locked PINs stay locked across reconnects.

For recovery, copy the complete stick folder into the configured VFido directory, disconnect the stick, open **Edit**, select the original PFX, enter its password and the original metadata password, and use **Restore master on this TPM**. Recovery checks the configured master identity and loads every existing wrapped credential under a staged master before atomically replacing `keys/master.json`. Wrong passwords, different masters, and wrong seeds leave existing key files intact. Keep `config.json`, credentials, wrapped keys, `pin.bin`, `salt.bin`, and `verifier.bin` together when backing up. The GUI uses the default Windows owner authorization; custom owner authorization is currently available only through the backend API.

`TpmBasedCredentialStore` reuses encrypted file metadata. `Fido2SecretManager` can accept an explicit PIN store and opt into owning/disposal of the key store, which the GUI does on connection. Standalone users still own their key store unless they pass `ownsKeyStore: true`. Attestation provisions an external ephemeral root/intermediate and imports its leaf private key; only the leaf/intermediate public certificates are retained. This is local packed attestation, not a manufacturer TPM attestation certificate.

GUI provisioning and recovery service tests are included in `TpmGuiProvisioningTests`, with local TPM tests enabled by the same environment flag. Run software tests with `dotnet test VirtualFido.Tests`. To exercise the local Windows TPM, set `VFIDO_TEST_TPM=1` and run `dotnet test VirtualFido.Tests --filter FullyQualifiedName~TpmSecretStoreIntegrationTests`. This creates temporary test directories and TPM objects, and may leave the shared persistent primary cache described above. It checks PFX-based master recovery, signing, restart, unchanged wrapped-key recovery, attestation, deletion, and wrong-seed rejection on the same TPM. A second independent physical TPM or simulator is still needed to validate cross-device compatibility.
