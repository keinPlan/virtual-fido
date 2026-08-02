namespace VFido.SecretManager
{
    /// <summary>The PIN hash and retry counter PinManager needs to survive a restart. Retries must persist alongside the hash - otherwise a restart would silently reset a locked-out PIN's retry count.</summary>
    public sealed record PinState(byte[] PinHash, int Retries);

    /// <summary>
    /// Optional persistence seam for PinManager's PIN state, mirroring IKeyStore/ICredentialStore.
    /// A stick with no backing store (e.g. in-memory) simply doesn't pass one, and PIN state stays
    /// process-lifetime only, same as today.
    /// </summary>
    public interface IPinStateStore
    {
        PinState? Load();
        void Save(PinState state);
    }
}
