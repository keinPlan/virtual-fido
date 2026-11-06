using System.Security.Cryptography;

namespace VFido.SecretManager.Protection;

public interface IPayloadProtector
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] ciphertext);
}

/// <summary>Owns a copy of the unlocked key. The storage session owns and disposes this object.</summary>
public sealed class AesPayloadProtector : IPayloadProtector, IDisposable
{
    private readonly byte[] _key;
    private bool _disposed;
    public AesPayloadProtector(byte[] key)
    {
        if (key.Length != 32) throw new ArgumentException("Expected a 256-bit storage key.", nameof(key));
        _key = key.ToArray();
    }
    public byte[] Protect(byte[] plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return AesKeyProtector.Encrypt(_key, plaintext);
    }
    public byte[] Unprotect(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return AesKeyProtector.Decrypt(_key, ciphertext);
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }
}
