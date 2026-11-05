using System.Security.Cryptography;
using System.Text;

namespace VFido.SecretManager;

/// <summary>RFC 9180 base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.</summary>
internal static class HpkeBase
{
    private static readonly byte[] KemSuite = [75, 69, 77, 0, 16];
    private static readonly byte[] Suite = [72, 80, 75, 69, 0, 16, 0, 1, 0, 1];

    internal static byte[] PublicKey(ECDiffieHellman key)
    {
        var p = key.ExportParameters(false);
        if (p.Curve.Oid.Value != "1.2.840.10045.3.1.7" || p.Q.X?.Length != 32 || p.Q.Y?.Length != 32)
            throw new CryptographicException("HPKE requires a P-256 key.");
        return [4, .. p.Q.X, .. p.Q.Y];
    }

    internal static ECDiffieHellman ImportPublic(byte[] encoded)
    {
        if (encoded.Length != 65 || encoded[0] != 4)
            throw new CryptographicException("Invalid HPKE P-256 public key.");
        // The platform validates curve membership and rejects the point at infinity.
        try { return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = encoded[1..33], Y = encoded[33..65] },
        }); }
        catch (Exception error) when (error is ArgumentException or PlatformNotSupportedException)
        {
            throw new CryptographicException("Invalid HPKE P-256 public key.", error);
        }
    }

    internal static Context Sender(ECDiffieHellman ephemeral, ECDiffieHellman recipient, byte[] info) =>
        Setup(ephemeral, recipient, PublicKey(ephemeral), PublicKey(recipient), info);

    internal static Context Receiver(ECDiffieHellman recipient, byte[] encapsulated, byte[] info)
    {
        using var ephemeral = ImportPublic(encapsulated);
        return Setup(recipient, ephemeral, encapsulated, PublicKey(recipient), info);
    }

    private static Context Setup(ECDiffieHellman own, ECDiffieHellman peer, byte[] enc, byte[] pkR, byte[] info)
    {
        var dh = own.DeriveRawSecretAgreement(peer.PublicKey);
        byte[] eae = [], shared = [], secret = [];
        try
        {
            eae = Extract([], KemSuite, "eae_prk", dh);
            shared = Expand(eae, KemSuite, "shared_secret", [.. enc, .. pkR], 32);
            var pskIdHash = Extract([], Suite, "psk_id_hash", []);
            var infoHash = Extract([], Suite, "info_hash", info);
            byte[] context = [0, .. pskIdHash, .. infoHash];
            secret = Extract(shared, Suite, "secret", []);
            var key = Expand(secret, Suite, "key", context, 16);
            try { return new Context(key, Expand(secret, Suite, "base_nonce", context, 12)); }
            catch { CryptographicOperations.ZeroMemory(key); throw; }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dh);
            CryptographicOperations.ZeroMemory(eae);
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static byte[] Extract(byte[] salt, byte[] suite, string label, byte[] input)
    {
        byte[] labeled = [.. "HPKE-v1"u8, .. suite, .. Encoding.ASCII.GetBytes(label), .. input];
        try { return HKDF.Extract(HashAlgorithmName.SHA256, labeled, salt); }
        finally { CryptographicOperations.ZeroMemory(labeled); }
    }

    private static byte[] Expand(byte[] prk, byte[] suite, string label, byte[] info, int length) =>
        HKDF.Expand(HashAlgorithmName.SHA256, prk, length,
            [(byte)(length >> 8), (byte)length, .. "HPKE-v1"u8, .. suite, .. Encoding.ASCII.GetBytes(label), .. info]);

    /// <summary>Single-message context (sequence number zero); never reuse a nonce.</summary>
    internal sealed class Context(byte[] key, byte[] nonce) : IDisposable
    {
        private bool _used;
        internal byte[] Nonce => nonce.ToArray();
        internal byte[] Seal(byte[] plaintext, byte[] aad)
        {
            Use();
            var output = new byte[plaintext.Length + 16];
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length), aad);
            return output;
        }
        internal byte[] Open(byte[] ciphertext, byte[] aad)
        {
            Use();
            if (ciphertext.Length < 16) throw new CryptographicException("Truncated HPKE ciphertext.");
            var output = new byte[ciphertext.Length - 16];
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(nonce, ciphertext.AsSpan(0, output.Length), ciphertext.AsSpan(output.Length), output, aad);
                return output;
            }
            catch { CryptographicOperations.ZeroMemory(output); throw; }
        }
        private void Use()
        {
            if (_used) throw new InvalidOperationException("HPKE context already used or disposed.");
            _used = true;
        }
        public void Dispose()
        {
            _used = true;
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }
}
