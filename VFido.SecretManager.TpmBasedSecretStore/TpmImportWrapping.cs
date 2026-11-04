using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace VFido.SecretManager.TpmBasedSecretStore;

/// <summary>Builds a SHA-256/AES-128-CFB outer duplication wrapper without TSS's static LastSeed.</summary>
internal static class TpmImportWrapping
{
    public static TpmPrivate Wrap(TssObject source, TpmPublic parent, out byte[] encryptedSeed)
    {
        if (parent.nameAlg != TpmAlgId.Sha256 || parent.parameters is not RsaParms rsa ||
            rsa.symmetric.Algorithm != TpmAlgId.Aes || rsa.symmetric.KeyBits != 128 || rsa.symmetric.Mode != TpmAlgId.Cfb)
            throw new InvalidDataException("Expected an RSA/SHA-256/AES-128-CFB storage parent.");
        var seed = RandomNumberGenerator.GetBytes(32);
        byte[]? storageKey = null, integrityKey = null, sensitive = null;
        try
        {
            encryptedSeed = parent.EncryptOaep(seed, Encoding.ASCII.GetBytes("DUPLICATE\0"));
            var name = source.Public.GetName();
            storageKey = KDF.KDFa(TpmAlgId.Sha256, seed, "STORAGE", name, Array.Empty<byte>(), 128);
            integrityKey = KDF.KDFa(TpmAlgId.Sha256, seed, "INTEGRITY", Array.Empty<byte>(), Array.Empty<byte>(), 256);
            sensitive = source.Sensitive.GetTpm2BRepresentation();
            using var cipher = SymCipher.Create(rsa.symmetric, storageKey);
            var encrypted = cipher.Encrypt(sensitive);
            var authenticated = new byte[encrypted.Length + name.Length];
            encrypted.CopyTo(authenticated, 0);
            name.CopyTo(authenticated, encrypted.Length);
            var hmac = HMACSHA256.HashData(integrityKey, authenticated);
            var duplicate = new byte[2 + hmac.Length + encrypted.Length];
            BinaryPrimitives.WriteUInt16BigEndian(duplicate, checked((ushort)hmac.Length));
            hmac.CopyTo(duplicate, 2);
            encrypted.CopyTo(duplicate, 2 + hmac.Length);
            return new TpmPrivate(duplicate);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (storageKey != null) CryptographicOperations.ZeroMemory(storageKey);
            if (integrityKey != null) CryptographicOperations.ZeroMemory(integrityKey);
            if (sensitive != null) CryptographicOperations.ZeroMemory(sensitive);
        }
    }
}
