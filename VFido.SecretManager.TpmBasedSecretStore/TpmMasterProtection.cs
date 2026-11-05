using System.Security.Cryptography;
using System.Text;

namespace VFido.SecretManager.TpmBasedSecretStore;

internal sealed record TpmMasterProtection(byte[] Salt, int Iterations, byte[] Verifier)
{
    internal const int WorkFactor = 600_000;
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("VFIDO_TPM_MASTER_AUTH_V1");

    internal static TpmMasterProtection Create(string password, out byte[] authorization)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        var salt = RandomNumberGenerator.GetBytes(32);
        authorization = Derive(password, salt);
        return new(salt, WorkFactor, SHA256.HashData(authorization));
    }

    internal byte[] Unlock(string? password)
    {
        if (Salt?.Length != 32 || Iterations != WorkFactor || Verifier?.Length != 32)
            throw new InvalidDataException("Invalid TPM master password protection parameters.");
        if (string.IsNullOrWhiteSpace(password))
            throw new CryptographicException("The TPM master password is required.");
        var authorization = Derive(password, Salt);
        var verifier = SHA256.HashData(authorization);
        try
        {
            if (CryptographicOperations.FixedTimeEquals(verifier, Verifier)) return authorization;
            CryptographicOperations.ZeroMemory(authorization);
            throw new CryptographicException("Incorrect TPM master password or damaged protection parameters.");
        }
        finally { CryptographicOperations.ZeroMemory(verifier); }
    }

    private static byte[] Derive(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt.Concat(Context).ToArray(), WorkFactor, HashAlgorithmName.SHA256, 32);
}
