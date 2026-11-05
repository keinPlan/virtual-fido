using System.Security.Cryptography;
using VFido.SecretManager;

namespace VirtualFido.Tests;

public sealed class HpkeBaseTests
{
    // RFC 9180 Appendix A.3.1, first encryption. Independent known-answer test, not a round trip.
    [Fact]
    public void BaseMode_MatchesRfc9180P256Vector()
    {
        var enc = Convert.FromHexString("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
        var pkR = Convert.FromHexString("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
        using var ephemeral = PrivateKey("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb", enc);
        using var recipient = PrivateKey("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2", pkR);
        var info = Convert.FromHexString("4f6465206f6e2061204772656369616e2055726e");
        var plaintext = Convert.FromHexString("4265617574792069732074727574682c20747275746820626561757479");
        var aad = Convert.FromHexString("436f756e742d30");
        var expected = Convert.FromHexString("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434");
        using var sender = HpkeBase.Sender(ephemeral, recipient, info);
        Assert.Equal(Convert.FromHexString("4e0bc5018beba4bf004cca59"), sender.Nonce);
        Assert.Equal(expected, sender.Seal(plaintext, aad));
        Assert.Throws<InvalidOperationException>(() => sender.Seal(plaintext, aad));
        using var receiver = HpkeBase.Receiver(recipient, enc, info);
        Assert.Equal(plaintext, receiver.Open(expected, aad));
        Assert.Throws<InvalidOperationException>(() => receiver.Open(expected, aad));
    }

    private static ECDiffieHellman PrivateKey(string scalar, byte[] point) => ECDiffieHellman.Create(new ECParameters
    {
        Curve = ECCurve.NamedCurves.nistP256,
        D = Convert.FromHexString(scalar),
        Q = new ECPoint { X = point[1..33], Y = point[33..65] },
    });

    [Fact]
    public void InvalidEncapsulatedPoint_IsRejected()
    {
        using var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var invalid = new byte[65];
        invalid[0] = 4;
        Assert.ThrowsAny<CryptographicException>(() => HpkeBase.Receiver(recipient, invalid, []));
        Assert.ThrowsAny<CryptographicException>(() => HpkeBase.Receiver(recipient, new byte[32], []));
    }
}
