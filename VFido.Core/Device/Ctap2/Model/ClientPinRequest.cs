using System.Security.Cryptography;

namespace VFido.Core.Device.Ctap2.Model
{
    internal record ClientPinRequest(
        byte PinProtocol,
        byte SubCommand,
        ECParameters? KeyAgreement,
        byte[]? PinUvAuthParam,
        byte[]? NewPinEnc,
        byte[]? PinHashEnc);
}
