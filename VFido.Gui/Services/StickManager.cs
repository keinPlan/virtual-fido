using NLog;
using VFido.Core;
using VFido.Core.Device;
using VFido.Core.Vhci;
using VFido.Gui.UserPresence;

namespace VFido.Gui.Services;

public sealed class StickManager : IStickManager
{
    private const string UnsupportedPlatformMessage =
        "Automatic device attach is only supported on Windows for now. Use a platform-specific usbip client to attach manually.";

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
    private static readonly int[] DeviceIds = { 0x00010001 /*, 0x00010002, 0x00010003, 0x00010004 */ };

    private const string Host = "127.0.0.1";
    private const int Port = 3240;

    private readonly UsbIpServer _server = new(Host, Port);
    private bool _started;

    public async Task<IReadOnlyList<StickAttachResult>> StartAsync()
    {
        if (_started)
            return Array.Empty<StickAttachResult>();

        _started = true;

        var devices = new List<FidoUsbStick>();
        foreach (var deviceId in DeviceIds)
        {
            var gate = new AvaloniaUserPresenceGate($"VFIDO-{deviceId:X8}");
            var device = new FidoUsbStick(deviceId, gate);
            _server.VirtualUsbDevices.Add(deviceId, device);
            devices.Add(device);
        }

        _server.Start();

        var results = new List<StickAttachResult>(devices.Count);
        foreach (var device in devices)
            results.Add(await AttachAsync($"{device.DeviceBusNum}-{device.DeviceBusID}"));

        return results;
    }

    public Task<StickAttachResult> AttachAsync(string busid)
    {
        if (!OperatingSystem.IsWindows())
        {
            Logger.Warn($"Skipping attach of busid={busid}: {UnsupportedPlatformMessage}");
            return Task.FromResult(new StickAttachResult(StickAttachOutcome.UnsupportedPlatform, busid, UnsupportedPlatformMessage));
        }

        var vhci = new VhciAttacher();
        if (!vhci.TryAttach(Host, Port.ToString(), busid, out _, out var error))
        {
            Logger.Warn($"Failed to attach busid={busid}: {error}");
            return Task.FromResult(new StickAttachResult(StickAttachOutcome.Failed, busid, error));
        }

        return Task.FromResult(new StickAttachResult(StickAttachOutcome.Success, busid, null));
    }
}
