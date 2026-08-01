using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using NLog;

namespace VFido.Core.Vhci
{
    /// <summary>
    /// Talks directly to the usbip-win2 "ude" VHCI driver (https://github.com/vadimgrn/usbip-win2)
    /// via its IOCTL interface, so a device can be attached to the local USB stack without shelling
    /// out to usbip.exe. The driver itself opens the TCP connection back to the given host/service
    /// and performs the usbip import handshake, so the target server still needs to answer OP_REQ_DEVINFO
    /// for the given busid (see UsbIpPacketHandler).
    /// </summary>
    public sealed class VhciAttacher
    {
        // usbip::vhci::GUID_DEVINTERFACE_USB_HOST_CONTROLLER (include/usbip/vhci.h)
        private static readonly Guid DeviceInterfaceGuid = new Guid("B4030C06-DC5F-4FCC-87EB-E5515A0935C0");

        private const int BusIdSize = 32;   // usbip::BUS_ID_SIZE
        private const int ServiceSize = 32; // NI_MAXSERV
        private const int HostSize = 1025;  // NI_MAXHOST

        // usbip::vhci::ioctl::function::plugin_hardware / plugout_hardware
        private const int FunctionPluginHardware = 0x800;
        private const int FunctionPlugoutHardware = 0x801;

        private static readonly uint IoctlPluginHardware = CtlCode(FunctionPluginHardware);
        private static readonly uint IoctlPlugoutHardware = CtlCode(FunctionPlugoutHardware);

        private readonly Logger _logger = LogManager.GetCurrentClassLogger();

        public bool TryAttach(string host, string service, string busid, out int port, out string? error)
        {
            port = 0;
            error = null;

            using var device = OpenVhciDevice(out error);
            if (device == null)
                return false;

            var plugin = new PluginHardware
            {
                Size = (uint)Marshal.SizeOf<PluginHardware>(),
                BusId = ToFixedBytes(busid, BusIdSize),
                Service = ToFixedBytes(service, ServiceSize),
                Host = ToFixedBytes(host, HostSize),
            };

            var inSize = Marshal.SizeOf<PluginHardware>();
            var outSize = sizeof(uint) + sizeof(int); // base.size + port, matches native `outlen`
            var inPtr = Marshal.AllocHGlobal(inSize);
            var outPtr = Marshal.AllocHGlobal(outSize);

            try
            {
                Marshal.StructureToPtr(plugin, inPtr, false);

                if (!DeviceIoControl(device, IoctlPluginHardware, inPtr, inSize, outPtr, outSize, out var bytesReturned, IntPtr.Zero))
                {
                    var message = $"PLUGIN_HARDWARE failed: {new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message}";
                    error = message;
                    _logger.Warn(() => $"vhci attach failed for busid={busid} host={host} service={service}: {message} (inSize={inSize})");
                    return false;
                }

                if (bytesReturned != outSize)
                {
                    error = $"Unexpected response size from driver: {bytesReturned} (expected {outSize})";
                    return false;
                }

                port = Marshal.ReadInt32(outPtr, sizeof(uint)); // skip base.size, read port
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
                Marshal.FreeHGlobal(outPtr);
            }

            var attachedPort = port;
            _logger.Info(() => $"vhci attached busid={busid} host={host} service={service} -> port={attachedPort}");
            return true;
        }

        public bool TryDetach(int port, out string? error)
        {
            error = null;

            using var device = OpenVhciDevice(out error);
            if (device == null)
                return false;

            var plugout = new PlugoutHardware
            {
                Size = (uint)Marshal.SizeOf<PlugoutHardware>(),
                Port = port,
            };

            var size = Marshal.SizeOf<PlugoutHardware>();
            var ptr = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(plugout, ptr, false);

                if (!DeviceIoControl(device, IoctlPlugoutHardware, ptr, size, IntPtr.Zero, 0, out _, IntPtr.Zero))
                {
                    var message = $"PLUGOUT_HARDWARE failed: {new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message}";
                    error = message;
                    _logger.Warn(() => $"vhci detach failed for port={port}: {message}");
                    return false;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            _logger.Info(() => $"vhci detached port={port}");
            return true;
        }

        private SafeFileHandle? OpenVhciDevice(out string? error)
        {
            error = null;

            var path = FindDeviceInterfacePath();
            if (path == null)
            {
                error = "usbip-win2 VHCI device interface not found. Is the driver installed?";
                return null;
            }

            var handle = CreateFile(path, GenericRead | GenericWrite, FileShareRead | FileShareWrite,
                IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero);

            if (handle.IsInvalid)
            {
                error = $"Failed to open {path}: {new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message}";
                handle.Dispose();
                return null;
            }

            return handle;
        }

        private string? FindDeviceInterfacePath()
        {
            var guid = DeviceInterfaceGuid;

            if (CM_Get_Device_Interface_List_Size(out var len, ref guid, null, CmGetDeviceInterfaceListPresent) != CrSuccess || len <= 1)
                return null;

            var buffer = new char[len];
            if (CM_Get_Device_Interface_List(ref guid, null, buffer, len, CmGetDeviceInterfaceListPresent) != CrSuccess)
                return null;

            var paths = new string(buffer)
                .Split('\0', StringSplitOptions.RemoveEmptyEntries)
                .ToArray();

            _logger.Debug(() => $"GUID_DEVINTERFACE_USB_HOST_CONTROLLER matches ({paths.Length}): {string.Join(", ", paths)}");

            // GUID_DEVINTERFACE_USB_HOST_CONTROLLER can also be exposed by real, physical USB
            // host controllers - don't blindly take the first match, since that can be a real
            // controller instead of the usbip-win2 vhci ("root\vhci_ude") one.
            var vhciPath = paths.FirstOrDefault(p => p.Contains("VHCI", StringComparison.OrdinalIgnoreCase));
            if (vhciPath != null)
                return vhciPath;

            return paths.Length == 1 ? paths[0] : null;
        }

        private static byte[] ToFixedBytes(string value, int fieldSize)
        {
            var bytes = Encoding.ASCII.GetBytes(value ?? string.Empty);
            if (bytes.Length >= fieldSize)
                throw new ArgumentException($"Value '{value}' does not fit into a {fieldSize}-byte field (including null terminator).");

            var result = new byte[fieldSize];
            Array.Copy(bytes, result, bytes.Length);
            return result;
        }

        private static uint CtlCode(int function)
        {
            const uint fileDeviceUnknown = 0x22;
            const uint methodBuffered = 0;
            const uint fileReadData = 1;
            const uint fileWriteData = 2;

            return (fileDeviceUnknown << 16) | ((fileReadData | fileWriteData) << 14) | ((uint)function << 2) | methodBuffered;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct PluginHardware
        {
            public uint Size;
            public int Port; // OUT

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = BusIdSize)]
            public byte[] BusId;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ServiceSize)]
            public byte[] Service;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = HostSize)]
            public byte[] Host;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct PlugoutHardware
        {
            public uint Size;
            public int Port;
        }

        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint FileShareRead = 1;
        private const uint FileShareWrite = 2;
        private const uint OpenExisting = 3;
        private const uint FileAttributeNormal = 0x80;

        private const int CrSuccess = 0;
        private const uint CmGetDeviceInterfaceListPresent = 0;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            int nInBufferSize,
            IntPtr lpOutBuffer,
            int nOutBufferSize,
            out int lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Device_Interface_List_Size(
            out uint pulLen,
            ref Guid interfaceClassGuid,
            string? deviceId,
            uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Device_Interface_List(
            ref Guid interfaceClassGuid,
            string? deviceId,
            char[] buffer,
            uint bufferLen,
            uint flags);
    }
}
