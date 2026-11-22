// PairVPN ARM64 Bridge
//
// PairVPN's Windows client normally exchanges Ethernet frames with its own x64-only
// kernel driver (pveth.sys) through \\.\PVETH.  The patched PairVPN.exe talks to the
// named pipe \\.\pipe\pveth instead, using exactly pveth's data format:
//   * first, PairVPN reads a 4-byte "adapter ready" value;
//   * PairVPN reads blocks of [uint32 length][Ethernet frame] records (frames from Windows);
//   * PairVPN writes one Ethernet frame per message (frames to Windows);
//   * a zero-length message means "stop".
// This service owns an ARM64-native TAP-Windows6 adapter (named "PairVPN") and relays
// frames between it and the pipe, and tells PairVPN the adapter's MAC address through
// the "MacAddress" registry value it expects.
//
// Build (C# 5, .NET Framework 4.8.1):
//   csc /target:exe /platform:anycpu /r:System.ServiceProcess.dll /out:PairVPN-ARM64-Bridge.exe PairVpnArm64Bridge.cs
// Run modes:
//   (no args)  Windows service "PairVPNArm64Bridge"
//   console    run in the foreground (as administrator) for troubleshooting
//   probe [s]  act like PairVPN for s seconds and print the frames received (test)

using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

[assembly: System.Reflection.AssemblyTitle("PairVPN ARM64 Bridge")]
[assembly: System.Reflection.AssemblyDescription("Relays PairVPN frames to an ARM64 TAP-Windows6 adapter")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.0.0")]

namespace PairVpnArm64
{
    internal static class Native
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint MAXIMUM_ALLOWED = 0x02000000;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint FILE_ATTRIBUTE_SYSTEM = 0x4;
        public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        public const uint PIPE_ACCESS_DUPLEX = 0x3;
        public const uint PIPE_TYPE_MESSAGE = 0x4;
        public const uint PIPE_READMODE_MESSAGE = 0x2;
        public const uint PIPE_REJECT_REMOTE_CLIENTS = 0x8;
        public const uint PIPE_UNLIMITED_INSTANCES = 255;
        public const int ERROR_BROKEN_PIPE = 109;
        public const int ERROR_MORE_DATA = 234;
        public const int ERROR_PIPE_CONNECTED = 535;
        public const int ERROR_OPERATION_ABORTED = 995;
        public const int ERROR_IO_PENDING = 997;
        public const uint WAIT_OBJECT_0 = 0;
        public const uint TAP_IOCTL_GET_MAC = 0x220004;
        public const uint TAP_IOCTL_GET_VERSION = 0x220008;
        public const uint TAP_IOCTL_GET_MTU = 0x22000C;
        public const uint TAP_IOCTL_SET_MEDIA_STATUS = 0x220018;

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances,
            uint outBufferSize, uint inBufferSize, uint defaultTimeout, ref SECURITY_ATTRIBUTES sa);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ConnectNamedPipe(SafeFileHandle pipe, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DisconnectNamedPipe(SafeFileHandle pipe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(SafeFileHandle h, IntPtr buffer, int count, IntPtr read, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(SafeFileHandle h, IntPtr buffer, int count, IntPtr written, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle h, uint code, IntPtr inBuf, int inLen, IntPtr outBuf, int outLen,
            IntPtr returned, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetOverlappedResult(SafeFileHandle h, IntPtr overlapped, out int transferred, bool wait);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CancelIoEx(SafeFileHandle h, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateEvent(IntPtr sa, bool manualReset, bool initialState, IntPtr name);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr h, uint ms);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr sd, IntPtr size);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr mem);
    }

    /// <summary>An OVERLAPPED with its own manual-reset event and an unmanaged buffer; one I/O at a time.</summary>
    internal sealed class AsyncIo : IDisposable
    {
        public readonly IntPtr Overlapped;
        public readonly IntPtr Event;
        public readonly IntPtr Buffer;
        public readonly int BufferSize;
        private int disposed;

        public AsyncIo(int bufferSize)
        {
            Overlapped = Marshal.AllocHGlobal(64);
            for (int i = 0; i < 64; i++) Marshal.WriteByte(Overlapped, i, 0);
            Event = Native.CreateEvent(IntPtr.Zero, true, false, IntPtr.Zero);
            if (Event == IntPtr.Zero) throw new Win32Exception();
            Marshal.WriteIntPtr(Overlapped, 2 * IntPtr.Size + 8, Event);   // OVERLAPPED.hEvent
            BufferSize = bufferSize;
            Buffer = bufferSize > 0 ? Marshal.AllocHGlobal(bufferSize) : IntPtr.Zero;
        }

        /// <summary>Complete an I/O just started (started = API return value). Returns bytes, or -1 and the Win32 error.</summary>
        public int Finish(SafeFileHandle h, bool started, out int error)
        {
            error = 0;
            if (!started)
            {
                error = Marshal.GetLastWin32Error();
                if (error != Native.ERROR_IO_PENDING) return -1;
            }
            int n;
            if (!Native.GetOverlappedResult(h, Overlapped, out n, true))
            {
                error = Marshal.GetLastWin32Error();
                return -1;
            }
            error = 0;
            return n;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            Native.CloseHandle(Event);
            Marshal.FreeHGlobal(Overlapped);
            if (Buffer != IntPtr.Zero) Marshal.FreeHGlobal(Buffer);
        }
    }

    internal static class Log
    {
        private static readonly object Sync = new object();
        private static string lastOnce;
        public static string FilePath;
        public static bool ToConsole;

        public static void Write(string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + msg;
            lock (Sync)
            {
                lastOnce = null;
                if (ToConsole) Console.WriteLine(line);
                if (FilePath == null) return;
                try
                {
                    FileInfo fi = new FileInfo(FilePath);
                    if (fi.Exists && fi.Length > 1024 * 1024)
                    {
                        string old = FilePath + ".old";
                        if (File.Exists(old)) File.Delete(old);
                        File.Move(FilePath, old);
                    }
                    File.AppendAllText(FilePath, line + Environment.NewLine);
                }
                catch (Exception) { }
            }
        }

        /// <summary>Write a message unless it is the same as the previous "once" message (for retry loops).</summary>
        public static void WriteOnce(string msg)
        {
            lock (Sync)
            {
                if (msg == lastOnce) return;
            }
            Write(msg);
            lock (Sync) { lastOnce = msg; }
        }
    }

    /// <summary>One connected PairVPN client on \\.\pipe\pveth.</summary>
    internal sealed class Session
    {
        private static int nextId;
        public readonly int Id;
        private readonly SafeFileHandle pipe;
        private readonly Bridge bridge;
        private readonly AsyncIo rd = new AsyncIo(65536);
        private readonly AsyncIo wr = new AsyncIo(65536 + 4);
        private readonly object writeLock = new object();
        private int closed;

        public Session(SafeFileHandle pipe, Bridge bridge)
        {
            Id = Interlocked.Increment(ref nextId);
            this.pipe = pipe;
            this.bridge = bridge;
        }

        public bool IsClosed { get { return Thread.VolatileRead(ref closed) != 0; } }

        /// <summary>Send bytes to PairVPN (one pipe message). Blocks until the pipe accepts them.</summary>
        public bool Send(byte[] data, int count)
        {
            lock (writeLock)
            {
                if (IsClosed) return false;
                try
                {
                    Marshal.Copy(data, 0, wr.Buffer, count);
                    bool ok = Native.WriteFile(pipe, wr.Buffer, count, IntPtr.Zero, wr.Overlapped);
                    int err;
                    int n = wr.Finish(pipe, ok, out err);
                    if (n == count) return true;
                    Close(n < 0 ? "pipe write failed (error " + err + ")" : "short pipe write");
                }
                catch (ObjectDisposedException)
                {
                    Close("pipe closed");
                }
                return false;
            }
        }

        /// <summary>Frames from PairVPN to Windows (runs on its own thread).</summary>
        public void ReadLoop()
        {
            bool dropping = false;
            try
            {
                while (!IsClosed)
                {
                    bool ok = Native.ReadFile(pipe, rd.Buffer, rd.BufferSize, IntPtr.Zero, rd.Overlapped);
                    int err;
                    int n = rd.Finish(pipe, ok, out err);
                    if (n < 0)
                    {
                        if (err == Native.ERROR_MORE_DATA)
                        {
                            if (!dropping) Log.Write("Session " + Id + ": oversized message from PairVPN dropped");
                            dropping = true;
                            continue;
                        }
                        Close(err == Native.ERROR_BROKEN_PIPE ? "PairVPN closed the adapter"
                            : err == Native.ERROR_OPERATION_ABORTED ? "cancelled" : "pipe read failed (error " + err + ")");
                        break;
                    }
                    if (dropping) { dropping = false; continue; }
                    if (n == 0)
                    {
                        bridge.OnStopRequested(this);
                        continue;
                    }
                    bridge.WriteToTap(rd.Buffer, n);
                }
            }
            catch (ObjectDisposedException)
            {
                Close("pipe closed");
            }
            catch (Exception e)
            {
                Log.Write("Session " + Id + " error: " + e);
                Close("error");
            }
            finally
            {
                lock (writeLock) { wr.Dispose(); }
                rd.Dispose();
            }
        }

        public void Close(string reason)
        {
            if (Interlocked.Exchange(ref closed, 1) != 0) return;
            try
            {
                Native.CancelIoEx(pipe, IntPtr.Zero);
                Native.DisconnectNamedPipe(pipe);
            }
            catch (ObjectDisposedException) { }
            pipe.Dispose();
            bridge.OnSessionClosed(this, reason);
        }
    }

    internal sealed class Bridge
    {
        public const string PipeName = @"\\.\pipe\pveth";
        public const string AdapterName = "PairVPN";
        private const string NetClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
        private const string NetConnKey = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";
        // SYSTEM and Administrators: full; interactive and authenticated users: read/write.
        private const string PipeSddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)(A;;GRGW;;;AU)";

        private readonly ManualResetEvent stopEvent = new ManualResetEvent(false);
        // TAP-Windows6 cancels reads (STATUS_CANCELLED) while its link is down, so frames are
        // only read while a PairVPN session has brought the link up.
        private readonly ManualResetEvent mediaUpEvent = new ManualResetEvent(false);
        private readonly ManualResetEvent tapResetEvent = new ManualResetEvent(false);
        private volatile bool mediaUp;
        private readonly object curLock = new object();
        private readonly object tapWriteLock = new object();
        private readonly object ioctlLock = new object();
        private volatile Session current;
        private volatile bool stopping;
        private volatile bool tapFailed;
        private volatile SafeFileHandle listening;
        private SafeFileHandle tap;
        private AsyncIo tapWr, ioctlIo;
        private Thread worker;
        private int tapWriteErrors;

        public void Start()
        {
            worker = new Thread(Run);
            worker.IsBackground = true;
            worker.Name = "bridge";
            worker.Start();
        }

        public void Stop()
        {
            stopping = true;
            stopEvent.Set();
            CancelListening();
            Session s;
            lock (curLock) { s = current; current = null; }
            if (s != null) s.Close("bridge stopping");
            SafeFileHandle t = tap;
            if (t != null)
            {
                try { Native.CancelIoEx(t, IntPtr.Zero); } catch (ObjectDisposedException) { }
            }
            if (worker != null) worker.Join(10000);
        }

        private void Run()
        {
            Log.Write("PairVPN ARM64 bridge starting (" + (IntPtr.Size * 8) + "-bit, " +
                      RuntimeInformationArch() + ")");
            while (!stopping)
            {
                Thread reader = null;
                try
                {
                    if (OpenTap())
                    {
                        tapFailed = false;
                        reader = new Thread(TapReadLoop);
                        reader.IsBackground = true;
                        reader.Name = "tap-reader";
                        reader.Start();
                        AcceptLoop();
                    }
                }
                catch (Exception e)
                {
                    Log.Write("Bridge error: " + e);
                }
                Session s;
                lock (curLock) { s = current; current = null; }
                if (s != null) s.Close(stopping ? "bridge stopping" : "adapter reset");
                CloseTap(reader);
                if (stopping || stopEvent.WaitOne(3000)) break;
            }
            Log.Write("PairVPN ARM64 bridge stopped");
        }

        private static string RuntimeInformationArch()
        {
            string a = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            return a ?? "unknown";
        }

        // ------------------------------------------------------------------ TAP adapter

        /// <summary>Find the TAP-Windows6 adapter named "PairVPN" (or one already marked with MacAddress).</summary>
        public static bool FindAdapter(out string guid, out string classSubkey)
        {
            guid = null;
            classSubkey = null;
            string fbGuid = null, fbKey = null;
            using (RegistryKey cls = Registry.LocalMachine.OpenSubKey(NetClassKey))
            {
                if (cls == null) return false;
                foreach (string sub in cls.GetSubKeyNames())
                {
                    if (sub.Length != 4) continue;
                    try
                    {
                        using (RegistryKey k = cls.OpenSubKey(sub))
                        {
                            if (k == null) continue;
                            string cid = k.GetValue("ComponentId") as string;
                            if (cid == null) continue;
                            if (!cid.Equals("tap0901", StringComparison.OrdinalIgnoreCase) &&
                                !cid.Equals(@"root\tap0901", StringComparison.OrdinalIgnoreCase)) continue;
                            string g = k.GetValue("NetCfgInstanceId") as string;
                            if (string.IsNullOrEmpty(g)) continue;
                            string name = null;
                            using (RegistryKey c = Registry.LocalMachine.OpenSubKey(NetConnKey + "\\" + g + "\\Connection"))
                            {
                                if (c != null) name = c.GetValue("Name") as string;
                            }
                            if (AdapterName.Equals(name, StringComparison.OrdinalIgnoreCase))
                            {
                                guid = g;
                                classSubkey = sub;
                                return true;
                            }
                            if (fbGuid == null && k.GetValue("MacAddress") != null)
                            {
                                fbGuid = g;
                                fbKey = sub;
                            }
                        }
                    }
                    catch (System.Security.SecurityException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            guid = fbGuid;
            classSubkey = fbKey;
            return guid != null;
        }

        private bool OpenTap()
        {
            string guid, sub;
            if (!FindAdapter(out guid, out sub))
            {
                Log.WriteOnce("No TAP-Windows6 adapter named \"" + AdapterName + "\" found yet; waiting.");
                return false;
            }
            string path = @"\\.\Global\" + guid + ".tap";
            SafeFileHandle h = Native.CreateFile(path, Native.GENERIC_READ | Native.GENERIC_WRITE, 0, IntPtr.Zero,
                Native.OPEN_EXISTING, Native.FILE_ATTRIBUTE_SYSTEM | Native.FILE_FLAG_OVERLAPPED, IntPtr.Zero);
            if (h.IsInvalid)
            {
                Log.WriteOnce("Cannot open " + path + " (error " + Marshal.GetLastWin32Error() +
                              "). Is the adapter disabled or used by another program?");
                return false;
            }
            tap = h;
            tapWr = new AsyncIo(0);
            ioctlIo = new AsyncIo(64);
            tapWriteErrors = 0;
            tapResetEvent.Reset();

            byte[] ver = Ioctl(Native.TAP_IOCTL_GET_VERSION, null, 12);
            byte[] mac = Ioctl(Native.TAP_IOCTL_GET_MAC, null, 6);
            byte[] mtu = Ioctl(Native.TAP_IOCTL_GET_MTU, null, 4);
            if (mac == null || mac.Length != 6) throw new InvalidOperationException("TAP adapter did not report its MAC address");
            Log.Write(string.Format("Opened TAP adapter {0} (class key {1}): driver {2}, MAC {3}, MTU {4}",
                guid, sub,
                ver != null && ver.Length >= 8 ? BitConverter.ToInt32(ver, 0) + "." + BitConverter.ToInt32(ver, 4) : "?",
                FormatMac(mac, 0),
                mtu != null && mtu.Length >= 4 ? BitConverter.ToInt32(mtu, 0).ToString() : "?"));
            SyncMacRegistry(sub, mac);
            SetMedia(false);
            return true;
        }

        /// <summary>PairVPN reads the adapter MAC from REG_BINARY "MacAddress" in the adapter's class key.</summary>
        private static void SyncMacRegistry(string ourSub, byte[] mac)
        {
            try
            {
                using (RegistryKey cls = Registry.LocalMachine.OpenSubKey(NetClassKey))
                {
                    foreach (string sub in cls.GetSubKeyNames())
                    {
                        if (sub.Length != 4) continue;
                        try
                        {
                            using (RegistryKey k = cls.OpenSubKey(sub, true))
                            {
                                if (k == null) continue;
                                string cid = k.GetValue("ComponentId") as string;
                                if (sub == ourSub)
                                {
                                    byte[] cur = k.GetValue("MacAddress") as byte[];
                                    if (cur == null || !SameBytes(cur, mac))
                                    {
                                        k.SetValue("MacAddress", mac, RegistryValueKind.Binary);
                                        Log.Write("Set MacAddress for PairVPN to " + FormatMac(mac, 0));
                                    }
                                }
                                else if (cid != null && cid.IndexOf("tap0901", StringComparison.OrdinalIgnoreCase) >= 0 &&
                                         k.GetValue("MacAddress") != null)
                                {
                                    // Only our adapter may carry the marker PairVPN looks for.
                                    k.DeleteValue("MacAddress", false);
                                    Log.Write("Removed stale MacAddress marker from adapter key " + sub);
                                }
                            }
                        }
                        catch (System.Security.SecurityException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
            }
            catch (Exception e)
            {
                Log.Write("Could not update MacAddress registry value: " + e.Message);
            }
        }

        private static bool SameBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        public static string FormatMac(byte[] b, int off)
        {
            return string.Format("{0:x2}:{1:x2}:{2:x2}:{3:x2}:{4:x2}:{5:x2}", b[off], b[off + 1], b[off + 2], b[off + 3], b[off + 4], b[off + 5]);
        }

        private byte[] Ioctl(uint code, byte[] input, int outLen)
        {
            lock (ioctlLock)
            {
                SafeFileHandle t = tap;
                if (t == null) return null;
                IntPtr inBuf = ioctlIo.Buffer;
                IntPtr outBuf = IntPtr.Add(ioctlIo.Buffer, 32);
                int inLen = 0;
                if (input != null)
                {
                    Marshal.Copy(input, 0, inBuf, input.Length);
                    inLen = input.Length;
                }
                try
                {
                    bool ok = Native.DeviceIoControl(t, code, inLen > 0 ? inBuf : IntPtr.Zero, inLen,
                        outLen > 0 ? outBuf : IntPtr.Zero, outLen, IntPtr.Zero, ioctlIo.Overlapped);
                    int err;
                    int n = ioctlIo.Finish(t, ok, out err);
                    if (n < 0)
                    {
                        Log.Write(string.Format("TAP ioctl 0x{0:X} failed (error {1})", code, err));
                        return null;
                    }
                    byte[] r = new byte[Math.Max(0, Math.Min(n, outLen))];
                    Marshal.Copy(outBuf, r, 0, r.Length);
                    return r;
                }
                catch (ObjectDisposedException)
                {
                    return null;
                }
            }
        }

        private void SetMedia(bool connected)
        {
            if (!connected)
            {
                mediaUp = false;
                mediaUpEvent.Reset();
            }
            byte[] r = Ioctl(Native.TAP_IOCTL_SET_MEDIA_STATUS, BitConverter.GetBytes(connected ? 1 : 0), 4);
            if (r == null) return;
            if (connected)
            {
                mediaUp = true;
                mediaUpEvent.Set();
            }
            Log.Write("TAP adapter link " + (connected ? "up" : "down"));
        }

        private void CloseTap(Thread reader)
        {
            SafeFileHandle t = tap;
            if (t == null) return;
            SetMedia(false);
            tapResetEvent.Set();
            try { Native.CancelIoEx(t, IntPtr.Zero); } catch (ObjectDisposedException) { }
            if (reader != null) reader.Join(5000);
            lock (tapWriteLock)
            {
                lock (ioctlLock)
                {
                    tap = null;
                    t.Dispose();
                    if (tapWr != null) tapWr.Dispose();
                    if (ioctlIo != null) ioctlIo.Dispose();
                    tapWr = null;
                    ioctlIo = null;
                }
            }
        }

        /// <summary>Frames from Windows (TAP) to PairVPN.</summary>
        private void TapReadLoop()
        {
            SafeFileHandle t = tap;
            AsyncIo rd = new AsyncIo(65536);
            byte[] rec = new byte[65536 + 4];
            WaitHandle[] idleWaits = { stopEvent, tapResetEvent, mediaUpEvent };
            int aborted = 0;
            try
            {
                while (!stopping)
                {
                    if (!mediaUp)
                    {
                        if (WaitHandle.WaitAny(idleWaits) != 2) break;   // stop or adapter reset
                        continue;
                    }
                    bool ok = Native.ReadFile(t, rd.Buffer, rd.BufferSize, IntPtr.Zero, rd.Overlapped);
                    int err;
                    int n = rd.Finish(t, ok, out err);
                    if (n < 0)
                    {
                        if (stopping || tapResetEvent.WaitOne(0)) break;
                        if (err == Native.ERROR_OPERATION_ABORTED)
                        {
                            // Normal when the link has just gone down; wait for the next session.
                            if (!mediaUp) continue;
                            if (++aborted < 200)
                            {
                                Thread.Sleep(10);
                                continue;
                            }
                        }
                        Log.Write("TAP read failed (error " + err + "); reopening the adapter");
                        tapFailed = true;
                        CancelListening();
                        break;
                    }
                    aborted = 0;
                    if (n < 14) continue;
                    // PairVPN only handles IPv4 and ARP (it silently drops IPv6 and logs anything else).
                    int etherType = (Marshal.ReadByte(rd.Buffer, 12) << 8) | Marshal.ReadByte(rd.Buffer, 13);
                    if (etherType != 0x0800 && etherType != 0x0806) continue;
                    Session s = current;
                    if (s == null) continue;
                    rec[0] = (byte)n;
                    rec[1] = (byte)(n >> 8);
                    rec[2] = (byte)(n >> 16);
                    rec[3] = (byte)(n >> 24);
                    Marshal.Copy(rd.Buffer, rec, 4, n);
                    s.Send(rec, n + 4);
                }
            }
            catch (Exception e)
            {
                if (!stopping)
                {
                    Log.Write("TAP reader error: " + e.Message);
                    tapFailed = true;
                    CancelListening();
                }
            }
            finally
            {
                rd.Dispose();
            }
        }

        /// <summary>Frames from PairVPN to Windows.</summary>
        internal void WriteToTap(IntPtr buf, int n)
        {
            if (n < 14) return;
            lock (tapWriteLock)
            {
                SafeFileHandle t = tap;
                if (t == null || tapWr == null) return;
                try
                {
                    bool ok = Native.WriteFile(t, buf, n, IntPtr.Zero, tapWr.Overlapped);
                    int err;
                    if (tapWr.Finish(t, ok, out err) < 0 && tapWriteErrors++ < 20)
                        Log.Write("TAP write failed (error " + err + ")");
                }
                catch (ObjectDisposedException) { }
            }
        }

        // ------------------------------------------------------------------ pipe server

        private void CancelListening()
        {
            SafeFileHandle l = listening;
            if (l == null) return;
            try { Native.CancelIoEx(l, IntPtr.Zero); } catch (ObjectDisposedException) { }
        }

        private void AcceptLoop()
        {
            IntPtr sd;
            if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(PipeSddl, 1, out sd, IntPtr.Zero))
                throw new Win32Exception();
            AsyncIo acc = new AsyncIo(0);
            try
            {
                Log.Write("Waiting for PairVPN on " + PipeName);
                while (!stopping && !tapFailed)
                {
                    Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
                    sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
                    sa.lpSecurityDescriptor = sd;
                    // Small outbound quota: a PairVPN read (32 KB) then always receives whole records.
                    SafeFileHandle p = Native.CreateNamedPipe(PipeName,
                        Native.PIPE_ACCESS_DUPLEX | Native.FILE_FLAG_OVERLAPPED,
                        Native.PIPE_TYPE_MESSAGE | Native.PIPE_READMODE_MESSAGE | Native.PIPE_REJECT_REMOTE_CLIENTS,
                        Native.PIPE_UNLIMITED_INSTANCES, 8192, 65536, 0, ref sa);
                    if (p.IsInvalid)
                    {
                        Log.Write("CreateNamedPipe failed (error " + Marshal.GetLastWin32Error() + ")");
                        if (stopEvent.WaitOne(2000)) break;
                        continue;
                    }
                    listening = p;
                    bool connected;
                    int err = 0;
                    if (stopping || tapFailed)
                    {
                        connected = false;
                    }
                    else
                    {
                        bool ok = Native.ConnectNamedPipe(p, acc.Overlapped);
                        err = ok ? 0 : Marshal.GetLastWin32Error();
                        connected = ok || err == Native.ERROR_PIPE_CONNECTED;
                        if (!connected && err == Native.ERROR_IO_PENDING)
                        {
                            int dummy;
                            connected = Native.GetOverlappedResult(p, acc.Overlapped, out dummy, true);
                            if (!connected) err = Marshal.GetLastWin32Error();
                        }
                    }
                    listening = null;
                    if (!connected || stopping || tapFailed)
                    {
                        if (!stopping && !tapFailed) Log.Write("ConnectNamedPipe failed (error " + err + ")");
                        p.Dispose();
                        continue;
                    }
                    StartSession(p);
                }
            }
            finally
            {
                acc.Dispose();
                Native.LocalFree(sd);
            }
        }

        private void StartSession(SafeFileHandle p)
        {
            Session s = new Session(p, this);
            Session old;
            lock (curLock) { old = current; current = null; }
            if (old != null) old.Close("replaced by a new PairVPN connection");
            Log.Write("PairVPN opened the adapter (session " + s.Id + ")");
            // pveth answered PairVPN's first request ("adapter ready") with a 4-byte value.
            if (!s.Send(new byte[] { 1, 0, 0, 0 }, 4)) return;
            lock (curLock) { current = s; }
            SetMedia(true);
            Thread t = new Thread(s.ReadLoop);
            t.IsBackground = true;
            t.Name = "session-" + s.Id;
            t.Start();
        }

        internal void OnSessionClosed(Session s, string reason)
        {
            bool wasCurrent;
            lock (curLock)
            {
                wasCurrent = current == s;
                if (wasCurrent) current = null;
            }
            Log.Write("Session " + s.Id + " ended: " + reason);
            if (wasCurrent && !stopping) SetMedia(false);
        }

        internal void OnStopRequested(Session s)
        {
            Log.Write("PairVPN stopped the network (session " + s.Id + ")");
            if (current == s) SetMedia(false);
        }
    }

    internal sealed class BridgeService : ServiceBase
    {
        public const string Name = "PairVPNArm64Bridge";
        private Bridge bridge;

        public BridgeService()
        {
            ServiceName = Name;
            CanStop = true;
            CanShutdown = true;
            AutoLog = false;
        }

        protected override void OnStart(string[] args)
        {
            bridge = new Bridge();
            bridge.Start();
        }

        protected override void OnStop()
        {
            if (bridge != null) bridge.Stop();
        }

        protected override void OnShutdown()
        {
            OnStop();
        }
    }

    /// <summary>Test client: behaves like the patched PairVPN.exe and reports what arrives.</summary>
    internal static class Probe
    {
        public static int Run(int seconds, bool sendTestFrame)
        {
            SafeFileHandle h = Native.CreateFile(Bridge.PipeName, Native.MAXIMUM_ALLOWED, 0, IntPtr.Zero, Native.OPEN_EXISTING,
                Native.FILE_FLAG_OVERLAPPED | Native.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (h.IsInvalid)
            {
                Console.WriteLine("FAIL: cannot open " + Bridge.PipeName + " (error " + Marshal.GetLastWin32Error() + ")");
                return 2;
            }
            using (h)
            using (AsyncIo io = new AsyncIo(0x8000))
            using (AsyncIo wio = new AsyncIo(64))
            {
                int err;
                bool ok = Native.ReadFile(h, io.Buffer, 4, IntPtr.Zero, io.Overlapped);
                int n = io.Finish(h, ok, out err);
                Console.WriteLine(n == 4 ? "OK: adapter-ready reply received" : "FAIL: ready read returned " + n + " (error " + err + ")");
                if (n != 4) return 3;

                if (sendTestFrame)
                {
                    // Broadcast ARP request "who-has 10.1.119.1 tell 10.1.119.100" from a made-up gateway MAC.
                    byte[] f = new byte[42];
                    for (int i = 0; i < 6; i++) f[i] = 0xff;
                    byte[] gw = { 0x02, 0x50, 0x56, 0x00, 0x00, 0x01 };
                    Array.Copy(gw, 0, f, 6, 6);
                    f[12] = 0x08; f[13] = 0x06;            // ARP
                    f[14] = 0; f[15] = 1; f[16] = 8; f[17] = 0; f[18] = 6; f[19] = 4; f[20] = 0; f[21] = 1;
                    Array.Copy(gw, 0, f, 22, 6);
                    f[28] = 10; f[29] = 1; f[30] = 119; f[31] = 100;
                    f[38] = 10; f[39] = 1; f[40] = 119; f[41] = 1;
                    Marshal.Copy(f, 0, wio.Buffer, f.Length);
                    ok = Native.WriteFile(h, wio.Buffer, f.Length, IntPtr.Zero, wio.Overlapped);
                    n = wio.Finish(h, ok, out err);
                    Console.WriteLine(n == 42 ? "OK: wrote a 42-byte test frame toward Windows" : "FAIL: test frame write (error " + err + ")");
                }

                DateTime end = DateTime.UtcNow.AddSeconds(seconds);
                int records = 0, reads = 0;
                byte[] adapterMac = null;
                byte[] adapterIp = null;
                bool arpSent = false, arpAnswered = false;
                byte[] fakeMac = { 0x02, 0x50, 0x56, 0x00, 0x00, 0x02 };
                while (DateTime.UtcNow < end)
                {
                    ok = Native.ReadFile(h, io.Buffer, 0x8000, IntPtr.Zero, io.Overlapped);
                    if (!ok && Marshal.GetLastWin32Error() != Native.ERROR_IO_PENDING)
                    {
                        Console.WriteLine("FAIL: read error " + Marshal.GetLastWin32Error());
                        break;
                    }
                    int left = (int)Math.Max(0, (end - DateTime.UtcNow).TotalMilliseconds);
                    if (Native.WaitForSingleObject(io.Event, (uint)left) != Native.WAIT_OBJECT_0)
                    {
                        Native.CancelIoEx(h, io.Overlapped);
                        int dummy;
                        Native.GetOverlappedResult(h, io.Overlapped, out dummy, true);
                        break;
                    }
                    if (!Native.GetOverlappedResult(h, io.Overlapped, out n, false))
                    {
                        Console.WriteLine("FAIL: read completion error " + Marshal.GetLastWin32Error());
                        break;
                    }
                    reads++;
                    byte[] b = new byte[n];
                    Marshal.Copy(io.Buffer, b, 0, n);
                    int off = 0;
                    while (n - off > 4)
                    {
                        int len = BitConverter.ToInt32(b, off);
                        off += 4;
                        if (len <= 0 || len > n - off)
                        {
                            Console.WriteLine("FAIL: malformed record (len " + len + ")");
                            break;
                        }
                        records++;
                        Console.WriteLine("  frame " + records + ": " + Describe(b, off, len));
                        int et = len >= 14 ? (b[off + 12] << 8) | b[off + 13] : 0;
                        // Learn the adapter's MAC/IP from what Windows sends.
                        if (et == 0x0800 && len >= 34 && adapterIp == null && (b[off + 26] | b[off + 27] | b[off + 28] | b[off + 29]) != 0)
                        {
                            adapterMac = new byte[6];
                            Array.Copy(b, off + 6, adapterMac, 0, 6);
                            adapterIp = new byte[4];
                            Array.Copy(b, off + 26, adapterIp, 0, 4);
                        }
                        // Windows' ARP reply to our probe proves frames written into the adapter are delivered.
                        if (et == 0x0806 && len >= 42 && b[off + 21] == 2 && b[off] == fakeMac[0] && b[off + 5] == fakeMac[5])
                            arpAnswered = true;
                        off += len;
                    }
                    if (sendTestFrame && !arpSent && adapterIp != null)
                    {
                        byte[] f = new byte[42];
                        for (int i = 0; i < 6; i++) f[i] = 0xff;
                        Array.Copy(fakeMac, 0, f, 6, 6);
                        f[12] = 0x08; f[13] = 0x06;
                        f[14] = 0; f[15] = 1; f[16] = 8; f[17] = 0; f[18] = 6; f[19] = 4; f[20] = 0; f[21] = 1;
                        Array.Copy(fakeMac, 0, f, 22, 6);
                        f[28] = adapterIp[0]; f[29] = adapterIp[1]; f[30] = 1; f[31] = 1;      // sender: same /16
                        Array.Copy(adapterIp, 0, f, 38, 4);                                  // target: Windows
                        Marshal.Copy(f, 0, wio.Buffer, f.Length);
                        ok = Native.WriteFile(h, wio.Buffer, f.Length, IntPtr.Zero, wio.Overlapped);
                        n = wio.Finish(h, ok, out err);
                        arpSent = true;
                        Console.WriteLine(string.Format("  -> sent ARP who-has {0}.{1}.{2}.{3} (Windows) tell {0}.{1}.1.1 from {4}",
                            adapterIp[0], adapterIp[1], adapterIp[2], adapterIp[3], Bridge.FormatMac(fakeMac, 0)));
                    }
                }
                Console.WriteLine(string.Format("Summary: {0} read(s), {1} frame record(s) in {2}s", reads, records, seconds));
                if (sendTestFrame)
                    Console.WriteLine(arpAnswered ? "OK: Windows answered the injected ARP request (PairVPN -> Windows path works)"
                        : arpSent ? "FAIL: no ARP reply from Windows to the injected request" : "SKIP: adapter IP not seen, ARP test not run");
                // pveth "stop" = zero-length message
                ok = Native.WriteFile(h, wio.Buffer, 0, IntPtr.Zero, wio.Overlapped);
                n = wio.Finish(h, ok, out err);
                Console.WriteLine(n == 0 && err == 0 ? "OK: stop message sent" : "FAIL: stop message (error " + err + ")");
                return records > 0 ? 0 : 4;
            }
        }

        private static string Describe(byte[] b, int off, int len)
        {
            if (len < 14) return len + " bytes (runt)";
            string s = string.Format("{0} bytes {1} -> {2}", len, Bridge.FormatMac(b, off + 6), Bridge.FormatMac(b, off));
            int et = (b[off + 12] << 8) | b[off + 13];
            if (et == 0x0806 && len >= 42)
                return s + string.Format(" ARP {0} {1}.{2}.{3}.{4} -> {5}.{6}.{7}.{8}", b[off + 21] == 1 ? "request" : "reply",
                    b[off + 28], b[off + 29], b[off + 30], b[off + 31], b[off + 38], b[off + 39], b[off + 40], b[off + 41]);
            if (et == 0x0800 && len >= 34)
            {
                int ihl = (b[off + 14] & 0xF) * 4;
                int proto = b[off + 23];
                string ip = string.Format(" IPv4 {0}.{1}.{2}.{3} -> {4}.{5}.{6}.{7}", b[off + 26], b[off + 27], b[off + 28], b[off + 29],
                    b[off + 30], b[off + 31], b[off + 32], b[off + 33]);
                if (proto == 17 && len >= 14 + ihl + 8)
                {
                    int sp = (b[off + 14 + ihl] << 8) | b[off + 15 + ihl];
                    int dp = (b[off + 16 + ihl] << 8) | b[off + 17 + ihl];
                    string tag = (sp == 68 && dp == 67) ? " (DHCP from Windows)" : "";
                    return s + ip + string.Format(" UDP {0}->{1}{2}", sp, dp, tag);
                }
                return s + ip + " proto " + proto;
            }
            return s + string.Format(" ethertype 0x{0:x4}", et);
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "";
            if (mode == "probe")
            {
                int secs = 15;
                if (args.Length > 1) int.TryParse(args[1], out secs);
                bool send = args.Length > 2 && args[2] == "sendtest";
                Log.ToConsole = true;
                return Probe.Run(secs, send);
            }

            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PairVPN-ARM64");
            try { Directory.CreateDirectory(dir); } catch (Exception) { }
            Log.FilePath = Path.Combine(dir, "bridge.log");

            if (mode == "console")
            {
                Log.ToConsole = true;
                Bridge b = new Bridge();
                b.Start();
                Console.WriteLine("Bridge running. Press Enter to stop.");
                Console.ReadLine();
                b.Stop();
                return 0;
            }
            if (mode == "find")
            {
                string g, sub;
                bool found = Bridge.FindAdapter(out g, out sub);
                Console.WriteLine(found ? "Adapter " + g + " (class key " + sub + ")" : "No PairVPN TAP adapter found");
                return found ? 0 : 1;
            }
            ServiceBase.Run(new BridgeService());
            return 0;
        }
    }
}
