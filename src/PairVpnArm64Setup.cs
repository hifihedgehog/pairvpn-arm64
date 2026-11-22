// PairVPN 1.9.16 for Windows on ARM - single-file setup (unofficial).
//
// Does everything end to end on an ARM64 PC:
//   1. checks the Microsoft Visual C++ runtime PairVPN's x64 route service needs (offers to get it);
//   2. installs OpenVPN's Microsoft-signed TAP-Windows6 9.27.0 ARM64 driver;
//   3. creates the network adapter "PairVPN" (hardware id tap0901) that stands in for pveth;
//   4. installs PairVPN.exe (patched to use \\.\pipe\pveth), PairVPN's pvservice.exe and the
//      PairVPN ARM64 Bridge into C:\Program Files\PairVPN;
//   5. registers and starts both services, adds a Start menu shortcut and an Apps & features entry;
//   6. self-tests the PairVPN <-> bridge <-> adapter path.
// Command line:  (none) GUI install | /quiet | /uninstall [/quiet] | /nolaunch | /launch | /autoclose
//
// Build: see build.ps1 (csc from .NET Framework 4.8.1, payload embedded as resources).

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("PairVPN 1.9.16 for Windows on ARM - Setup")]
[assembly: AssemblyDescription("Unofficial ARM64 installer for PairVPN 1.9.16 (TAP-Windows6 adapter + bridge service)")]
[assembly: AssemblyProduct("PairVPN for Windows on ARM (unofficial)")]
[assembly: AssemblyCopyright("PairVPN (c) Mobile Co.; TAP-Windows6 (c) OpenVPN Inc. (GPLv2); ARM64 adaptation unofficial")]
[assembly: AssemblyVersion("1.9.16.1")]
[assembly: AssemblyFileVersion("1.9.16.1")]
[assembly: AssemblyInformationalVersion("1.9.16-arm64.1")]

namespace PairVpnArm64Setup
{
    internal sealed class SetupException : Exception
    {
        public SetupException(string message) : base(message) { }
    }

    internal sealed class Options
    {
        public bool Quiet, Uninstall, NoLaunch, Launch, AutoClose, Relocated, SkipSelfTest, TestVcRedist;

        public static Options Parse(string[] args)
        {
            Options o = new Options();
            foreach (string raw in args)
            {
                string a = raw.Trim().TrimStart('/', '-').ToLowerInvariant();
                switch (a)
                {
                    case "quiet": case "q": case "s": case "silent": case "verysilent": o.Quiet = true; break;
                    case "uninstall": case "u": case "x": o.Uninstall = true; break;
                    case "nolaunch": o.NoLaunch = true; break;
                    case "launch": o.Launch = true; break;
                    case "autoclose": o.AutoClose = true; break;
                    case "relocated": o.Relocated = true; break;
                    case "noselftest": o.SkipSelfTest = true; break;
                    case "test-vcredist": o.TestVcRedist = true; o.Quiet = true; break;
                }
            }
            return o;
        }
    }

    internal sealed class Logger
    {
        private readonly object sync = new object();
        public readonly string LogPath;
        public Action<string> Sink;

        public Logger(string path)
        {
            LogPath = path;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.AppendAllText(path, Environment.NewLine + "==== " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " +
                                         Setup.VersionText + " ====" + Environment.NewLine);
            }
            catch (Exception) { }
        }

        public void Write(string msg)
        {
            lock (sync)
            {
                try { File.AppendAllText(LogPath, DateTime.Now.ToString("HH:mm:ss") + "  " + msg + Environment.NewLine); }
                catch (Exception) { }
            }
            Action<string> s = Sink;
            if (s != null) s(msg);
        }
    }

    internal static class Native
    {
        public const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        public const uint SERVICE_ALL_ACCESS = 0xF01FF;
        public const uint SERVICE_WIN32_OWN_PROCESS = 0x10;
        public const uint SERVICE_AUTO_START = 2;
        public const uint SERVICE_ERROR_NORMAL = 1;
        public const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        public const uint DELETE = 0x10000;
        public const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_FAILURE_ACTIONS
        {
            public int dwResetPeriod;
            public IntPtr lpRebootMsg;
            public IntPtr lpCommand;
            public int cActions;
            public IntPtr lpsaActions;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenSCManager(string machine, string database, uint access);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenService(IntPtr scm, string name, uint access);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateService(IntPtr scm, string name, string displayName, uint access, uint type, uint start,
            uint errorControl, string binaryPath, string loadOrderGroup, IntPtr tagId, string dependencies, string account, string password);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ChangeServiceConfig(IntPtr svc, uint type, uint start, uint errorControl, string binaryPath,
            string loadOrderGroup, IntPtr tagId, string dependencies, string account, string password, string displayName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ChangeServiceConfig2(IntPtr svc, uint level, IntPtr info);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DeleteService(IntPtr svc);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WaitNamedPipe(string name, uint timeout);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(string existing, string newName, uint flags);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        public static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
    }

    internal sealed class TapAdapter
    {
        public string Guid, ClassKey, Name, PnpId;
    }

    internal static class Setup
    {
        public const string VersionText = "PairVPN 1.9.16 ARM64 setup 1.9.16-arm64.1";
        public const string AdapterName = "PairVPN";
        public const string BridgeService = "PairVPNArm64Bridge";
        public const string RouteService = "PairVPN Client Adapter";
        public const string SetupFileName = "PairVPN-ARM64-Setup.exe";
        public const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PairVPN-ARM64";
        private const string NetClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
        private const string NetConnKey = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";
        private static readonly string[] AppFiles = { "PairVPN.exe", "pvservice.exe", "PairVPN-ARM64-Bridge.exe" };
        private static readonly string[] TapFiles = { "OemVista.inf", "tap0901.sys", "tap0901.cat", "devcon.exe" };
        private static readonly string[] VcDlls = { "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll" };
        private static readonly string[] VcRedistUrls =
        {
            "https://aka.ms/vc14/vc_redist.arm64.exe",
            "https://aka.ms/vs/17/release/vc_redist.arm64.exe"
        };

        public static string InstallDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PairVPN"); }
        }

        public static string DataDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PairVPN-ARM64"); }
        }

        private static string StartMenuDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "PairVPN"); }
        }

        private static string SystemDir
        {
            get { return Environment.GetFolderPath(Environment.SpecialFolder.System); }
        }

        public static string SelfPath
        {
            get { return Assembly.GetExecutingAssembly().Location; }
        }

        // ------------------------------------------------------------------ install

        public static void Install(Logger log, Options opt, Func<string, bool> confirm)
        {
            log.Write(VersionText);
            CheckPlatform();
            if (Directory.Exists(InstallDir) || ServiceExists(BridgeService))
                log.Write("An existing installation was found; it will be repaired/updated.");

            string tmp = ExtractPayload();
            try
            {
                Step(log, "Checking the Microsoft Visual C++ runtime (used by PairVPN's route service)");
                EnsureVcRuntime(log, tmp, confirm);

                Step(log, "Closing PairVPN and stopping its services");
                StopEverything(log);

                Step(log, "Installing the TAP-Windows6 ARM64 driver");
                InstallDriver(log, Path.Combine(tmp, "tap"));

                Step(log, "Setting up the \"" + AdapterName + "\" network adapter");
                EnsureAdapter(log, Path.Combine(tmp, "tap"));

                Step(log, "Copying program files to " + InstallDir);
                CopyFiles(log, tmp);

                Step(log, "Registering services");
                EnsureService(log, BridgeService, "PairVPN ARM64 Bridge",
                    "Connects PairVPN to its ARM64 TAP-Windows6 network adapter (\"" + AdapterName + "\").",
                    Path.Combine(InstallDir, "PairVPN-ARM64-Bridge.exe"), true);
                EnsureService(log, RouteService, RouteService,
                    "PairVPN's helper that adds and removes the VPN routes.",
                    Path.Combine(InstallDir, "pvservice.exe"), false);

                Step(log, "Adding the Start menu shortcut and the Apps & features entry");
                CreateShortcut(log);
                RegisterUninstall(log);

                Step(log, "Starting services");
                StartService(log, BridgeService);
                StartService(log, RouteService);
                WaitForBridge(log);

                if (!opt.SkipSelfTest)
                {
                    Step(log, "Self-test: PairVPN pipe <-> bridge <-> adapter");
                    SelfTest(log);
                }
                log.Write("");
                log.Write("INSTALL COMPLETE - open PairVPN from the Start menu and connect to your phone as usual.");
            }
            finally
            {
                TryDeleteDir(tmp);
            }
        }

        private static void Step(Logger log, string text)
        {
            log.Write("");
            log.Write("== " + text);
        }

        private static void CheckPlatform()
        {
            string arch = null;
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
            {
                if (k != null) arch = k.GetValue("PROCESSOR_ARCHITECTURE") as string;
            }
            if (!"ARM64".Equals(arch, StringComparison.OrdinalIgnoreCase))
                throw new SetupException("This installer is only for Windows on ARM (ARM64) PCs. This PC is " + (arch ?? "unknown") +
                                         "; use the official PairVPN installer instead.");
        }

        private static string ExtractPayload()
        {
            string dir = Path.Combine(Path.GetTempPath(), "PairVPN-ARM64-Setup-" + System.Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(Path.Combine(dir, "tap"));
            foreach (string f in AppFiles) File.WriteAllBytes(Path.Combine(dir, f), ReadResource(f));
            foreach (string f in TapFiles) File.WriteAllBytes(Path.Combine(dir, "tap", f), ReadResource("tap." + f));
            return dir;
        }

        private static byte[] ReadResource(string name)
        {
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                if (s == null) throw new SetupException("This setup file is damaged (missing " + name + ").");
                using (MemoryStream m = new MemoryStream())
                {
                    s.CopyTo(m);
                    return m.ToArray();
                }
            }
        }

        // ---- Visual C++ runtime (pvservice.exe is x64 and imports MSVCP140/VCRUNTIME140)

        private static bool VcRuntimeUsable(out string detail)
        {
            foreach (string dll in VcDlls)
            {
                string p = Path.Combine(SystemDir, dll);
                if (!File.Exists(p)) { detail = dll + " not found"; return false; }
                if (!LoadableByX64(p)) { detail = dll + " is an ARM64-only build"; return false; }
            }
            detail = "version " + FileVersionInfo.GetVersionInfo(Path.Combine(SystemDir, "msvcp140.dll")).FileVersion;
            return true;
        }

        /// <summary>True for x64 images and ARM64X/ARM64EC hybrids (which x64-emulated code can load).</summary>
        private static bool LoadableByX64(string path)
        {
            byte[] d = File.ReadAllBytes(path);
            int pe = BitConverter.ToInt32(d, 0x3C);
            ushort machine = BitConverter.ToUInt16(d, pe + 4);
            if (machine == 0x8664) return true;
            if (machine != 0xAA64) return false;
            int nsec = BitConverter.ToUInt16(d, pe + 6);
            int optsz = BitConverter.ToUInt16(d, pe + 20);
            int opt = pe + 24;
            if (BitConverter.ToUInt16(d, opt) != 0x20b) return false;
            uint lcRva = BitConverter.ToUInt32(d, opt + 112 + 10 * 8);
            if (lcRva == 0) return false;
            for (int i = 0; i < nsec; i++)
            {
                int s = opt + optsz + 40 * i;
                uint vsize = BitConverter.ToUInt32(d, s + 8), va = BitConverter.ToUInt32(d, s + 12);
                uint rsize = BitConverter.ToUInt32(d, s + 16), rptr = BitConverter.ToUInt32(d, s + 20);
                if (lcRva >= va && lcRva < va + Math.Max(vsize, rsize))
                {
                    int off = (int)(rptr + (lcRva - va));
                    uint size = BitConverter.ToUInt32(d, off);
                    if (size < 0xD0) return false;
                    return BitConverter.ToUInt64(d, off + 0xC8) != 0;   // CHPEMetadataPointer
                }
            }
            return false;
        }

        private static void EnsureVcRuntime(Logger log, string tmp, Func<string, bool> confirm)
        {
            string detail;
            if (VcRuntimeUsable(out detail))
            {
                log.Write("  OK (" + detail + ")");
                return;
            }
            log.Write("  Not usable: " + detail);
            if (!confirm("PairVPN's route service needs the Microsoft Visual C++ Runtime for ARM64, which is not installed (" + detail +
                         ").\n\nDownload it from Microsoft (about 12 MB) and install it now?"))
                throw new SetupException("The Microsoft Visual C++ Runtime (ARM64) is required. Install it from " + VcRedistUrls[0] +
                                         " and run setup again.");
            string file = Path.Combine(tmp, "vc_redist.arm64.exe");
            DownloadVcRedist(log, file);
            log.Write("  Installing the Visual C++ Runtime...");
            string output;
            int rc = Run(file, "/install /quiet /norestart", tmp, 900000, out output);
            if (rc != 0 && rc != 3010 && rc != 1638)
                throw new SetupException("The Visual C++ Runtime installer failed (exit code " + rc + ").");
            if (!VcRuntimeUsable(out detail))
                throw new SetupException("The Visual C++ Runtime is still not usable after installing it (" + detail + ").");
            log.Write("  Installed (" + detail + ")" + (rc == 3010 ? "; Windows asks for a restart later." : ""));
        }

        private static void DownloadVcRedist(Logger log, string file)
        {
            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch (Exception) { }
            Exception last = null;
            foreach (string url in VcRedistUrls)
            {
                try
                {
                    log.Write("  Downloading " + url);
                    using (WebClient wc = new WebClient())
                    {
                        wc.Headers[HttpRequestHeader.UserAgent] = "PairVPN-ARM64-Setup";
                        wc.DownloadFile(url, file);
                    }
                    string signer = VerifySignature(file);
                    if (signer.IndexOf("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase) < 0)
                        throw new SetupException("unexpected signer: " + signer);
                    log.Write("  Microsoft signature verified (" + new FileInfo(file).Length.ToString("N0") + " bytes)");
                    return;
                }
                catch (Exception e)
                {
                    last = e;
                    log.Write("  Failed: " + e.Message);
                    TryDeleteFile(file);
                }
            }
            throw new SetupException("Could not download the Visual C++ Runtime: " + (last != null ? last.Message : "unknown error"));
        }

        /// <summary>Authenticode check with WinVerifyTrust; returns the signer's subject.</summary>
        private static string VerifySignature(string file)
        {
            Native.WINTRUST_FILE_INFO fi = new Native.WINTRUST_FILE_INFO();
            fi.cbStruct = (uint)Marshal.SizeOf(typeof(Native.WINTRUST_FILE_INFO));
            fi.pcwszFilePath = file;
            IntPtr pfi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fi, pfi, false);
            Native.WINTRUST_DATA wd = new Native.WINTRUST_DATA();
            wd.cbStruct = (uint)Marshal.SizeOf(typeof(Native.WINTRUST_DATA));
            wd.dwUIChoice = 2;          // WTD_UI_NONE
            wd.fdwRevocationChecks = 0; // WTD_REVOKE_NONE
            wd.dwUnionChoice = 1;       // WTD_CHOICE_FILE
            wd.pFile = pfi;
            wd.dwStateAction = 1;       // WTD_STATEACTION_VERIFY
            Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");   // WINTRUST_ACTION_GENERIC_VERIFY_V2
            int rc;
            try
            {
                rc = Native.WinVerifyTrust(IntPtr.Zero, ref action, ref wd);
                wd.dwStateAction = 2;   // WTD_STATEACTION_CLOSE
                Native.WinVerifyTrust(IntPtr.Zero, ref action, ref wd);
            }
            finally
            {
                Marshal.DestroyStructure(pfi, typeof(Native.WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pfi);
            }
            if (rc != 0) throw new SetupException(string.Format("the file's digital signature is not valid (0x{0:X8})", rc));
            return X509Certificate.CreateFromSignedFile(file).Subject;
        }

        public static int TestVcRedistDownload(Logger log)
        {
            string tmp = Path.Combine(Path.GetTempPath(), "PairVPN-ARM64-vctest-" + System.Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tmp);
            try
            {
                string detail;
                log.Write("VC++ runtime currently usable: " + VcRuntimeUsable(out detail) + " (" + detail + ")");
                DownloadVcRedist(log, Path.Combine(tmp, "vc_redist.arm64.exe"));
                log.Write("VCREDIST DOWNLOAD TEST PASSED");
                return 0;
            }
            catch (Exception e)
            {
                log.Write("VCREDIST DOWNLOAD TEST FAILED: " + e.Message);
                return 1;
            }
            finally
            {
                TryDeleteDir(tmp);
            }
        }

        // ---- processes and services

        private static void StopEverything(Logger log)
        {
            foreach (Process p in Process.GetProcessesByName("PairVPN"))
            {
                try
                {
                    log.Write("  Closing PairVPN (process " + p.Id + ")");
                    p.Kill();
                    p.WaitForExit(10000);
                }
                catch (Exception e)
                {
                    log.Write("  Could not close PairVPN: " + e.Message);
                }
            }
            StopService(log, BridgeService);
            StopService(log, RouteService);
        }

        private static bool ServiceExists(string name)
        {
            try
            {
                using (ServiceController sc = new ServiceController(name))
                {
                    ServiceControllerStatus st = sc.Status;
                    return true;
                }
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }

        private static void StopService(Logger log, string name)
        {
            try
            {
                using (ServiceController sc = new ServiceController(name))
                {
                    if (sc.Status == ServiceControllerStatus.Stopped) return;
                    log.Write("  Stopping service \"" + name + "\"");
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            }
            catch (InvalidOperationException) { }   // not installed
            catch (System.ServiceProcess.TimeoutException)
            {
                log.Write("  Service \"" + name + "\" did not stop in time");
            }
        }

        private static void StartService(Logger log, string name)
        {
            using (ServiceController sc = new ServiceController(name))
            {
                if (sc.Status != ServiceControllerStatus.Running)
                {
                    sc.Start();
                    try
                    {
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    }
                    catch (System.ServiceProcess.TimeoutException)
                    {
                        throw new SetupException("The service \"" + name + "\" did not start.");
                    }
                }
                log.Write("  \"" + name + "\" is running");
            }
        }

        private static void EnsureService(Logger log, string name, string display, string description, string exe, bool restartOnFailure)
        {
            string bin = "\"" + exe + "\"";
            IntPtr scm = Native.OpenSCManager(null, null, Native.SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero) throw new SetupException("Cannot open the service manager: " + new Win32Exception().Message);
            try
            {
                IntPtr svc = Native.OpenService(scm, name, Native.SERVICE_ALL_ACCESS);
                if (svc == IntPtr.Zero)
                {
                    svc = Native.CreateService(scm, name, display, Native.SERVICE_ALL_ACCESS, Native.SERVICE_WIN32_OWN_PROCESS,
                        Native.SERVICE_AUTO_START, Native.SERVICE_ERROR_NORMAL, bin, null, IntPtr.Zero, null, null, null);
                    if (svc == IntPtr.Zero)
                        throw new SetupException("Cannot create the service \"" + name + "\": " + new Win32Exception().Message);
                    log.Write("  Created service \"" + name + "\"");
                }
                else
                {
                    if (!Native.ChangeServiceConfig(svc, Native.SERVICE_WIN32_OWN_PROCESS, Native.SERVICE_AUTO_START,
                            Native.SERVICE_ERROR_NORMAL, bin, null, IntPtr.Zero, null, null, null, display))
                        throw new SetupException("Cannot update the service \"" + name + "\": " + new Win32Exception().Message);
                    log.Write("  Updated service \"" + name + "\"");
                }
                try
                {
                    IntPtr text = Marshal.StringToHGlobalUni(description);
                    IntPtr desc = Marshal.AllocHGlobal(IntPtr.Size);
                    try
                    {
                        Marshal.WriteIntPtr(desc, text);
                        Native.ChangeServiceConfig2(svc, 1, desc);   // SERVICE_CONFIG_DESCRIPTION
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(desc);
                        Marshal.FreeHGlobal(text);
                    }
                    if (restartOnFailure)
                    {
                        int[] delays = { 5000, 5000, 30000 };
                        IntPtr actions = Marshal.AllocHGlobal(8 * delays.Length);
                        IntPtr fa = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.SERVICE_FAILURE_ACTIONS)));
                        try
                        {
                            for (int i = 0; i < delays.Length; i++)
                            {
                                Marshal.WriteInt32(actions, 8 * i, 1);      // SC_ACTION_RESTART
                                Marshal.WriteInt32(actions, 8 * i + 4, delays[i]);
                            }
                            Native.SERVICE_FAILURE_ACTIONS f = new Native.SERVICE_FAILURE_ACTIONS();
                            f.dwResetPeriod = 86400;
                            f.cActions = delays.Length;
                            f.lpsaActions = actions;
                            Marshal.StructureToPtr(f, fa, false);
                            Native.ChangeServiceConfig2(svc, 2, fa);   // SERVICE_CONFIG_FAILURE_ACTIONS
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(fa);
                            Marshal.FreeHGlobal(actions);
                        }
                    }
                }
                finally
                {
                    Native.CloseServiceHandle(svc);
                }
            }
            finally
            {
                Native.CloseServiceHandle(scm);
            }
        }

        private static void DeleteService(Logger log, string name)
        {
            IntPtr scm = Native.OpenSCManager(null, null, Native.SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero) return;
            try
            {
                IntPtr svc = Native.OpenService(scm, name, Native.DELETE);
                if (svc == IntPtr.Zero) return;
                try
                {
                    if (Native.DeleteService(svc)) log.Write("  Removed service \"" + name + "\"");
                    else log.Write("  Could not remove service \"" + name + "\": " + new Win32Exception().Message);
                }
                finally
                {
                    Native.CloseServiceHandle(svc);
                }
            }
            finally
            {
                Native.CloseServiceHandle(scm);
            }
        }

        // ---- driver and adapter

        private static void InstallDriver(Logger log, string tapDir)
        {
            string output;
            int rc = Run(Path.Combine(SystemDir, "pnputil.exe"), "/add-driver \"" + Path.Combine(tapDir, "OemVista.inf") + "\" /install",
                tapDir, 180000, out output);
            LogOutput(log, output);
            if (rc != 0) log.Write("  (pnputil exit code " + rc + "; the adapter step below checks the result)");
        }

        private static List<TapAdapter> FindTapAdapters()
        {
            List<TapAdapter> list = new List<TapAdapter>();
            using (RegistryKey cls = Registry.LocalMachine.OpenSubKey(NetClassKey))
            {
                if (cls == null) return list;
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
                            TapAdapter a = new TapAdapter();
                            a.ClassKey = sub;
                            a.Guid = k.GetValue("NetCfgInstanceId") as string;
                            if (a.Guid != null)
                            {
                                using (RegistryKey c = Registry.LocalMachine.OpenSubKey(NetConnKey + "\\" + a.Guid + "\\Connection"))
                                {
                                    if (c != null)
                                    {
                                        a.Name = c.GetValue("Name") as string;
                                        a.PnpId = c.GetValue("PnPInstanceId") as string;
                                    }
                                }
                            }
                            list.Add(a);
                        }
                    }
                    catch (System.Security.SecurityException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            return list;
        }

        /// <summary>GUIDs of all network connections with this name (any adapter type).</summary>
        private static List<string> ConnectionsNamed(string name)
        {
            List<string> r = new List<string>();
            using (RegistryKey net = Registry.LocalMachine.OpenSubKey(NetConnKey))
            {
                if (net == null) return r;
                foreach (string g in net.GetSubKeyNames())
                {
                    try
                    {
                        using (RegistryKey c = net.OpenSubKey(g + "\\Connection"))
                        {
                            if (c != null && name.Equals(c.GetValue("Name") as string, StringComparison.OrdinalIgnoreCase)) r.Add(g);
                        }
                    }
                    catch (System.Security.SecurityException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            return r;
        }

        private static TapAdapter FindOurAdapter()
        {
            return FindTapAdapters().FirstOrDefault(a => AdapterName.Equals(a.Name, StringComparison.OrdinalIgnoreCase));
        }

        private static void EnsureAdapter(Logger log, string tapDir)
        {
            TapAdapter ours = FindOurAdapter();
            if (ours != null)
            {
                log.Write("  Already present (" + ours.PnpId + ")");
                return;
            }
            if (ConnectionsNamed(AdapterName).Count > 0)
                throw new SetupException("A network connection named \"" + AdapterName + "\" already exists and is not a TAP-Windows6 " +
                                         "adapter. Rename it in Settings > Network & internet, then run setup again.");

            HashSet<string> before = new HashSet<string>(FindTapAdapters().Where(a => a.Guid != null).Select(a => a.Guid),
                StringComparer.OrdinalIgnoreCase);
            // Hardware id "tap0901" (not root\tap0901) makes the adapter's ComponentId exactly "tap0901",
            // which is what the patched PairVPN.exe looks for.
            string output;
            int rc = Run(Path.Combine(tapDir, "devcon.exe"), "install \"" + Path.Combine(tapDir, "OemVista.inf") + "\" tap0901",
                tapDir, 300000, out output);
            LogOutput(log, output);
            if (rc != 0 && rc != 1) throw new SetupException("Creating the TAP adapter failed (devcon exit code " + rc + ").");
            if (rc == 1) log.Write("  Windows reports that a restart is needed to finish the driver installation.");

            TapAdapter created = null;
            for (int i = 0; i < 80 && created == null; i++)
            {
                Thread.Sleep(250);
                created = FindTapAdapters().FirstOrDefault(a => a.Guid != null && a.Name != null && !before.Contains(a.Guid));
            }
            if (created == null) throw new SetupException("The new TAP adapter did not appear.");
            log.Write("  Created \"" + created.Name + "\" (" + created.PnpId + ")");

            rc = Run(Path.Combine(SystemDir, "netsh.exe"),
                "interface set interface name=\"" + created.Name + "\" newname=\"" + AdapterName + "\"", SystemDir, 60000, out output);
            if (rc != 0)
            {
                LogOutput(log, output);
                log.Write("  netsh could not rename it (exit code " + rc + "); setting the name directly");
                using (RegistryKey c = Registry.LocalMachine.OpenSubKey(NetConnKey + "\\" + created.Guid + "\\Connection", true))
                {
                    if (c != null) c.SetValue("Name", AdapterName, RegistryValueKind.String);
                }
            }
            for (int i = 0; i < 40 && FindOurAdapter() == null; i++) Thread.Sleep(250);
            if (FindOurAdapter() == null) throw new SetupException("Could not rename the new adapter to \"" + AdapterName + "\".");
            log.Write("  Renamed to \"" + AdapterName + "\"");
        }

        private static void RemoveOurDriverPackages(Logger log)
        {
            if (FindTapAdapters().Count > 0)
            {
                log.Write("  Other TAP-Windows6 adapters exist; keeping the driver.");
                return;
            }
            byte[] ours;
            using (SHA256 sha = SHA256.Create()) ours = sha.ComputeHash(ReadResource("tap.OemVista.inf"));
            string infDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF");
            int removed = 0;
            foreach (string f in Directory.GetFiles(infDir, "oem*.inf"))
            {
                byte[] h;
                try
                {
                    using (SHA256 sha = SHA256.Create()) h = sha.ComputeHash(File.ReadAllBytes(f));
                }
                catch (Exception) { continue; }
                if (!h.SequenceEqual(ours)) continue;
                string output;
                int rc = Run(Path.Combine(SystemDir, "pnputil.exe"), "/delete-driver " + Path.GetFileName(f), SystemDir, 120000, out output);
                LogOutput(log, output);
                if (rc == 0) removed++;
            }
            if (removed == 0) log.Write("  No driver package of ours was found in the driver store.");
        }

        // ---- files, shortcut, Apps entry

        private static void CopyFiles(Logger log, string tmp)
        {
            Directory.CreateDirectory(InstallDir);
            foreach (string f in AppFiles) CopyWithRetry(Path.Combine(tmp, f), Path.Combine(InstallDir, f));
            string target = Path.Combine(InstallDir, SetupFileName);
            if (!string.Equals(Path.GetFullPath(SelfPath), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
                CopyWithRetry(SelfPath, target);
            TryDeleteFile(Path.Combine(InstallDir, "Uninstall-PairVPN-ARM64.ps1"));   // from the script-based install
            foreach (string f in Directory.GetFiles(InstallDir))
                log.Write(string.Format("  {0,-28} {1,10:N0} bytes", Path.GetFileName(f), new FileInfo(f).Length));
        }

        private static void CopyWithRetry(string src, string dst)
        {
            for (int i = 0; ; i++)
            {
                try
                {
                    File.Copy(src, dst, true);
                    return;
                }
                catch (IOException)
                {
                    if (i >= 20) throw;
                    Thread.Sleep(500);
                }
                catch (UnauthorizedAccessException)
                {
                    if (i >= 20) throw;
                    Thread.Sleep(500);
                }
            }
        }

        private static void CreateShortcut(Logger log)
        {
            Directory.CreateDirectory(StartMenuDir);
            string lnk = Path.Combine(StartMenuDir, "PairVPN.lnk");
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            object shell = Activator.CreateInstance(t);
            try
            {
                dynamic sh = shell;
                dynamic s = sh.CreateShortcut(lnk);
                s.TargetPath = Path.Combine(InstallDir, "PairVPN.exe");
                s.WorkingDirectory = InstallDir;
                s.Description = "PairVPN";
                s.Save();
            }
            finally
            {
                Marshal.FinalReleaseComObject(shell);
            }
            log.Write("  " + lnk);
        }

        private static void RegisterUninstall(Logger log)
        {
            long bytes = Directory.GetFiles(InstallDir).Sum(f => new FileInfo(f).Length);
            string setup = Path.Combine(InstallDir, SetupFileName);
            using (RegistryKey k = Registry.LocalMachine.CreateSubKey(UninstallKey))
            {
                k.SetValue("DisplayName", "PairVPN (ARM64 compatibility install)");
                k.SetValue("DisplayVersion", "1.9.16");
                k.SetValue("Publisher", "Mobile Co. (adapted for Windows on ARM, unofficial)");
                k.SetValue("InstallLocation", InstallDir);
                k.SetValue("DisplayIcon", Path.Combine(InstallDir, "PairVPN.exe"));
                k.SetValue("UninstallString", "\"" + setup + "\" /uninstall");
                k.SetValue("QuietUninstallString", "\"" + setup + "\" /uninstall /quiet");
                k.SetValue("EstimatedSize", (int)(bytes / 1024), RegistryValueKind.DWord);
                k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
            log.Write("  Apps & features: \"PairVPN (ARM64 compatibility install)\"");
        }

        // ---- verification

        private static void WaitForBridge(Logger log)
        {
            for (int i = 0; i < 120; i++)
            {
                if (Native.WaitNamedPipe(@"\\.\pipe\pveth", 250)) return;
                Thread.Sleep(250);
            }
            throw new SetupException("The bridge service is not accepting connections. See " + Path.Combine(DataDir, "bridge.log") + ".");
        }

        private static void SelfTest(Logger log)
        {
            string output;
            int rc = Run(Path.Combine(InstallDir, "PairVPN-ARM64-Bridge.exe"), "probe 12 sendtest", InstallDir, 90000, out output);
            bool ready = false, both = false;
            int frames = 0;
            foreach (string raw in output.Split('\n'))
            {
                string l = raw.Trim();
                if (l.StartsWith("OK: adapter-ready")) ready = true;
                if (l.StartsWith("OK: Windows answered")) both = true;
                Match m = Regex.Match(l, @"^Summary: \d+ read\(s\), (\d+) frame");
                if (m.Success) frames = int.Parse(m.Groups[1].Value);
                if (l.StartsWith("OK:") || l.StartsWith("FAIL:") || l.StartsWith("SKIP:") || l.StartsWith("Summary:")) log.Write("  " + l);
            }
            if (!ready || frames == 0)
                throw new SetupException("Self-test failed: no traffic passed between the bridge and the adapter (probe exit code " + rc +
                                         "). See " + Path.Combine(DataDir, "bridge.log") + ".");
            log.Write(both ? "  Self-test passed in both directions."
                           : "  Self-test passed (Windows -> PairVPN); the reverse check was skipped because Windows had no address on the adapter yet.");
        }

        // ------------------------------------------------------------------ uninstall

        public static void Uninstall(Logger log)
        {
            log.Write(VersionText + " - uninstall");
            Step(log, "Closing PairVPN and stopping its services");
            StopEverything(log);

            Step(log, "Removing services");
            DeleteService(log, BridgeService);
            DeleteService(log, RouteService);

            Step(log, "Removing the \"" + AdapterName + "\" network adapter");
            bool any = false;
            foreach (TapAdapter a in FindTapAdapters())
            {
                if (!AdapterName.Equals(a.Name, StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(a.PnpId)) continue;
                any = true;
                string output;
                Run(Path.Combine(SystemDir, "pnputil.exe"), "/remove-device \"" + a.PnpId + "\"", SystemDir, 120000, out output);
                LogOutput(log, output);
            }
            if (!any) log.Write("  Not present.");

            Step(log, "Removing the TAP-Windows6 driver package (if nothing else uses it)");
            RemoveOurDriverPackages(log);

            Step(log, "Removing program files, shortcut and Apps & features entry");
            DeleteDirWithRetry(log, InstallDir);
            TryDeleteDir(StartMenuDir);
            try { Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, false); } catch (Exception) { }
            TryDeleteDir(DataDir);
            log.Write("");
            log.Write("UNINSTALL COMPLETE (PairVPN's pairing settings in HKCU\\Software\\PairVPN were kept).");
        }

        private static void DeleteDirWithRetry(Logger log, string dir)
        {
            for (int i = 0; i < 40 && Directory.Exists(dir); i++)
            {
                try
                {
                    Directory.Delete(dir, true);
                }
                catch (Exception)
                {
                    Thread.Sleep(500);
                }
            }
            log.Write(Directory.Exists(dir) ? "  Could not delete " + dir + " completely." : "  Deleted " + dir);
        }

        // ------------------------------------------------------------------ helpers

        public static void LaunchPairVpn(Logger log)
        {
            // Via Explorer so PairVPN runs as the signed-in user, not elevated like setup.
            string exe = Path.Combine(InstallDir, "PairVPN.exe");
            try
            {
                Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), "\"" + exe + "\"");
                log.Write("Started PairVPN.");
            }
            catch (Exception e)
            {
                log.Write("Could not start PairVPN: " + e.Message);
            }
        }

        private static int Run(string exe, string args, string workDir, int timeoutMs, out string output)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.WorkingDirectory = workDir;
            StringBuilder sb = new StringBuilder();
            object gate = new object();
            using (Process p = new Process())
            {
                p.StartInfo = psi;
                p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (gate) sb.AppendLine(e.Data); };
                p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (gate) sb.AppendLine(e.Data); };
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch (Exception) { }
                    throw new SetupException(Path.GetFileName(exe) + " did not finish in time.");
                }
                p.WaitForExit();
                lock (gate) output = sb.ToString();
                return p.ExitCode;
            }
        }

        private static void LogOutput(Logger log, string output)
        {
            foreach (string raw in output.Split('\n'))
            {
                string l = raw.TrimEnd('\r', ' ');
                if (l.Trim().Length == 0 || l.StartsWith("Microsoft PnP Utility")) continue;
                log.Write("    " + l.Trim());
            }
        }

        public static void TryDeleteFile(string f)
        {
            try { if (File.Exists(f)) File.Delete(f); } catch (Exception) { }
        }

        public static void TryDeleteDir(string d)
        {
            try { if (Directory.Exists(d)) Directory.Delete(d, true); } catch (Exception) { }
        }
    }

    // ---------------------------------------------------------------------- UI

    internal sealed class SetupForm : Form
    {
        private readonly Options opt;
        private readonly Logger log;
        private readonly TextBox box = new TextBox();
        private readonly ProgressBar bar = new ProgressBar();
        private readonly Label status = new Label();
        private readonly Button launchButton = new Button();
        private readonly Button closeButton = new Button();
        private bool busy;
        public int ExitCode = 1;

        public SetupForm(Options opt, Logger log)
        {
            this.opt = opt;
            this.log = log;
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 9F);
            Text = opt.Uninstall ? "PairVPN for Windows on ARM - Uninstall" : "PairVPN 1.9.16 for Windows on ARM - Setup";
            ClientSize = new Size(700, 470);
            MinimumSize = new Size(540, 380);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch (Exception) { }

            Label title = new Label();
            title.Dock = DockStyle.Top;
            title.Height = 30;
            title.Font = new Font("Segoe UI Semibold", 12F);
            title.Text = opt.Uninstall ? "Removing PairVPN (ARM64)" : "PairVPN for Windows on ARM";
            Label desc = new Label();
            desc.Dock = DockStyle.Fill;
            desc.Text = opt.Uninstall
                ? "Removes PairVPN, its two services, the \"PairVPN\" network adapter and the TAP-Windows6 driver (if nothing else uses it). " +
                  "Your pairing settings are kept."
                : "Installs PairVPN 1.9.16 adapted for this ARM64 PC: OpenVPN's Microsoft-signed TAP-Windows6 ARM64 driver (network adapter " +
                  "\"PairVPN\"), PairVPN patched to use it, and the PairVPN ARM64 Bridge service. Unofficial adaptation, not supported by " +
                  "PairVPN's developer.";
            Panel head = new Panel();
            head.Dock = DockStyle.Fill;
            head.Controls.Add(desc);
            head.Controls.Add(title);

            box.Multiline = true;
            box.ReadOnly = true;
            box.ScrollBars = ScrollBars.Both;
            box.WordWrap = false;
            box.Dock = DockStyle.Fill;
            box.Font = new Font("Consolas", 9F);
            box.BackColor = SystemColors.Window;

            bar.Dock = DockStyle.Fill;
            bar.Style = ProgressBarStyle.Marquee;
            bar.MarqueeAnimationSpeed = 30;
            bar.Margin = new Padding(0, 8, 0, 8);

            status.AutoSize = true;
            status.Anchor = AnchorStyles.Left;
            status.Text = opt.Uninstall ? "Removing..." : "Installing...";
            launchButton.Text = "Launch PairVPN";
            launchButton.AutoSize = true;
            launchButton.Padding = new Padding(8, 2, 8, 2);
            launchButton.Enabled = false;
            launchButton.Visible = !opt.Uninstall && !opt.NoLaunch;
            launchButton.Click += delegate
            {
                Setup.LaunchPairVpn(log);
                Close();
            };
            closeButton.Text = "Close";
            closeButton.AutoSize = true;
            closeButton.Padding = new Padding(8, 2, 8, 2);
            closeButton.Enabled = false;
            closeButton.Click += delegate { Close(); };

            TableLayoutPanel bottom = new TableLayoutPanel();
            bottom.Dock = DockStyle.Fill;
            bottom.AutoSize = true;
            bottom.ColumnCount = 3;
            bottom.RowCount = 1;
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bottom.Controls.Add(status, 0, 0);
            bottom.Controls.Add(launchButton, 1, 0);
            bottom.Controls.Add(closeButton, 2, 0);

            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.ColumnCount = 1;
            root.RowCount = 4;
            root.Padding = new Padding(12);
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 86F));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32F));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(head, 0, 0);
            root.Controls.Add(box, 0, 1);
            root.Controls.Add(bar, 0, 2);
            root.Controls.Add(bottom, 0, 3);
            Controls.Add(root);
            ResumeLayout(true);

            log.Sink = AppendLine;
            Shown += delegate { Begin(); };
            FormClosing += delegate(object s, FormClosingEventArgs e)
            {
                if (busy) e.Cancel = true;
            };
        }

        private void AppendLine(string line)
        {
            if (IsDisposed) return;
            if (InvokeRequired)
            {
                try { BeginInvoke(new Action<string>(AppendLine), line); } catch (Exception) { }
                return;
            }
            box.AppendText(line + Environment.NewLine);
        }

        private void Begin()
        {
            if (opt.Uninstall && !opt.AutoClose &&
                MessageBox.Show(this, "Remove PairVPN (ARM64) and its \"PairVPN\" network adapter from this PC?", Text,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            {
                ExitCode = 2;
                Close();
                return;
            }
            busy = true;
            Thread t = new Thread(Work);
            t.IsBackground = true;
            t.Start();
        }

        private void Work()
        {
            bool ok = false;
            try
            {
                if (opt.Uninstall) Setup.Uninstall(log);
                else Setup.Install(log, opt, Confirm);
                ok = true;
            }
            catch (Exception e)
            {
                log.Write("");
                log.Write("ERROR: " + (e is SetupException ? e.Message : e.ToString()));
            }
            try { BeginInvoke(new Action<bool>(Done), ok); } catch (Exception) { }
        }

        private bool Confirm(string question)
        {
            return (bool)Invoke(new Func<bool>(() =>
                MessageBox.Show(this, question, Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes));
        }

        private void Done(bool ok)
        {
            busy = false;
            ExitCode = ok ? 0 : 1;
            bar.Style = ProgressBarStyle.Continuous;
            bar.Value = ok ? 100 : 0;
            if (ok)
                status.Text = opt.Uninstall ? "PairVPN (ARM64) has been removed." : "Done. Open PairVPN and connect to your phone as usual.";
            else
            {
                status.Text = "Something went wrong; see above. Log: " + log.LogPath;
                status.ForeColor = Color.Firebrick;
            }
            launchButton.Enabled = ok && !opt.Uninstall;
            closeButton.Enabled = true;
            if (launchButton.Visible && launchButton.Enabled) launchButton.Focus();
            else closeButton.Focus();
            if (opt.AutoClose)
            {
                System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
                timer.Interval = 3000;
                timer.Tick += delegate
                {
                    timer.Stop();
                    Close();
                };
                timer.Start();
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            Options opt = Options.Parse(args);

            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            {
                if (!opt.Quiet)
                    MessageBox.Show("Please run this setup as an administrator.", "PairVPN for Windows on ARM", MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                return 3;
            }

            // Uninstalling from the installed copy: run from a temporary copy so the folder can be deleted.
            if (opt.Uninstall && !opt.Relocated &&
                Path.GetFullPath(Setup.SelfPath).StartsWith(Path.GetFullPath(Setup.InstallDir) + "\\", StringComparison.OrdinalIgnoreCase))
            {
                string tmpExe = Path.Combine(Path.GetTempPath(), "PairVPN-ARM64-Uninstall-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".exe");
                File.Copy(Setup.SelfPath, tmpExe, true);
                ProcessStartInfo psi = new ProcessStartInfo(tmpExe, string.Join(" ", args.Select(a => "\"" + a + "\"")) + " /relocated");
                psi.UseShellExecute = false;
                Process.Start(psi);
                return 0;
            }

            Logger log = new Logger(opt.Uninstall || opt.TestVcRedist
                ? Path.Combine(Path.GetTempPath(), opt.TestVcRedist ? "PairVPN-ARM64-vctest.log" : "PairVPN-ARM64-uninstall.log")
                : Path.Combine(Setup.DataDir, "setup.log"));

            int code;
            if (opt.TestVcRedist)
            {
                code = Setup.TestVcRedistDownload(log);
            }
            else if (opt.Quiet)
            {
                code = 0;
                try
                {
                    if (opt.Uninstall) Setup.Uninstall(log);
                    else
                    {
                        Setup.Install(log, opt, delegate { return true; });
                        if (opt.Launch && !opt.NoLaunch) Setup.LaunchPairVpn(log);
                    }
                }
                catch (Exception e)
                {
                    log.Write("ERROR: " + (e is SetupException ? e.Message : e.ToString()));
                    code = 1;
                }
            }
            else
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                SetupForm form = new SetupForm(opt, log);
                Application.Run(form);
                code = form.ExitCode;
            }

            if (opt.Relocated)
                Native.MoveFileEx(Setup.SelfPath, null, Native.MOVEFILE_DELAY_UNTIL_REBOOT);
            return code;
        }
    }
}
