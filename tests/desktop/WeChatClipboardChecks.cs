// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AppShield;
using AppShield.Model;
using AppShield.Native;
using Microsoft.Win32.SafeHandles;

internal static class WeChatClipboardChecks
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Startup
    {
        public int Size; public string Reserved, Desktop, Title;
        public int X, Y, Width, Height, Columns, Rows, Fill, Flags;
        public short Show, ReservedBytes; public IntPtr ReservedPointer, StdIn, StdOut, StdErr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Child { public IntPtr Process, Thread; public int Pid, Tid; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool CreateProcessW(string image, StringBuilder command, IntPtr pa, IntPtr ta, bool inherit,
        int flags, IntPtr env, string directory, ref Startup startup, out Child child);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr t);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr p, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr p, int ms);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr p, out int code);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(IntPtr job, int info, out int value, int size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(IntPtr proc, SafeFileHandle job, out bool inside);

    // Synthetic private-station client or this suite's own child; a closed last caller handle must
    // leave both the initial process and any subsequent child under the clipboard restriction.
    private static int BoundChild(string image, string args, string desktop)
    {
        var start = new Startup { Size = Marshal.SizeOf(typeof(Startup)), Desktop = desktop };
        if (!CreateProcessW(image, new StringBuilder("\"" + image + "\" " + args), IntPtr.Zero, IntPtr.Zero,
            false, 0x08000004, IntPtr.Zero, Path.GetDirectoryName(image), ref start, out var child)) throw new Win32Exception();
        try
        {
            using (WeChatClipboardJob.BindSuspended(child.Process)) { }
            if (ResumeThread(child.Thread) == uint.MaxValue) throw new Win32Exception();
            if (WaitForSingleObject(child.Process, 15000) != 0) throw new TimeoutException("Private clipboard fixture did not finish.");
            if (!GetExitCodeProcess(child.Process, out int code)) throw new Win32Exception();
            return code;
        }
        catch { TerminateProcess(child.Process, 1); throw; }
        finally { CloseHandle(child.Thread); CloseHandle(child.Process); }
    }

    internal static int Run(string[] args)
    {
        try
        {
            string self = typeof(WeChatClipboardChecks).Assembly.Location;
            if (args.Length == 0)
            {
                if (BoundChild(self, "--wechat-clipboard-test descendant", null) != 0)
                    throw new InvalidOperationException("Clipboard limits were lost across the process tree.");
                Console.WriteLine("PASS: exact clipboard UI limits survived handle closure and were inherited by a child.");
                return 0;
            }
            if (args.Length == 1 && (args[0] == "descendant" || args[0] == "leaf"))
            {
                if (!QueryInformationJobObject(IntPtr.Zero, 4, out int limits, 4, IntPtr.Zero) ||
                    limits != WeChatClipboardJob.ClipboardLimits) return 1;
                if (args[0] == "leaf") return 0;
                using (var p = Process.Start(new ProcessStartInfo(self,"--wechat-clipboard-test leaf") {
                    UseShellExecute = false, CreateNoWindow = true }))
                {
                    if (!p.WaitForExit(7000)) { p.Kill(); return 1; }
                    return p.ExitCode;
                }
            }
            if (args.Length == 3 && args[0] == "private-station")
            {
                string image = Path.GetFullPath(args[1]);
                string[] names = args[2].Split('\\');
                if (!Path.GetFileName(image).Equals("AppShield-clipboard-check.exe", StringComparison.OrdinalIgnoreCase) ||
                    names.Length != 2 || names[0] != names[1] || !names[0].StartsWith("AppShield.Clipboard.", StringComparison.Ordinal) ||
                    !Guid.TryParseExact(names[0].Substring("AppShield.Clipboard.".Length), "D", out _)) return 2;
                return BoundChild(image, "--child " + args[2], args[2]);
            }
            if (args.Length == 1 && args[0] == "guest-client") return GuestClient();
            return 2;
        }
        catch (Exception e) { Console.Error.WriteLine(e.GetBaseException().Message); return 1; }
    }

    private static int GuestClient()
    {
        // The test package is staged only in the fresh Windows Sandbox. Never start a real host profile.
        if (!File.Exists(@"C:\AppShieldInput\ClipboardGuest.ps1") ||
            !Environment.UserName.Equals("ASClipboardTrial",StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fresh Windows Sandbox required.");
        string image = WeChatIntegration.Detect() ?? throw new FileNotFoundException("Signed WeChat installation unavailable.");
        if (new[] { "Weixin", "WeChat" }.SelectMany(Process.GetProcessesByName).Any())
            throw new InvalidOperationException("An existing WeChat instance was detected.");
        string hash;
        using (var input = SafeFiles.OpenImage(image))
        using (var sha = SHA256.Create()) hash = BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "");
        using (var job = WeChatClipboardJob.StartCurrentUser(image, hash, out int pid))
        using (var client = Process.GetProcessById(pid))
        {
            var time = Stopwatch.StartNew();
            long started = 0, matchingWindow = 0;
            bool sawChild = false;
            while (time.Elapsed.TotalSeconds < 45)
            {
                if (client.HasExited) throw new InvalidOperationException("Guest WeChat exited: 0x" + client.ExitCode.ToString("X8"));
                if (!IsProcessInJob(client.Handle, job, out bool owned) || !owned) throw new InvalidOperationException("Lost verified guest process.");
                foreach (string name in new[] { "Weixin", "WeixinExt", "crashpad_handler" })
                    foreach (var other in Process.GetProcessesByName(name))
                        using (other) {
                            try { if (other.Id != pid && IsProcessInJob(other.Handle, job, out bool member) && member) sawChild = true; }
                            catch (InvalidOperationException) { }
                            catch (Win32Exception) { }
                        }
                long match = 0;
                foreach (TextTarget w in WindowTransfer.List(new[] {pid}))
                {
                    var read = Task.Run(() => WeChatWindowMarkers.Read(w));
                    if (!read.Wait(3000)) throw new TimeoutException("UIA_PROVIDER_TIMEOUT");
                    if (read.Result == WeChatWindowMarkers.Marker.ClientError) throw new InvalidOperationException("CLIENT_ERROR");
                    if (read.Result == WeChatWindowMarkers.Marker.ScanToLogin) match = w.WindowHandle;
                }
                if (match == 0 || match != matchingWindow) { matchingWindow = match; started = time.ElapsedMilliseconds; }
                else if (time.ElapsedMilliseconds - started >= 3000)
                {
                    Console.WriteLine("PASS_SCAN_PROMPT, root_job=true, observed_job_child=" + sawChild);
                    return sawChild ? 0 : 20; // 20 means root/window passed but no extra job member was observed.
                }
                Thread.Sleep(250);
            }
            throw new TimeoutException("No stable verified login prompt.");
        }
    }
}
