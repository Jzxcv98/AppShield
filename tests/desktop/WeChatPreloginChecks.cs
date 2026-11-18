// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AppShield;
using AppShield.Model;
using AppShield.Native;
using Microsoft.Win32.SafeHandles;

internal static class WeChatPreloginChecks
{
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int CreateAppContainerProfile(string name, string display, string description,
        IntPtr capabilities, uint count, out IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeleteAppContainerProfile(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle OpenJobObject(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr window, uint flags);
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr window, uint attribute, out int value, int size);

    internal static int Run()
    {
        if (!Environment.UserInteractive || WeChatIntegration.Detect() == null)
        {
            Console.WriteLine("SKIP: an interactive desktop and a verified WeChat installation are required.");
            return 77;
        }
        string temp = SafeFiles.LocalPath(Path.GetTempPath());
        string root = Path.Combine(temp, "AppShield.WeChatPrelogin." + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(root)) throw new IOException("Test directory already exists.");
        var app = new AppService(root);
        AppProfile profile = null;
        bool ownsIdentity = false;
        int result = 1;
        string stage = "IMPORT";
        try
        {
            profile = app.ImportWeChat();
            Console.WriteLine("IMPORT: verified WeChat " + profile.ProductVersion);
            stage = "PREFLIGHT";
            var initial = app.Inspect(profile);
            if (!initial.EngineReady || initial.Unboxed != 0 || initial.Unknown != 0 || initial.Boxed != 0)
            {
                Console.WriteLine("SKIP: desktop engine unavailable or an existing instance was detected; boxed=" +
                    initial.Boxed + " outside=" + initial.Unboxed + " unknown=" + initial.Unknown);
                result = 77;
            }
            else
            {
                // Require positive ownership before touching a package profile, even on a GUID collision.
                string name = ContainerIdentity.NameFor(profile.Id);
                int created = CreateAppContainerProfile(name, "AppShield WeChat test", "Temporary pre-login test",
                    IntPtr.Zero, 0, out var sid);
                Marshal.ThrowExceptionForHR(created);
                FreeSid(sid);
                ownsIdentity = true;
                stage = "APPLY";
                app.Apply(profile);
                for (int run = 1; run <= 2; run++)
                {
                    stage = "STARTUP " + run;
                    Console.WriteLine(stage + ": launching under the temporary identity");
                    Console.WriteLine(stage + ": " + app.LaunchAppContainer(profile));
                    stage = "OBSERVE " + run;
                    ObserveStableWindow(app, profile);
                    Console.WriteLine(stage + ": matched a scan-to-login prompt in the same visible window for 3 seconds");
                    stage = "STOP " + run;
                    StopTestJob(profile.Id);
                }
                result = 0;
            }
        }
        catch (Exception e) { Console.Error.WriteLine("FAIL " + stage + ": " + e.Message); }
        try
        {
            if (ownsIdentity)
            {
                StopTestJob(profile.Id);
                app.Revoke(profile);
                string name = ContainerIdentity.NameFor(profile.Id);
                int removed = DeleteAppContainerProfile(name);
                for (int retry = 0; retry < 10 && removed == unchecked((int)0x80070005); retry++)
                {
                    Thread.Sleep(400);
                    removed = DeleteAppContainerProfile(name);
                }
                Marshal.ThrowExceptionForHR(removed);
            }
            if (Directory.Exists(root) && string.Equals(Path.GetDirectoryName(root), temp, StringComparison.OrdinalIgnoreCase))
            {
                SafeFiles.PlainDirectories(root);
                Directory.Delete(root, true);
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("FAIL CLEANUP: " + e.Message + " | retained test state: " + root);
            return 1;
        }
        if (result == 0) Console.WriteLine("PASS: two managed launches with stable scan-to-login prompts and cleanup.");
        return result;
    }

    private static void ObserveStableWindow(AppService app, AppProfile profile)
    {
        var watch = Stopwatch.StartNew();
        TextTarget candidate = null;
        long visibleSince = 0;
        bool everVisible = false, everMatched = false;
        while (watch.ElapsedMilliseconds < 20000)
        {
            var report = app.Inspect(profile);
            if (!report.Applied || report.Unknown != 0 || report.Unboxed != 0)
                throw new InvalidOperationException("policy or process ownership changed");
            if (report.Boxed == 0 && !NativeJob.Active(profile.Id))
                throw new InvalidOperationException("PROCESS_EXITED: the verified process tree ended");
            var visible = report.Targets.Where(OnScreen).ToArray();
            everVisible |= visible.Length > 0;
            // Run UI Automation on an MTA worker and bound a stalled accessibility provider.
            var read = Task.Run(() => visible.Select(WeChatWindowMarkers.Read).ToArray());
            if (!read.Wait(TimeSpan.FromSeconds(3)))
                throw new TimeoutException("UNVERIFIED_WINDOW: accessibility provider timed out");
            var markers = read.Result;
            if (markers.Contains(WeChatWindowMarkers.Marker.ClientError))
                throw new InvalidOperationException("CLIENT_ERROR");
            var prompts = visible.Where((target, index) => markers[index] == WeChatWindowMarkers.Marker.ScanToLogin).ToArray();
            everMatched |= prompts.Length > 0;
            if (candidate != null && prompts.Any(t => t.WindowHandle == candidate.WindowHandle &&
                t.ProcessId == candidate.ProcessId && t.ProcessStartUtcTicks == candidate.ProcessStartUtcTicks))
            {
                if (watch.ElapsedMilliseconds - visibleSince >= 3000) return;
            }
            else
            {
                candidate = prompts.FirstOrDefault();
                visibleSince = watch.ElapsedMilliseconds;
            }
            Thread.Sleep(250);
        }
        if (everMatched) throw new TimeoutException("UNSTABLE_WINDOW: scan-to-login prompt did not remain stable");
        throw new TimeoutException(everVisible ? "UNVERIFIED_WINDOW: no known scan-to-login prompt"
            : "NO_WINDOW: no visible window in the verified process tree");
    }

    private static bool OnScreen(TextTarget target)
    {
        var window = new IntPtr(target.WindowHandle);
        return !IsIconic(window) && MonitorFromWindow(window, 0) != IntPtr.Zero &&
            GetClientRect(window, out var rect) && rect.Right > rect.Left && rect.Bottom > rect.Top &&
            DwmGetWindowAttribute(window, 14 /* DWMWA_CLOAKED */, out int cloaked, sizeof(int)) == 0 && cloaked == 0;
    }

    private static void StopTestJob(Guid id)
    {
        // Only this newly allocated profile's Job is eligible for teardown; the app can spawn helpers.
        using (var job = OpenJobObject(0x0008 /* JOB_OBJECT_TERMINATE */, false, NativeJob.JobName(id)))
        {
            if (job.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 2) return;
                throw new Win32Exception(error);
            }
            if (!TerminateJobObject(job, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var watch = Stopwatch.StartNew();
            while (NativeJob.Active(id))
            {
                if (watch.ElapsedMilliseconds >= 5000) throw new TimeoutException("test Job did not stop");
                Thread.Sleep(100);
            }
        }
    }
}
