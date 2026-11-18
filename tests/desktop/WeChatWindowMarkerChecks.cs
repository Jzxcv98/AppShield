// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using AppShield.Model;

internal static class WeChatWindowMarkerChecks
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(uint exStyle, string windowClass, string title, uint style,
        int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr parameter);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);

    internal static void Run()
    {
        // The client queries UIA from a separate thread while the synthetic windows pump messages.
        Dispatcher dispatcher = null;
        using (var started = new ManualResetEventSlim())
        {
            var thread = new Thread(() =>
            {
                dispatcher = Dispatcher.CurrentDispatcher;
                started.Set();
                Dispatcher.Run();
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            started.Wait();
            try
            {
                Check(dispatcher, "Launch Error", "Scan to log in", WeChatWindowMarkers.Marker.ClientError);
                Check(dispatcher, "AppShield fixture", "Scan to log in tomorrow", WeChatWindowMarkers.Marker.Unknown);
                Check(dispatcher, "Launch\u00a0Error", "OK", WeChatWindowMarkers.Marker.ClientError);
                Check(dispatcher, "AppShield fixture", "Scan to log in", WeChatWindowMarkers.Marker.ScanToLogin);
                Check(dispatcher, "AppShield fixture", "扫码登录", WeChatWindowMarkers.Marker.ScanToLogin);
                Check(dispatcher, "AppShield fixture", "掃碼登入", WeChatWindowMarkers.Marker.ScanToLogin);
                Console.WriteLine("PASS: a launch-error dialog and unrelated text cannot pass the scan-to-login check");
            }
            finally
            {
                dispatcher.BeginInvokeShutdown(DispatcherPriority.Send);
                thread.Join(3000);
            }
        }
    }

    private static void Check(Dispatcher dispatcher, string title, string text, WeChatWindowMarkers.Marker expected)
    {
        var window = dispatcher.Invoke(() =>
        {
            const uint noActivateToolWindow = 0x08000080, visibleCaptionPopup = 0x90C00000, visibleChild = 0x50000000;
            var dialog = CreateWindowEx(noActivateToolWindow, "#32770", title, visibleCaptionPopup, 24, 24, 280, 80,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (dialog == IntPtr.Zero) throw new Win32Exception();
            if (CreateWindowEx(0, "STATIC", text, visibleChild, 8, 4, 240, 24, dialog, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                DestroyWindow(dialog);
                throw new Win32Exception(error);
            }
            return dialog;
        });
        try
        {
            using (var self = Process.GetCurrentProcess())
            {
                var target = new TextTarget { WindowHandle = window.ToInt64(), ProcessId = self.Id };
                var read = Task.Run(() => WeChatWindowMarkers.Read(target));
                if (!read.Wait(TimeSpan.FromSeconds(5)) || read.Result != expected)
                    throw new InvalidOperationException("synthetic UIA classification failed for " + expected);
            }
        }
        finally { dispatcher.Invoke(() => DestroyWindow(window)); }
    }
}
