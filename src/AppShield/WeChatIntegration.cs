// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using AppShield.Model;
using Microsoft.Win32;

namespace AppShield
{
    internal static class WeChatIntegration
    {
        private const string Client = "Weixin.exe";
        private const string Signer = "Tencent Technology (Shenzhen) Company Limited";
        private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Weixin";

        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out int pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hwnd, StringBuilder name, int length);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hwnd, StringBuilder title, int length);

        internal static bool IsLaunchError(TextTarget target)
        {
            var window = new IntPtr(target.WindowHandle);
            if (GetWindowThreadProcessId(window, out int pid) == 0 || pid != target.ProcessId) return false;
            var text = new StringBuilder(64);
            if (GetClassName(window, text, text.Capacity) == 0 || text.ToString() != "#32770") return false;
            if (GetWindowText(window, text, text.Capacity) == 0) return false;
            string title = text.ToString().Replace('\u00a0', ' ');
            return title.Equals("Launch Error", StringComparison.OrdinalIgnoreCase) || title == "启动错误" || title == "啟動錯誤";
        }

        // The current x64 Store and standalone installers register the same Win32 client.
        internal static string Detect()
        {
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string directory in InstallDirectories())
            {
                if (string.IsNullOrWhiteSpace(directory)) continue;
                try
                {
                    string path = Path.Combine(SafeFiles.LocalPath(directory.Trim('"')), Client);
                    if (!visited.Add(path) || !File.Exists(path)) continue;
                    using (var image = SafeFiles.OpenImage(path))
                    {
                        var metadata = FileVersionInfo.GetVersionInfo(path);
                        ImageTrust.Describe(path, image, out string signer);
                        if (IsOfficialClient(path, metadata, signer)) return path;
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (ArgumentException) { }
                catch (NotSupportedException) { }
            }
            return null;
        }

        internal static bool IsOfficialClient(string path, FileVersionInfo metadata, string verifiedPublisher)
        {
            // Tencent helpers and the uninstaller are signed by the same publisher.
            return string.Equals(Path.GetFileName(path), Client, StringComparison.OrdinalIgnoreCase)
                && string.Equals(verifiedPublisher, Signer, StringComparison.OrdinalIgnoreCase)
                && string.Equals(metadata.ProductName, "Weixin", StringComparison.OrdinalIgnoreCase)
                && string.Equals(metadata.FileDescription, "Weixin", StringComparison.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> InstallDirectories()
        {
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
                foreach (var view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
                    yield return RegisteredDirectory(hive, view);

            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (programFiles.Length != 0) yield return Path.Combine(programFiles, "Tencent", "Weixin");
        }

        private static string RegisteredDirectory(RegistryHive hive, RegistryView view)
        {
            try
            {
                using (var root = RegistryKey.OpenBaseKey(hive, view))
                using (var key = root.OpenSubKey(UninstallKey))
                    return key?.GetValue("InstallLocation") as string;
            }
            catch (IOException) { return null; }
            catch (SecurityException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }
    }
}
