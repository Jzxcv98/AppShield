// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace AppShield
{
    internal static class ManagedShortcut
    {
        internal static void Write(Guid profile, string target, bool overwrite)
        {
            target = SafeFiles.LocalPath(target);
            if (!string.Equals(Path.GetExtension(target), ".lnk", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("请选择 Windows 快捷方式（.lnk）。");
            string parent = Path.GetDirectoryName(target);
            using (SafeFiles.PinDirectory(parent))
            {
                string temp = Path.Combine(parent, ".appshield-" + Guid.NewGuid().ToString("N") + ".lnk");
                object shell = null, link = null;
                try
                {
                    string exe = typeof(ManagedShortcut).Assembly.Location;
                    string arguments = "--open-profile " + profile.ToString("N");
                    shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell", true));
                    link = ((dynamic)shell).CreateShortcut(temp);
                    dynamic record = link;
                    record.TargetPath = exe;
                    record.Arguments = arguments;
                    record.WorkingDirectory = Path.GetDirectoryName(exe);
                    record.Description = "通过 AppShield 隔离启动";
                    record.Save();
                    Marshal.FinalReleaseComObject(link);
                    link = null;
                    link = ((dynamic)shell).CreateShortcut(temp);
                    record = link;
                    if (!string.Equals((string)record.TargetPath, exe, StringComparison.OrdinalIgnoreCase) ||
                        (string)record.Arguments != arguments)
                        throw new IOException("Windows 未能核对快捷方式目标。");
                    if (overwrite && File.Exists(target)) File.Replace(temp, target, null);
                    else File.Move(temp, target);
                }
                finally
                {
                    if (link != null) Marshal.FinalReleaseComObject(link);
                    if (shell != null) Marshal.FinalReleaseComObject(shell);
                    if (File.Exists(temp)) File.Delete(temp);
                }
            }
        }
    }
}
