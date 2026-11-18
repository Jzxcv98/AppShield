// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace AppShield.Native
{
    // The application and local-user filters are both mandatory. This rule covers
    // outbound traffic by one executable; other images and loopback have separate semantics.
    internal static class WeChatAccountNetwork
    {
        internal static SecurityIdentifier[] RecordedAccounts(Guid profileId, string imagePath)
        {
            int status = Run(profileId, imagePath, null, "list", false, out var text);
            Check(status);
            return text.Split(new[] {'\r', '\n'}, StringSplitOptions.RemoveEmptyEntries)
                .Select(value => new SecurityIdentifier(value)).Distinct().ToArray();
        }

        internal static bool IsApplied(Guid profileId, string imagePath, SecurityIdentifier sid)
        {
            int status = Run(profileId, imagePath, sid, "inspect", false);
            if (status == 21) return false;
            Check(status);
            return true;
        }

        internal static void Apply(Guid profileId, string imagePath, SecurityIdentifier sid)
        {
            if (IsApplied(profileId, imagePath, sid)) return;
            Check(Run(profileId, imagePath, sid, "apply", true));
            if (!IsApplied(profileId, imagePath, sid))
                throw new InvalidOperationException("Windows 尚未确认微信主程序的出站规则。");
        }

        internal static void Revoke(Guid profileId, string imagePath, SecurityIdentifier sid)
        {
            // Inspect ownership even when the firewall profile has changed or become disabled.
            int status = Run(profileId, imagePath, sid, "can-remove", false);
            if (status == 21) return;
            Check(status);
            Check(Run(profileId, imagePath, sid, "remove", true));
            status = Run(profileId, imagePath, sid, "can-remove", false);
            if (status != 21) { Check(status); throw new IOException("Windows 尚未确认撤销网络规则。"); }
        }

        private static void Check(int code)
        {
            if (code == 0) return;
            if (code == 20) throw new InvalidOperationException("Windows 防火墙未启用、排除了接口或禁止本地规则。");
            if (code == 22) throw new InvalidOperationException("同名网络规则的账户、程序或来源不一致，已保留原规则。");
            if (code == 24) throw new InvalidOperationException("当前有效策略未包含完整的预期出站阻止规则。");
            if (code == 25) throw new InvalidOperationException("网络策略应用失败，未能确认回收本次规则。请刷新并检查状态。");
            throw new InvalidOperationException("Windows 无法核实微信主程序的出站策略（状态 " + code + "）。");
        }

        private static int Run(Guid id, string path, SecurityIdentifier sid, string operation, bool elevate)
            => Run(id, path, sid, operation, elevate, out _);

        private static int Run(Guid id, string path, SecurityIdentifier sid, string operation, bool elevate, out string text)
        {
            text = "";
            if (id == Guid.Empty || (operation != "list" && (sid == null || !sid.IsAccountSid() ||
                !sid.Value.StartsWith("S-1-5-21-", StringComparison.Ordinal))))
                throw new ArgumentException("需要有效的应用标识和普通用户 SID。");
            path = SafeFiles.LocalPath(path);
            if (!Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("需要 Windows 程序路径。");
            var assembly = typeof(WeChatAccountNetwork).Assembly;
            string resource = assembly.GetManifestResourceNames().Single(n => n.EndsWith(".Native.WeChatAccountNetwork.ps1", StringComparison.Ordinal));
            string script;
            using (var reader = new StreamReader(assembly.GetManifestResourceStream(resource)))
                script = reader.ReadToEnd().Replace("__ID__", id.ToString("N")).Replace("__SID__", sid?.Value ?? "")
                    .Replace("__OP__", operation).Replace("__IMAGE64__", Convert.ToBase64String(Encoding.Unicode.GetBytes(path)));
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script))) {
                UseShellExecute = elevate, CreateNoWindow = !elevate, WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Environment.SystemDirectory, Verb = elevate ? "runas" : "",
                RedirectStandardOutput = operation == "list"
            };
            try
            {
                using (var child = Process.Start(start)) {
                    if (start.RedirectStandardOutput) text = child.StandardOutput.ReadToEnd();
                    child.WaitForExit(); return child.ExitCode;
                }
            }
            catch (Win32Exception e) when (e.NativeErrorCode == 1223)
            { throw new InvalidOperationException("此次出站防火墙操作未获授权。"); }
        }
    }
}
