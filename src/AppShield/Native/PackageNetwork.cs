// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using AppShield.Model;

namespace AppShield.Native
{
    public static class PackageNetwork
    {
        [DllImport("FirewallAPI.dll")]
        private static extern uint NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr sids);
        [DllImport("kernel32.dll")] private static extern IntPtr GetProcessHeap();
        [DllImport("kernel32.dll")] private static extern bool HeapFree(IntPtr heap, uint flags, IntPtr value);
        [StructLayout(LayoutKind.Sequential)]
        private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

        private static void ValidateIdentity(Guid id, string sid)
        {
            using (var expected = new ContainerIdentity(id, false))
            {
                if (!string.Equals(sid, expected.Sid.Value, StringComparison.Ordinal))
                    throw new InvalidOperationException("应用 SID 与此配置的 Windows 身份不一致。");
            }
        }

        internal static string Scope(Guid id, string sid, AppProfile profile)
        {
            if (profile == null || profile.Id != id) throw new ArgumentException("配置标识不一致。");
            ValidateIdentity(id, sid);
            if (!profile.BlockLoopback)
                throw new NotSupportedException("当前原生引擎要求保持 AppContainer 的系统回环隔离。");
            if (!profile.AllowInternet && !profile.BlockLan)
                throw new NotSupportedException("当前原生引擎的离线模式要求同时阻断局域网。");
            if (!profile.AllowInternet) return "offline";
            return profile.BlockLan ? "public" : "network";
        }

        internal static bool HasLoopbackExemption(string sid)
        {
            uint status = NetworkIsolationGetAppContainerConfig(out var count, out var entries);
            if (status != 0) throw new Win32Exception((int)status, "无法读取 Windows AppContainer 回环例外。");
            IntPtr heap = GetProcessHeap();
            int stride = Marshal.SizeOf(typeof(SidAndAttributes));
            bool found = false;
            try
            {
                for (uint index = 0; index < count; index++)
                {
                    var value = Marshal.PtrToStructure<SidAndAttributes>(IntPtr.Add(entries, checked((int)index * stride)));
                    if (new SecurityIdentifier(value.Sid).Value == sid) found = true;
                }
                return found;
            }
            finally
            {
                for (uint index = 0; index < count; index++)
                {
                    var ptr = Marshal.ReadIntPtr(entries, checked((int)index * stride));
                    if (ptr != IntPtr.Zero) HeapFree(heap, 0, ptr);
                }
                if (entries != IntPtr.Zero) HeapFree(heap, 0, entries);
            }
        }

        public static void Apply(Guid id, string sid, AppProfile profile)
        {
            string scope = Scope(id, sid, profile);
            WithLock(id, () =>
            {
                if (HasLoopbackExemption(sid))
                    throw new InvalidOperationException("此应用存在 Windows 回环例外。请移除此应用的例外，再应用权限。");
                int current = Run(id, sid, scope, false);
                if (current == 0) return;
                if (current != 21) RequireSuccess(current);
                RequireSuccess(Run(id, sid, scope, true));
                Verify(id, sid, profile);
            });
        }

        public static void Verify(Guid id, string sid, AppProfile profile)
        {
            string scope = Scope(id, sid, profile);
            if (HasLoopbackExemption(sid))
                throw new InvalidOperationException("此应用存在 Windows 回环例外，无法确认本机阻断。");
            RequireSuccess(Run(id, sid, scope, false));
        }

        public static void Remove(Guid id, string sid)
        {
            ValidateIdentity(id, sid);
            WithLock(id, () =>
            {
                int existing = Run(id, sid, "remove", false);
                if (existing == 0) return;
                if (existing != 21) RequireSuccess(existing);
                RequireSuccess(Run(id, sid, "remove", true));
            });
        }

        private static void WithLock(Guid id, Action operation)
        {
            using (var gate = new Mutex(false, @"Local\AppShield.Network." + id.ToString("N")))
            {
                bool acquired;
                try { acquired = gate.WaitOne(TimeSpan.FromSeconds(30)); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("另一个窗口正在更新此应用的网络规则。");
                try { operation(); } finally { gate.ReleaseMutex(); }
            }
        }

        private static void RequireSuccess(int code)
        {
            if (code == 0) return;
            if (code == 20) throw new InvalidOperationException("Windows 防火墙未启用、排除了接口或禁止了本地规则。");
            if (code == 21) throw new InvalidOperationException("应用专属网络规则缺失或与保存的策略不符。请先应用权限。");
            if (code == 22) throw new InvalidOperationException("同名防火墙规则的归属不一致。请检查现有规则。");
            throw new InvalidOperationException("无法核实 Windows 有效防火墙策略（状态 " + code.ToString(CultureInfo.InvariantCulture) + "）。");
        }

        private static int Run(Guid id, string sid, string scope, bool apply)
        {
            var assembly = typeof(PackageNetwork).Assembly;
            string resource = assembly.GetManifestResourceNames().Single(n => n.EndsWith(".Native.PackageNetwork.ps1", StringComparison.Ordinal));
            string script;
            using (var reader = new StreamReader(assembly.GetManifestResourceStream(resource)))
                script = reader.ReadToEnd().Replace("__ID__", id.ToString("N")).Replace("__SID__", sid)
                    .Replace("__SCOPE__", scope).Replace("__APPLY__", apply ? "$true" : "$false");
            string exe = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            var start = new ProcessStartInfo(exe, "-NoProfile -NoLogo -NonInteractive -EncodedCommand " +
                Convert.ToBase64String(Encoding.Unicode.GetBytes(script)))
            {
                UseShellExecute = apply,
                CreateNoWindow = !apply,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Environment.SystemDirectory,
                Verb = apply ? "runas" : ""
            };
            try
            {
                using (var process = Process.Start(start)) { process.WaitForExit(); return process.ExitCode; }
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            { throw new InvalidOperationException("未授权本次应用专属防火墙配置。"); }
        }
    }
}
