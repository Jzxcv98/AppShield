// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using AppShield.Model;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Model
{
    public sealed class WeChatLiveReport
    {
        public DateTime SampleUtc { get; internal set; }
        public int CurrentUserProcesses { get; internal set; }
        public int OtherUserProcesses { get; internal set; }
        public int OtherSessionProcesses { get; internal set; }
        public int UnverifiedProcesses { get; internal set; }
        public int? CurrentUserEstablishedTcp { get; internal set; }
        public int? OtherUserEstablishedTcp { get; internal set; }
        public int? OtherSessionEstablishedTcp { get; internal set; }
    }
}

namespace AppShield.Native
{
    internal static class WeChatLiveStatus
    {
        private enum Group { CurrentUser, OtherUser, OtherSession }
        private sealed class Instance
        {
            internal SafeFileHandle Handle;
            internal long Created;
            internal Group Owner;
            internal int Established;
            internal bool MissingBindTime;
        }

        [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeFileHandle OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeFileHandle process,
            out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeFileHandle process, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ProcessIdToSessionId(int pid, out int session);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeFileHandle process, uint access, out SafeAccessTokenHandle token);
        [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size,
            bool sorted, int family, int tableClass, uint reserved);

        internal static WeChatLiveReport Read(AppProfile profile)
        {
            if (profile == null || !profile.IsWeChat) throw new InvalidOperationException("请先导入已核验的微信。");
            string path = SafeFiles.LocalPath(profile.ExecutablePath);
            using (SafeFiles.PinDirectory(Path.GetDirectoryName(path)))
            using (var image = SafeFiles.OpenImage(path))
            {
                AppShieldEngine.CheckHash(image, profile);
                ImageTrust.Describe(path, image, out string signer);
                if (!WeChatIntegration.IsOfficialClient(path, FileVersionInfo.GetVersionInfo(path), signer))
                    throw new InvalidDataException("微信映像签名或产品信息已改变，请重新导入。");
                return ObserveImage(path, File.GetLastWriteTimeUtc(path).ToFileTimeUtc());
            }
        }

        internal static WeChatLiveReport ObserveImage(string path, long fileWriteTime)
        {
            var report = new WeChatLiveReport();
            var instances = new Dictionary<int, Instance>();
            using (var self = Process.GetCurrentProcess())
            using (var identity = WindowsIdentity.GetCurrent())
            try
            {
                int session = self.SessionId;
                var sid = identity.User;
                foreach (var candidate in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path)))
                using (candidate)
                {
                    int pid = candidate.Id;
                    var handle = OpenProcess(0x101000 /* SYNCHRONIZE | QUERY_LIMITED_INFORMATION */, false, pid);
                    try
                    {
                        if (handle.IsInvalid)
                        {
                            if (Marshal.GetLastWin32Error() != 87) ++report.UnverifiedProcesses;
                            continue;
                        }
                        if (WaitForSingleObject(handle, 0) == 0) continue;
                        if (!string.Equals(NativeJob.Image(handle.DangerousGetHandle()), path, StringComparison.OrdinalIgnoreCase) ||
                            !GetProcessTimes(handle, out long created, out _, out _, out _) || created < fileWriteTime ||
                            !ProcessIdToSessionId(pid, out int processSession) ||
                            !OpenProcessToken(handle, 8 /* TOKEN_QUERY */, out var token))
                        {
                            ++report.UnverifiedProcesses;
                            continue;
                        }
                        using (token)
                        using (var processIdentity = new WindowsIdentity(token.DangerousGetHandle()))
                        {
                            var owner = processIdentity.User;
                            if (owner == null) { ++report.UnverifiedProcesses; continue; }
                            instances.Add(pid, new Instance { Handle = handle, Created = created,
                                Owner = processSession != session ? Group.OtherSession : owner.Equals(sid) ? Group.CurrentUser : Group.OtherUser });
                            handle = null; // Retained until both TCP snapshots and the final liveness check.
                        }
                    }
                    catch (Win32Exception) { ++report.UnverifiedProcesses; }
                    catch (UnauthorizedAccessException) { ++report.UnverifiedProcesses; }
                    finally { handle?.Dispose(); }
                }
                bool complete = instances.Count == 0 || (ReadTcp(2, instances) && ReadTcp(23, instances));
                report.CurrentUserEstablishedTcp = report.OtherUserEstablishedTcp = report.OtherSessionEstablishedTcp = complete ? 0 : (int?)null;
                foreach (var entry in instances.Values)
                {
                    uint state = WaitForSingleObject(entry.Handle, 0);
                    if (state == 0) continue;
                    if (state != 258 /* WAIT_TIMEOUT */) { ++report.UnverifiedProcesses; continue; }
                    int? count = entry.MissingBindTime ? (int?)null : entry.Established;
                    switch (entry.Owner)
                    {
                        case Group.CurrentUser: ++report.CurrentUserProcesses; report.CurrentUserEstablishedTcp += count; break;
                        case Group.OtherUser: ++report.OtherUserProcesses; report.OtherUserEstablishedTcp += count; break;
                        case Group.OtherSession: ++report.OtherSessionProcesses; report.OtherSessionEstablishedTcp += count; break;
                    }
                }
                report.SampleUtc = DateTime.UtcNow;
                return report;
            }
            finally { foreach (var entry in instances.Values) entry.Handle.Dispose(); }
        }

        private static bool ReadTcp(int family, Dictionary<int, Instance> instances)
        {
            // x64 Windows SDK MIB_TCP[6]TABLE_OWNER_MODULE: first row is 8-byte aligned;
            // each row ends with the bind FILETIME followed by 16 opaque module slots.
            // Only the state, PID and creation timestamp are accessed.
            int stateOffset = family == 2 ? 0 : 48, pidOffset = family == 2 ? 20 : 52;
            int timestampOffset = pidOffset + sizeof(int);
            int stride = timestampOffset + sizeof(long) + 16 * sizeof(long);
            int size = 0;
            uint status = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 7 /* OWNER_MODULE_CONNECTIONS */, 0);
            for (int attempt = 0; attempt < 4 && status == 122 && size >= 4 && size <= 64 * 1024 * 1024; attempt++)
            {
                int allocated = size;
                var buffer = Marshal.AllocHGlobal(allocated);
                try
                {
                    status = GetExtendedTcpTable(buffer, ref size, false, family, 7, 0);
                    if (status != 0) continue;
                    int rows = Marshal.ReadInt32(buffer);
                    if (rows < 0 || (rows > 0 && 8L + (long)rows * stride > allocated)) return false;
                    for (int n = 0; n < rows; n++)
                    {
                        var row = IntPtr.Add(buffer, 8 + n * stride);
                        if (Marshal.ReadInt32(row, stateOffset) != 5 /* ESTABLISHED */ ||
                            !instances.TryGetValue(Marshal.ReadInt32(row, pidOffset), out var process)) continue;
                        long bound = Marshal.ReadInt64(row, timestampOffset);
                        if (bound == 0) process.MissingBindTime = true;
                        else if (bound >= process.Created) ++process.Established;
                    }
                    return true;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            return false;
        }
    }
}
