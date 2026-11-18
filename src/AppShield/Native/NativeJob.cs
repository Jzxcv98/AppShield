// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using AppShield.Model;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Native
{
    internal static class NativeJob
    {
        // Win32 Job restrictions apply to the entire job, including descendants.
        private const int UiFlags = 0x2 | 0x4 | 0x40;
        private const int UiClass = 4, AccountingClass = 1;
        internal static string JobName(Guid id) => @"Local\AppShield.Native.Job." + id.ToString("N");

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityCaps { public IntPtr Package, Groups; public uint Count, Reserved; }
        [StructLayout(LayoutKind.Sequential)]
        private struct SidAttr { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Startup
        {
            public int Size; public IntPtr Reserved, Desktop, Title; public int X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
            public short Show, ReservedBytes; public IntPtr ReservedPointer, StdIn, StdOut, StdErr;
        }
        [StructLayout(LayoutKind.Sequential)] private struct StartupEx { public Startup Info; public IntPtr Attrs; }
        [StructLayout(LayoutKind.Sequential)] private struct Child { public IntPtr Process, Thread; public int Pid, Tid; }
        [StructLayout(LayoutKind.Sequential)]
        private struct Accounting
        {
            public long User, Kernel, PeriodUser, PeriodKernel;
            public uint Faults, Total, Active, Terminated;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Limits
        {
            public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinWorkingSet, MaxWorkingSet;
            public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ExtLimits
        {
            public Limits Basic; public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
            public UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob;
        }
        [DllImport("kernel32.dll", EntryPoint = "SetInformationJobObject", SetLastError = true)]
        private static extern bool SetJobLimits(SafeFileHandle job, int cls, ref ExtLimits limit, int bytes);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr sa, string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle OpenJobObject(uint access, bool inherit, string name);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, int cls, ref int data, int bytes);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(SafeFileHandle job, int cls, out int data, int bytes, IntPtr length);
        [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)] private static extern bool JobAccounting(SafeFileHandle job, int cls, out Accounting data, int bytes, IntPtr length);
        [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)] private static extern bool JobProcessList(SafeFileHandle job, int cls, IntPtr data, int bytes, out int returned);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(SafeFileHandle job, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(IntPtr process, SafeFileHandle job, out bool inside);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr key, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessW(string image, StringBuilder cmd, IntPtr sa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref StartupEx start, out Child child);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageName(IntPtr handle, uint flags, StringBuilder path, ref int count);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeFileHandle OpenProcess(uint rights, bool inherit, int pid);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint rights, out SafeFileHandle token);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeFileHandle token, int kind, IntPtr data, int bytes, out int needed);

        private static void Check(bool result, string stage)
        {
            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error(), stage + "失败（Windows " + Marshal.GetLastWin32Error() + "）。");
        }
        private sealed class Memory : IDisposable
        {
            private readonly List<IntPtr> items = new List<IntPtr>();
            public IntPtr Alloc(int size) { var p = Marshal.AllocHGlobal(size); items.Add(p); return p; }
            public IntPtr Value<T>(T v) where T : struct { var p = Alloc(Marshal.SizeOf(typeof(T))); Marshal.StructureToPtr(v, p, false); return p; }
            public IntPtr Sid(SecurityIdentifier sid) { var b = new byte[sid.BinaryLength]; sid.GetBinaryForm(b, 0); var p = Alloc(b.Length); Marshal.Copy(b, 0, p, b.Length); return p; }
            public void Dispose() { foreach (var p in items) Marshal.FreeHGlobal(p); }
        }
        private static IntPtr TokenData(SafeFileHandle token, int kind, Memory mem)
        {
            GetTokenInformation(token, kind, IntPtr.Zero, 0, out int n);
            if (n < 4 || n > 1024 * 1024) throw new Win32Exception(Marshal.GetLastWin32Error());
            var data = mem.Alloc(n); Check(GetTokenInformation(token, kind, data, n, out n), "查询令牌"); return data;
        }
        private static bool IsOurToken(IntPtr process, SecurityIdentifier expected, IEnumerable<string> caps)
        {
            Check(OpenProcessToken(process, 8, out var token), "打开进程令牌");
            using (token) using (var mem = new Memory())
            {
                if (Marshal.ReadInt32(TokenData(token, 29, mem)) == 0) return false;
                var ptr = Marshal.ReadIntPtr(TokenData(token, 31, mem));
                if (ptr == IntPtr.Zero || !new SecurityIdentifier(ptr).Equals(expected)) return false;
                if (caps == null) return true;
                var data = TokenData(token, 30, mem);
                int count = Marshal.ReadInt32(data);
                var remaining = new HashSet<string>(caps, StringComparer.OrdinalIgnoreCase);
                if (count != remaining.Count) return false;
                for (int i = 0; i < count; i++)
                {
                    var entry = (SidAttr)Marshal.PtrToStructure(IntPtr.Add(data, IntPtr.Size + i * Marshal.SizeOf(typeof(SidAttr))), typeof(SidAttr));
                    if ((entry.Attributes & 4) == 0 || !remaining.Remove(new SecurityIdentifier(entry.Sid).Value)) return false;
                }
                return remaining.Count == 0;
            }
        }
        private static bool Inside(IntPtr process, SafeFileHandle job)
        {
            Check(IsProcessInJob(process, job, out var inside), "查询 Job 归属"); return inside;
        }
        private static bool HasUiLimits(SafeFileHandle job)
        {
            Check(QueryInformationJobObject(job, UiClass, out int active, 4, IntPtr.Zero), "查询剪贴板边界");
            return (active & UiFlags) == UiFlags;
        }
        internal static bool Active(Guid id)
        {
            using (var job = OpenJobObject(4, false, JobName(id)))
            {
                if (job.IsInvalid) { int err = Marshal.GetLastWin32Error(); if (err == 2) return false; throw new Win32Exception(err); }
                Check(JobAccounting(job, AccountingClass, out var data, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero), "查询运行数量"); return data.Active != 0;
            }
        }
        // A named job's name may disappear once its last user handle closes, while the
        // processes still run. The trusted keeper owns one query handle for the tree's
        // lifetime. Kill-on-last-close also covers an abnormal keeper exit.
        internal static int Keep(Guid id, Guid nonce)
        {
            using (var job = OpenJobObject(4, false, JobName(id)))
            {
                if (job.IsInvalid || !HasUiLimits(job)) return 1;
                using (var ack = EventWaitHandle.OpenExisting(AckName(nonce))) ack.Set();
                while (true)
                {
                    Check(JobAccounting(job, AccountingClass, out var info, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero), "核对受管进程树");
                    if (info.Active == 0) return 0;
                    Thread.Sleep(200);
                }
            }
        }
        private static string AckName(Guid value) => @"Local\AppShield.JobReady." + value.ToString("N");
        private static void StartKeeper(Guid id)
        {
            var nonce = Guid.NewGuid();
            using (var ack = new EventWaitHandle(false, EventResetMode.ManualReset, AckName(nonce)))
            using (var keeper = Process.Start(new ProcessStartInfo(typeof(NativeJob).Assembly.Location,
                "--keep-job " + id.ToString("N") + " " + nonce.ToString("N"))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Environment.SystemDirectory
            }))
            {
                if (keeper == null || !ack.WaitOne(10000) || keeper.HasExited)
                    throw new InvalidOperationException("无法保留进程树的监督句柄，已停止启动。");
            }
        }
        internal static string Image(IntPtr process)
        {
            var path = new StringBuilder(32768); int count = path.Capacity;
            Check(QueryFullProcessImageName(process, 0, path, ref count), "核对进程映像"); return path.ToString();
        }
        private static List<int> MemberSnapshot(SafeFileHandle job)
        {
            const int header = 2 * sizeof(uint);
            for (int capacity = 32; capacity <= 131072; capacity *= 2)
            {
                int size = checked(header + capacity * IntPtr.Size);
                IntPtr data = Marshal.AllocHGlobal(size);
                try
                {
                    if (!JobProcessList(job, 3 /* JobObjectBasicProcessIdList */, data, size, out _))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 234) continue; // Membership grew before the query completed.
                        throw new Win32Exception(error, "无法枚举此 Job 中的进程。");
                    }
                    int assigned = Marshal.ReadInt32(data), count = Marshal.ReadInt32(data, sizeof(uint));
                    if (assigned > count) continue;
                    if (count < 0 || assigned < 0 || count > capacity || count != assigned)
                        throw new InvalidDataException("Windows 返回了无效的 Job 进程列表。");
                    var ids = new List<int>(count);
                    for (int i = 0; i < count; i++)
                        ids.Add(checked((int)Marshal.ReadIntPtr(data, header + i * IntPtr.Size).ToInt64()));
                    return ids;
                }
                finally { Marshal.FreeHGlobal(data); }
            }
            throw new InvalidOperationException("进程树变化过快，暂时无法确认所有成员。");
        }

        private static List<int> ConfirmMembers(SafeFileHandle job, SecurityIdentifier sid, IEnumerable<string> caps, out int unknown)
        {
            unknown = 0;
            bool limits = HasUiLimits(job);
            var ids = new List<int>();
            foreach (int pid in MemberSnapshot(job))
            using (var handle = OpenProcess(0x101000, false, pid))
            {
                if (handle.IsInvalid)
                {
                    // An exited process can disappear between enumeration and OpenProcess.
                    if (Marshal.GetLastWin32Error() != 87) unknown++;
                    continue;
                }
                IntPtr h = handle.DangerousGetHandle();
                if (WaitForSingleObject(h, 0) == 0) continue;
                try
                {
                    // Reused PIDs pointing outside this job are not its members.
                    if (!Inside(h, job)) continue;
                    bool verified = limits && IsOurToken(h, sid, caps);
                    if (WaitForSingleObject(h, 0) == 0) continue;
                    if (verified) ids.Add(pid); else unknown++;
                }
                catch (Win32Exception) { if (WaitForSingleObject(h, 0) != 0) unknown++; }
            }
            return ids;
        }

        internal static List<int> Observe(AppProfile profile, string runtimeImage, SecurityIdentifier sid, out int outside, out int unknown)
        {
            var ids = new List<int>(); outside = 0; unknown = 0;
            using (var job = OpenJobObject(4, false, JobName(profile.Id)))
            {
                int openError = job.IsInvalid ? Marshal.GetLastWin32Error() : 0;
                if (!job.IsInvalid) ids = ConfirmMembers(job, sid, null, out unknown);
                else if (openError != 2) unknown++;
                var names = profile.IsWeChat ? new[] { "Weixin", "WeChat" }
                    : new[] { Path.GetFileNameWithoutExtension(profile.ExecutablePath) };
                foreach (var proc in names.SelectMany(Process.GetProcessesByName))
                    using (proc) using (var handle = OpenProcess(0x101000, false, proc.Id))
                    {
                        if (handle.IsInvalid) { if (Marshal.GetLastWin32Error() != 87) unknown++; continue; }
                        try
                        {
                            var h = handle.DangerousGetHandle(); if (WaitForSingleObject(h, 0) == 0) continue;
                            string actual = Image(h);
                            bool knownImage = SamePath(actual, profile.ExecutablePath) || SamePath(actual, runtimeImage);
                            if (!knownImage && (!profile.IsWeChat ||
                                !names.Contains(Path.GetFileNameWithoutExtension(actual), StringComparer.OrdinalIgnoreCase))) continue;
                            if (!job.IsInvalid && Inside(h, job)) continue; // Counted by the complete job snapshot.
                            // Another installation or the legacy client may receive a single-instance handoff.
                            // A filename alone cannot verify that this is WeChat. Leave its process untouched.
                            if (!knownImage) { unknown++; continue; }
                            if (IsOurToken(h, sid, null)) unknown++;
                            else if (openError == 0 || openError == 2) outside++; else unknown++;
                        }
                        catch (Win32Exception) { unknown++; }
                    }
            }
            return ids;
        }
        private static bool SamePath(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        private static SafeFileHandle CreateFreshJob(Guid id)
        {
            var elapsed = Stopwatch.StartNew();
            while (true)
            {
                var job = CreateJobObject(IntPtr.Zero, JobName(id));
                int error = Marshal.GetLastWin32Error();
                if (job.IsInvalid) { job.Dispose(); throw new Win32Exception(error, "无法创建受管 Job。"); }
                if (error != 183) return job;
                // A keeper can retain the previous empty job for a single poll.
                // Leave its settings and member processes completely untouched.
                using (job)
                {
                    Check(JobAccounting(job, AccountingClass, out var current, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero), "查询已有进程树");
                    if (current.Active != 0 || elapsed.ElapsedMilliseconds >= 1500)
                        throw new InvalidOperationException("已有同名进程树仍在运行或回收中，请稍后刷新。");
                }
                Thread.Sleep(50);
            }
        }

        internal static List<int> Launch(AppProfile p, ContainerIdentity identity, string image, string work, string[] args,
            out uint? launcherExitCode)
        {
            launcherExitCode = null;
            using (var job = CreateFreshJob(p.Id)) using (var mem = new Memory())
            {
                Check(JobAccounting(job, AccountingClass, out var active, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero), "查询 Job");
                if (active.Active != 0) throw new InvalidOperationException("本应用已有受管进程，请关闭后重新启动。");
                var lifetime = new ExtLimits { Basic = new Limits { Flags = 0x2000 } };
                Check(SetJobLimits(job, 9, ref lifetime, Marshal.SizeOf(typeof(ExtLimits))), "设置进程树退出规则");
                int limits = UiFlags;
                Check(SetInformationJobObject(job, UiClass, ref limits, 4), "设置剪贴板边界");
                if (!HasUiLimits(job)) throw new InvalidOperationException("Windows 未确认剪贴板 Job 限制。");
                var capSids = new List<string>();
                if (p.AllowInternet) capSids.Add("S-1-15-3-1"); // internetClient
                if (!p.BlockLan) capSids.Add("S-1-15-3-3"); // privateNetworkClientServer
                int groupBytes = Marshal.SizeOf(typeof(SidAttr));
                var groups = capSids.Count == 0 ? IntPtr.Zero : mem.Alloc(capSids.Count * groupBytes);
                for (int i = 0; i < capSids.Count; i++)
                    Marshal.StructureToPtr(new SidAttr { Sid = mem.Sid(new SecurityIdentifier(capSids[i])), Attributes = 4 }, IntPtr.Add(groups, i * groupBytes), false);
                var caps = new SecurityCaps { Package = identity.Pointer, Groups = groups, Count = (uint)capSids.Count };
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                var list = mem.Alloc(size.ToInt32());
                Check(InitializeProcThreadAttributeList(list, 2, 0, ref size), "创建启动属性");
                try
                {
                    Check(UpdateProcThreadAttribute(list, 0, new IntPtr(0x20009), mem.Value(caps), new IntPtr(Marshal.SizeOf(typeof(SecurityCaps))), IntPtr.Zero, IntPtr.Zero), "绑定应用权限");
                    var jobPtr = mem.Alloc(IntPtr.Size); Marshal.WriteIntPtr(jobPtr, job.DangerousGetHandle());
                    Check(UpdateProcThreadAttribute(list, 0, new IntPtr(0x2000d), jobPtr, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "绑定进程树");
                    var start = new StartupEx { Info = new Startup { Size = Marshal.SizeOf(typeof(StartupEx)) }, Attrs = list };
                    string temp = Path.Combine(identity.Folder, "AppShieldTemp");
                    Directory.CreateDirectory(temp);
                    var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    string roaming = work, local = work;
                    if (p.IsWeChat)
                    {
                        roaming = Path.Combine(work, "AppData", "Roaming");
                        local = Path.Combine(work, "AppData", "Local");
                        SafeFiles.PlainDirectories(roaming, true);
                        SafeFiles.PlainDirectories(local, true);
                        SafeFiles.PlainDirectories(Path.Combine(work, "Documents"), true);
                    }
                    string block = string.Join("\0", new[]{ "APPDATA="+roaming,"LOCALAPPDATA="+local,
                        "PATH="+Environment.SystemDirectory,"SystemDrive="+windir.Substring(0,2),"SystemRoot="+windir,
                        "TEMP="+temp,"TMP="+temp,"USERPROFILE="+work,"WINDIR="+windir }) + "\0\0";
                    byte[] bytes = Encoding.Unicode.GetBytes(block);
                    var env = mem.Alloc(bytes.Length); Marshal.Copy(bytes, 0, env, bytes.Length);
                    var cmd = new StringBuilder(string.Join(" ", new[] { image }.Concat(args).Select(Quote)));
                    string cwd = p.IsWeChat ? Path.GetDirectoryName(image) : work;
                    Check(CreateProcessW(image, cmd, IntPtr.Zero, IntPtr.Zero, false, 0x00080404, env, cwd, ref start, out var child), "挂起创建受限程序");
                    try
                    {
                        if (!Inside(child.Process, job) || !IsOurToken(child.Process, identity.Sid, capSids) || !SamePath(Image(child.Process), image))
                            throw new InvalidOperationException("Windows 没有确认预期映像、进程身份或能力。");
                        StartKeeper(p.Id);
                        Check(ResumeThread(child.Thread) != uint.MaxValue, "恢复受管程序");
                        // WeChat can display a short-lived window before its launcher exits.
                        uint rootState = WaitForSingleObject(child.Process, p.IsWeChat ? 5000u : 1250u);
                        Check(rootState == 0 || rootState == 258, "观察启动器");
                        var members = ConfirmMembers(job, identity.Sid, capSids, out int unverified);
                        if (rootState == 258 && !members.Contains(child.Pid))
                        {
                            // The launcher can exit while the Job snapshot is being verified.
                            rootState = WaitForSingleObject(child.Process, 0);
                            Check(rootState == 0 || rootState == 258, "复核启动器");
                        }
                        if (rootState == 0)
                        {
                            Check(GetExitCodeProcess(child.Process, out var code), "查询启动器退出码");
                            launcherExitCode = code;
                        }
                        if (members.Count > 0 && unverified == 0) return members;
                        if (launcherExitCode.HasValue)
                            throw new InvalidOperationException("启动器已退出（" + launcherExitCode.Value + "，0x" + launcherExitCode.Value.ToString("X8") + "），未确认仍在此身份和 Job 中运行的子进程。");
                        throw new InvalidOperationException("无法确认受管进程树的身份和能力。");
                    }
                    catch
                    {
                        // This handle refers to our newly created job, never to an
                        // existing profile's running tree. Remove descendants as well.
                        Check(TerminateJobObject(job, 1), "终止本轮未确认的进程树");
                        throw;
                    }
                    finally { CloseHandle(child.Thread); CloseHandle(child.Process); }
                }
                finally { DeleteProcThreadAttributeList(list); GC.KeepAlive(job); }
            }
        }
        private static string Quote(string s)
        {
            if (s.IndexOfAny(new[] { '"', '\0', '\r', '\n' }) >= 0) throw new ArgumentException("启动参数无效。");
            return "\"" + s + new string('\\', s.Length - s.TrimEnd('\\').Length) + "\"";
        }
    }
}
