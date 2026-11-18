// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using AppShield.Model;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Native
{
    internal static class WeChatClipboardJob
    {
        private const int UiClass = 4;
        internal const int ClipboardLimits = 0x2 | 0x4; // READCLIPBOARD and WRITECLIPBOARD

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref int flags, int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(SafeFileHandle job, int infoClass, out int flags, int size, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(IntPtr process, SafeFileHandle job, out bool member);

        [StructLayout(LayoutKind.Sequential)]
        private struct Startup
        {
            public int Size;
            public IntPtr Reserved, Desktop, Title;
            public int X, Y, Width, Height, Columns, Rows, Fill, Flags;
            public short Show, ReservedBytes;
            public IntPtr ReservedPointer, StdIn, StdOut, StdErr;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Child { public IntPtr Process, Thread; public int Pid, Tid; }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateProcessW(string image, StringBuilder command, IntPtr processAttributes,
            IntPtr threadAttributes, bool inherit, int flags, IntPtr environment, string cwd, ref Startup startup, out Child child);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, int rights, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, out int value, int bytes, out int used);
        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr environment, SafeAccessTokenHandle token, bool inherit);
        [DllImport("userenv.dll")] private static extern bool DestroyEnvironmentBlock(IntPtr environment);

        private static SafeAccessTokenHandle OpenToken(IntPtr process, int rights)
        {
            if (!OpenProcessToken(process, rights, out var token)) throw Error("打开 Windows 进程令牌");
            return token;
        }

        private static int TokenValue(SafeAccessTokenHandle token, int kind)
        {
            if (!GetTokenInformation(token, kind, out int value, sizeof(int), out int size))
                throw Error("核查 Windows 令牌");
            if (size != sizeof(int)) throw new InvalidDataException("Windows 返回了无效的令牌字段。");
            return value;
        }

        internal static int LaunchCurrentUser(string path, string expectedHash)
        {
            using (StartCurrentUser(path, expectedHash, out int pid)) return pid;
        }

        // The caller can retain the returned job for inspection. Disposing it is safe while the client runs.
        internal static SafeFileHandle StartCurrentUser(string executablePath, string expectedHash, out int pid)
        {
            string path = SafeFiles.LocalPath(executablePath);
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Tencent", "Weixin");
            if (!string.Equals(path, Path.Combine(dir, "Weixin.exe"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("剪贴板受限启动需要 Program Files 中正式安装的微信。");
            using (SafeFiles.PinDirectory(dir))
            using (var image = SafeFiles.OpenImage(path))
            using (var host = Process.GetCurrentProcess())
            using (var token = OpenToken(host.Handle, 0x000a /* TOKEN_QUERY | TOKEN_DUPLICATE */))
            using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
            {
                if (host.SessionId == 0 || TokenValue(token, 20 /* TokenElevation */) != 0)
                    throw new InvalidOperationException("请在普通用户的交互式桌面运行 AppShield。");
                AppShieldEngine.CheckHash(image, new AppProfile { ImageHash = expectedHash });
                ImageTrust.Describe(path, image, out string signer);
                if (!WeChatIntegration.IsOfficialClient(path, FileVersionInfo.GetVersionInfo(path), signer))
                    throw new InvalidDataException("微信主程序的签名或产品信息无法核实。");

                if (!CreateEnvironmentBlock(out var environment, token, false)) throw Error("构造当前用户环境");
                Child child;
                try
                {
                    var startup = new Startup { Size = Marshal.SizeOf(typeof(Startup)) };
                    if (!CreateProcessW(path, new StringBuilder("\"" + path + "\""), IntPtr.Zero, IntPtr.Zero,
                        false, 0x404 /* UNICODE_ENVIRONMENT | SUSPENDED */, environment, dir, ref startup, out child))
                        throw Error("挂起启动微信");
                }
                finally { DestroyEnvironmentBlock(environment); }

                SafeFileHandle job = null;
                try
                {
                    using (var childToken = OpenToken(child.Process, 8))
                    using (var actual = new WindowsIdentity(childToken.DangerousGetHandle()))
                    {
                        if (!identity.User.Equals(actual.User) || TokenValue(childToken, 12 /* TokenSessionId */) != host.SessionId ||
                            TokenValue(childToken, 20) != 0 || !string.Equals(NativeJob.Image(child.Process), path, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException("微信进程映像、用户或桌面会话不符。");
                    }
                    job = BindSuspended(child.Process);
                    if (ResumeThread(child.Thread) == uint.MaxValue) throw Error("恢复微信主线程");
                    pid = child.Pid;
                    return job;
                }
                catch
                {
                    job?.Dispose();
                    if (!TerminateProcess(child.Process, 1)) throw Error("终止本次未通过核对的进程");
                    throw;
                }
                finally { CloseHandle(child.Thread); CloseHandle(child.Process); }
            }
        }

        private static Win32Exception Error(string operation)
        {
            int code = Marshal.GetLastWin32Error();
            return new Win32Exception(code, operation + "失败（Windows " + code + "）。");
        }

        // The caller owns this newly created process, still suspended, and terminates it on failure.
        // The anonymous job has neither a breakaway flag nor KILL_ON_JOB_CLOSE: normal descendants
        // inherit these limits and closing AppShield does not terminate the client.
        internal static SafeFileHandle BindSuspended(IntPtr process)
        {
            var job = CreateJobObjectW(IntPtr.Zero, null);
            try
            {
                if (job.IsInvalid) throw Error("创建剪贴板 Job");
                int flags = ClipboardLimits;
                if (!SetInformationJobObject(job, UiClass, ref flags, sizeof(int)))
                    throw Error("设置剪贴板读写限制");
                if (!QueryInformationJobObject(job, UiClass, out int effective, sizeof(int), IntPtr.Zero))
                    throw Error("读取剪贴板限制");
                if (effective != flags) throw new InvalidOperationException("Windows 未确认所选剪贴板限制。");
                if (!AssignProcessToJobObject(job, process)) throw Error("绑定新进程的剪贴板限制");
                if (!IsProcessInJob(process, job, out bool member)) throw Error("查询剪贴板 Job 成员");
                if (!member) throw new InvalidOperationException("Windows 未确认进程处于所选剪贴板 Job。");
                return job;
            }
            catch
            {
                job.Dispose();
                throw;
            }
        }
    }
}
