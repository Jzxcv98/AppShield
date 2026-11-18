// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using AppShield.Model;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Native
{
    // This mode uses a real local user's Windows profile on the caller's desktop.
    // Directory access follows that user's NTFS rights. The desktop and clipboard are shared.
    internal static class WeChatAccountLauncher
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct LocalUserInfo
        {
            public IntPtr Name, FullName, Comment;
            public uint Flags;
            public IntPtr Sid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            public int Size;
            public IntPtr Reserved, Desktop, Title;
            public int X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
            public short Show, ReservedBytes;
            public IntPtr ReservedPointer, StdIn, StdOut, StdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Child { public IntPtr Process, Thread; public int Pid, Tid; }

        [StructLayout(LayoutKind.Sequential)]
        private struct Group { public IntPtr Sid; public uint Attributes; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int NetUserGetInfo(string server, string name, int level, out IntPtr data);
        [DllImport("netapi32.dll", ExactSpelling = true)] private static extern int NetApiBufferFree(IntPtr data);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool LogonUserW(string name, string domain, IntPtr password, int type, int provider, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateProcessWithLogonW(string name, string domain, IntPtr password, int logonFlags,
            string app, StringBuilder command, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out Child child);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, int access, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, IntPtr data, int size, out int used);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern bool LookupPrivilegeValueW(string system, string name, out long luid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

        private static Win32Exception LastError(string operation)
        {
            int code = Marshal.GetLastWin32Error();
            return new Win32Exception(code, operation + "失败（Windows " + code + "）：" + new Win32Exception(code).Message);
        }

        internal static SecurityIdentifier VerifyAccount(string localUserName, SecureString password)
        {
            var sid = ResolveLocalAccount(localUserName);
            IntPtr secret = CopyPassword(password);
            try
            {
                using (var token = Logon(localUserName, secret))
                    VerifyToken(token, sid);
                return sid;
            }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
        }

        internal static int Launch(string executablePath, string expectedHash, string localUserName, SecureString password,
            SecurityIdentifier expectedSid = null, bool limitClipboard = false)
        {
            var sid = ResolveLocalAccount(localUserName);
            if (expectedSid != null && !sid.Equals(expectedSid))
                throw new InvalidOperationException("专用账户的 SID 已变化，请重新核对账户和目录授权。");
            string path = SafeFiles.LocalPath(executablePath);
            string installDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Tencent", "Weixin");
            if (!string.Equals(path, Path.Combine(installDir, "Weixin.exe"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("专用账户启动需要 Program Files 中正式安装的微信。");
            using (SafeFiles.PinDirectory(installDir))
            using (var image = SafeFiles.OpenImage(path))
            {
                AppShieldEngine.CheckHash(image, new AppProfile { ImageHash = expectedHash });
                ImageTrust.Describe(path, image, out var signer);
                if (!WeChatIntegration.IsOfficialClient(path, FileVersionInfo.GetVersionInfo(path), signer))
                    throw new InvalidDataException("无法核对微信主程序的签名或产品信息。");
                IntPtr secret = CopyPassword(password);
                try
                {
                    using (var logon = Logon(localUserName, secret))
                    {
                        VerifyToken(logon, sid);
                        var si = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfo)) };
                        // Windows builds the environment from the dedicated account and loads its HKCU.
                        if (!CreateProcessWithLogonW(localUserName, ".", secret, 1 /* LOGON_WITH_PROFILE */,
                            path, new StringBuilder("\"" + path + "\""), 4 /* CREATE_SUSPENDED */, IntPtr.Zero,
                            installDir, ref si, out var child)) throw LastError("以专用账户创建微信进程");
                        try
                        {
                            using (var token = OpenChildToken(child.Process, logon))
                            using (var caller = Process.GetCurrentProcess())
                            {
                                VerifyToken(token, sid);
                                int session = ReadToken(token, 12 /* TokenSessionId */, (p, n) => Marshal.ReadInt32(p), sizeof(int));
                                if (session == 0 || session != caller.SessionId ||
                                    !string.Equals(NativeJob.Image(child.Process), path, StringComparison.OrdinalIgnoreCase))
                                    throw new InvalidOperationException("新进程的桌面会话或实际映像不符。");
                            }
                            using (limitClipboard ? WeChatClipboardJob.BindSuspended(child.Process) : null)
                            {
                                if (ResumeThread(child.Thread) == uint.MaxValue) throw LastError("恢复微信主线程");
                            }
                            return child.Pid;
                        }
                        catch
                        {
                            if (!TerminateProcess(child.Process, 1)) throw LastError("清理本次未通过核对的进程");
                            throw;
                        }
                        finally { CloseHandle(child.Thread); CloseHandle(child.Process); }
                    }
                }
                finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
            }
        }

        private static SecurityIdentifier ResolveLocalAccount(string name)
        {
            if (string.IsNullOrWhiteSpace(name) || name != name.Trim() || name.IndexOfAny(new[] {'\\','/','@','\0'}) >= 0)
                throw new ArgumentException("请输入本机专用标准账户名。");
            int err = NetUserGetInfo(null, name, 23 /* USER_INFO_23 */, out var data);
            if (err != 0) throw new Win32Exception(err, "查询本机账户失败（Windows " + err + "）：" + new Win32Exception(err).Message);
            try
            {
                var user = Marshal.PtrToStructure<LocalUserInfo>(data);
                var sid = new SecurityIdentifier(user.Sid);
                if ((user.Flags & 0x202) != 0x200 || !sid.IsAccountSid() ||
                    !uint.TryParse(sid.Value.Substring(sid.Value.LastIndexOf('-') + 1), out var rid) || rid < 1000)
                    throw new InvalidOperationException("需要已启用的本机专用标准账户。");
                using (var current = WindowsIdentity.GetCurrent())
                    if (sid.Equals(current.User)) throw new InvalidOperationException("请选择与当前 Windows 用户不同的账户。");
                return sid;
            }
            finally { NetApiBufferFree(data); }
        }

        private static IntPtr CopyPassword(SecureString password)
        {
            if (password == null || password.Length == 0) throw new ArgumentException("请输入专用 Windows 账户密码。");
            return Marshal.SecureStringToGlobalAllocUnicode(password);
        }

        private static SafeAccessTokenHandle Logon(string name, IntPtr secret)
        {
            if (!LogonUserW(name, ".", secret, 2 /* interactive */, 0, out var token)) throw LastError("验证专用账户凭据");
            return token;
        }

        private static SafeAccessTokenHandle OpenChildToken(IntPtr process, SafeAccessTokenHandle account)
        {
            // The new token's DACL can grant the secondary user query access without granting it to the host.
            return WindowsIdentity.RunImpersonated(account, () => {
                if (!OpenProcessToken(process, 8 /* TOKEN_QUERY */, out var child)) throw LastError("核对新进程的账户令牌");
                return child;
            });
        }

        private static T ReadToken<T>(SafeAccessTokenHandle token, int kind, Func<IntPtr, int, T> read, int fixedSize = 0)
        {
            int size = fixedSize;
            if (size == 0)
            {
                GetTokenInformation(token, kind, IntPtr.Zero, 0, out size);
                int error = Marshal.GetLastWin32Error();
                if (error != 122 || size < 4 || size > 1024 * 1024)
                    throw new Win32Exception(error, "查询 Windows 令牌字段 " + kind + " 所需长度失败（Windows " + error + "，长度 " + size + "）。");
            }
            IntPtr data = Marshal.AllocHGlobal(size);
            try
            {
                if (!GetTokenInformation(token, kind, data, size, out var used)) throw LastError("读取 Windows 令牌字段 " + kind);
                if (used < 4 || used > size || (fixedSize != 0 && used != fixedSize)) throw new InvalidDataException("Windows 返回了无效的令牌字段长度。");
                return read(data, used);
            }
            finally { Marshal.FreeHGlobal(data); }
        }

        private static void VerifyToken(SafeAccessTokenHandle token, SecurityIdentifier sid)
        {
            if (!ReadToken(token, 1 /* TokenUser */, (p, n) => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Equals(sid)) ||
                ReadToken(token, 20 /* TokenElevation */, (p, n) => Marshal.ReadInt32(p), sizeof(int)) != 0)
                throw new InvalidOperationException("Windows 令牌与专用非提升账户不符。");

            bool privilegedGroup = ReadToken(token, 2 /* TokenGroups */, (p, n) => {
                int count = Marshal.ReadInt32(p);
                int stride = Marshal.SizeOf(typeof(Group));
                if (count < 0 || count > (n - IntPtr.Size) / stride) throw new InvalidDataException("无效的令牌组列表。");
                for (int i = 0; i < count; i++)
                {
                    var group = new SecurityIdentifier(Marshal.ReadIntPtr(p, IntPtr.Size + i * stride));
                    // Inspect every SID, including UAC's deny-only Administrators entry.
                    if (group.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                        group.IsWellKnown(WellKnownSidType.BuiltinBackupOperatorsSid)) return true;
                }
                return false;
            });
            if (privilegedGroup) throw new InvalidOperationException("专用账户不能属于管理员或备份操作员组。");

            // A locally delegated privilege can override file DACLs even outside those groups.
            var privileged = new System.Collections.Generic.HashSet<long>();
            foreach (string name in new[] { "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeDebugPrivilege",
                "SeTcbPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeCreateTokenPrivilege", "SeLoadDriverPrivilege" })
            {
                if (!LookupPrivilegeValueW(null, name, out var luid)) throw LastError("核实 Windows 特权 " + name);
                privileged.Add(luid);
            }
            bool overrideRights = ReadToken(token, 3 /* TokenPrivileges */, (p, n) => {
                int count = Marshal.ReadInt32(p);
                // TOKEN_PRIVILEGES contains a DWORD followed by 12-byte LUID_AND_ATTRIBUTES entries.
                if (count < 0 || count > (n - 4) / 12) throw new InvalidDataException("无效的令牌特权列表。");
                for (int i = 0; i < count; i++)
                    if (privileged.Contains(Marshal.ReadInt64(p, 4 + i * 12))) return true;
                return false;
            });
            if (overrideRights) throw new InvalidOperationException("专用账户含有可改变系统或越过数据访问限制的特权。");
        }
    }
}
