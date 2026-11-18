// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Xml;

namespace AppShield.Native
{
    internal sealed class WeChatSandboxLauncher
    {
        internal const string SupportedVersion = "4.2.0.53";
        // Tencent.WeChat.Universal x64 WinGet manifest and Microsoft's Store catalog.
        internal const string InstallerHash = "A463110FED2DAD8F27A313A1E5118CFBBE8B9DE2B9296DB8015A496E07191052";
        private const long InstallerSize = 259805488;
        private const string InstallerName = "WeChatSetup.exe";
        private const string Publisher = "Tencent Technology (Shenzhen) Company Limited";
        private readonly string cache, input, installer;

        internal WeChatSandboxLauncher(string storageRoot)
        {
            cache = Path.Combine(SafeFiles.LocalPath(storageRoot), "WeChatSandbox");
            input = Path.Combine(cache, SupportedVersion, "Input");
            installer = Path.Combine(input, InstallerName);
        }

        private static void CheckVersion(string version)
        {
            if (version != SupportedVersion)
                throw new NotSupportedException("当前沙盒启动器只收录微信 " + SupportedVersion + " x64 的官方安装包摘要。");
        }

        // A cheap setup hint. Launch always validates both content and Authenticode again.
        internal bool HasInstaller(string version) => version == SupportedVersion &&
            File.Exists(installer) && new FileInfo(installer).Length == InstallerSize;

        private SafeFiles.DirectoryLease PinCache(bool create)
        {
            using (SafeFiles.PinDirectory(Path.GetDirectoryName(cache), create))
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var owner = identity.User;
                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                if (create && !Directory.Exists(cache))
                {
                    var acl = new DirectorySecurity();
                    acl.SetAccessRuleProtection(true, false);
                    acl.SetOwner(owner);
                    foreach (var sid in new[] {owner, system})
                        acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                            PropagationFlags.None, AccessControlType.Allow));
                    Directory.CreateDirectory(cache, acl);
                }
                var lease = SafeFiles.PinDirectory(cache);
                try
                {
                    var security = Directory.GetAccessControl(cache, AccessControlSections.Owner | AccessControlSections.Access);
                    if (!owner.Equals(security.GetOwner(typeof(SecurityIdentifier))) || !security.AreAccessRulesProtected ||
                        security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                            .Any(rule => !owner.Equals(rule.IdentityReference) && !system.Equals(rule.IdentityReference)))
                        throw new IOException("无法核实微信沙盒安装包专用目录的访问权限。");
                    return lease;
                }
                catch { lease.Dispose(); throw; }
            }
        }

        internal void ImportInstaller(string source, string version)
        {
            CheckVersion(version);
            source = SafeFiles.LocalPath(source);
            if (!Path.GetExtension(source).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("请选择腾讯官方 Windows x64 安装程序。");
            using (SafeFiles.PinDirectory(Path.GetDirectoryName(source)))
            using (var original = SafeFiles.OpenImage(source))
            {
                VerifyInstaller(source, original);
                using (PinCache(true))
                using (SafeFiles.PinDirectory(input, true))
                {
                    bool replace = File.Exists(installer);
                    if (replace)
                    {
                        using (var existing = SafeFiles.OpenRead(installer, true))
                        {
                            try { VerifyInstaller(installer, existing); return; }
                            catch (InvalidDataException) { /* Replace only a plain file, with our verified candidate. */ }
                        }
                    }
                    // Stage outside the only directory that the guest can see.
                    string temp = Path.Combine(cache, Guid.NewGuid().ToString("N") + ".tmp");
                    try
                    {
                        using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                        {
                            original.Position = 0;
                            original.CopyTo(output);
                            output.Flush(true);
                            CheckDigest(output);
                        }
                        try
                        {
                            if (replace) File.Replace(temp, installer, null);
                            else File.Move(temp, installer);
                        }
                        catch (IOException) when (File.Exists(installer))
                        { using (var existing = SafeFiles.OpenRead(installer, true)) VerifyInstaller(installer, existing); }
                    }
                    finally { if (File.Exists(temp)) File.Delete(temp); }
                }
            }
        }

        private static void CheckDigest(FileStream stream)
        {
            if (stream.Length != InstallerSize) throw new InvalidDataException("安装包大小与官方微信版本不符。");
            stream.Position = 0;
            using (var sha = SHA256.Create())
                if (BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "") != InstallerHash)
                    throw new InvalidDataException("安装包 SHA-256 与官方微信版本不符。");
        }

        private static void VerifyInstaller(string path, FileStream stream)
        {
            CheckDigest(stream);
            ImageTrust.Describe(path, stream, out var signer);
            if (!Publisher.Equals(signer, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Windows 未确认预期的腾讯安装包签名。");
        }

        internal string Launch(string version, bool allowNetwork)
        {
            CheckVersion(version);
            RequireInteractiveUser();
            if (!HasInstaller(version)) throw new FileNotFoundException("请先为微信沙盒选择官方 x64 安装包。");
            using (var gate = new Mutex(false, @"Local\AppShield.WeChatSandbox.Launch"))
            {
                bool held;
                try { held = gate.WaitOne(TimeSpan.Zero); } catch (AbandonedMutexException) { held = true; }
                if (!held) throw new InvalidOperationException("另一窗口正在启动 Windows 沙盒。");
                try
                {
                    using (PinCache(false))
                    using (SafeFiles.PinDirectory(input))
                    using (var binary = SafeFiles.OpenRead(installer, true))
                    {
                        if (!Directory.GetFileSystemEntries(input).SequenceEqual(new[] {installer}, StringComparer.OrdinalIgnoreCase))
                            throw new IOException("共享输入目录应只含已核验的微信安装包。");
                        VerifyInstaller(installer, binary);
                        return StartSandbox(BuildConfig(input, allowNetwork, Guid.NewGuid()));
                    }
                }
                finally { gate.ReleaseMutex(); }
            }
        }

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool WTSQuerySessionInformationW(IntPtr server, int session, int info, out IntPtr text, out int bytes);
        [DllImport("wtsapi32.dll", ExactSpelling = true)] private static extern void WTSFreeMemory(IntPtr memory);

        private static string SessionName(int session, int info)
        {
            if (!WTSQuerySessionInformationW(IntPtr.Zero, session, info, out var value, out var size))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法核实 Windows 桌面会话的用户。");
            try { return size < 2 ? "" : Marshal.PtrToStringUni(value); }
            finally { WTSFreeMemory(value); }
        }

        private static void RequireInteractiveUser()
        {
            using (var self = Process.GetCurrentProcess())
            using (var identity = WindowsIdentity.GetCurrent())
            {
                if (!Environment.UserInteractive || self.SessionId == 0 || identity.IsSystem)
                    throw new InvalidOperationException("请从已登录的 Windows 交互桌面启动微信沙盒。");
                var user = SessionName(self.SessionId, 5 /* WTSUserName */);
                var domain = SessionName(self.SessionId, 7 /* WTSDomainName */);
                if (string.IsNullOrWhiteSpace(user) ||
                    !new NTAccount(domain, user).Translate(typeof(SecurityIdentifier)).Equals(identity.User))
                    throw new InvalidOperationException("请用当前 Windows 桌面的账户运行 AppShield 后再启动微信沙盒。");
            }
        }

        internal static string BuildConfig(string inputDirectory, bool allowNetwork, Guid run)
        {
            string path = SafeFiles.LocalPath(inputDirectory);
            if (path.Contains("%")) throw new InvalidDataException("沙盒共享路径不能包含环境变量占位符。");
            string bootstrap;
            var assembly = typeof(WeChatSandboxLauncher).Assembly;
            string resource = assembly.GetManifestResourceNames().Single(n => n.EndsWith(".Native.WeChatSandboxGuest.ps1", StringComparison.Ordinal));
            using (var reader = new StreamReader(assembly.GetManifestResourceStream(resource)))
                bootstrap = reader.ReadToEnd().Replace("__HASH__", InstallerHash).Replace("__VERSION__", SupportedVersion).Replace("__RUN__", run.ToString("D"));
            string command = "powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand " +
                Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap));
            var builder = new StringBuilder();
            using (var xml = XmlWriter.Create(builder, new XmlWriterSettings { OmitXmlDeclaration = true }))
            {
                xml.WriteStartElement("Configuration");
                foreach (var key in new[] {"VGpu", "ClipboardRedirection", "AudioInput", "VideoInput", "PrinterRedirection"})
                    xml.WriteElementString(key, "Disable");
                xml.WriteElementString("ProtectedClient", "Enable");
                xml.WriteElementString("Networking", allowNetwork ? "Enable" : "Disable");
                xml.WriteStartElement("MappedFolders");
                xml.WriteStartElement("MappedFolder");
                xml.WriteElementString("HostFolder", path);
                xml.WriteElementString("SandboxFolder", @"C:\AppShieldInput");
                xml.WriteElementString("ReadOnly", "true");
                xml.WriteEndElement(); xml.WriteEndElement();
                xml.WriteStartElement("LogonCommand");
                xml.WriteElementString("Command", command);
                xml.WriteEndElement(); xml.WriteEndElement();
            }
            return builder.ToString();
        }

        private string StartSandbox(string config)
        {
            string cli = FindCli();
            if (cli != null)
            {
                var json = new JavaScriptSerializer();
                var sessions = json.DeserializeObject(WeChatSandboxProcess.Query(cli, "list", "--raw")) as IDictionary<string,object>;
                if (sessions == null || !sessions.TryGetValue("WindowsSandboxEnvironments", out var value) || !(value is object[] listed))
                    throw new InvalidDataException("无法核实 Windows 沙盒的现有会话。");
                if (listed.Length > 0) throw new InvalidOperationException("已有 Windows 沙盒会话在运行。请在该会话处理完毕后再启动新沙盒。");
                string reply = WeChatSandboxProcess.Query(cli, "start", "--config", config, "--raw");
                Guid id = ParseNewSession(reply);
                // connect only to the instance returned by our own successful start.
                try
                {
                    WeChatSandboxProcess.StartDetached(cli, "connect", "--id", id.ToString("D"));
                }
                catch (Exception ex) when (ex is Win32Exception || ex is IOException)
                { throw new IOException("已创建沙盒 " + id + "，但未能打开其交互桌面。", ex); }
                return "已创建独立 Windows 沙盒 " + id + "，已请求连接桌面。请在来宾中查看微信安装和登录窗口。";
            }
            string legacy = Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe");
            if (!File.Exists(legacy)) throw new NotSupportedException("Windows 沙盒启动器不可用，请确认已启用该系统组件并完成所需重启。");
            foreach (string name in new[] {"WindowsSandbox", "WindowsSandboxClient", "WindowsSandboxRemoteSession", "WindowsSandboxServer"})
            {
                var processes = Process.GetProcessesByName(name);
                try { if (processes.Length > 0) throw new InvalidOperationException("已有 Windows 沙盒在运行，请先处理该会话。"); }
                finally { foreach (var process in processes) process.Dispose(); }
            }
            string file = Path.Combine(cache, "WeChat.wsb");
            TransferBroker.SavePlainText(file, config, true);
            WeChatSandboxProcess.StartDetached(legacy,file);
            return "已请求打开 Windows 沙盒。请在来宾中查看微信安装和登录窗口。";
        }

        // The Store execution alias can be disabled. Resolve the Microsoft-signed installed
        // package via its family, rather than executing an arbitrary wsb.exe from PATH.
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
        private static extern int GetPackagesByPackageFamily(string family, ref uint count, IntPtr names, ref uint chars, IntPtr buffer);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
        private static extern int GetPackagePathByFullName(string fullName, ref uint chars, StringBuilder path);
        private static string FindCli()
        {
            string system = Path.Combine(Environment.SystemDirectory, "wsb.exe");
            if (File.Exists(system)) return system;
            const string family = "MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy";
            uint count=0, chars=0;
            if (GetPackagesByPackageFamily(family, ref count, IntPtr.Zero, ref chars, IntPtr.Zero)!=122 || count==0 || count>64 || chars>65536) return null;
            var names = Marshal.AllocHGlobal(checked((int)count * IntPtr.Size));
            var buffer = Marshal.AllocHGlobal(checked((int)chars * sizeof(char)));
            try
            {
                if (GetPackagesByPackageFamily(family,ref count,names,ref chars,buffer)!=0) return null;
                for (int i=0;i<count;i++)
                {
                    string full=Marshal.PtrToStringUni(Marshal.ReadIntPtr(names,i*IntPtr.Size));
                    uint size=0;
                    if (GetPackagePathByFullName(full,ref size,null)!=122 || size==0 || size>32768) continue;
                    var dir=new StringBuilder((int)size);
                    if (GetPackagePathByFullName(full,ref size,dir)!=0) continue;
                    string exe=Path.Combine(dir.ToString(),"wsb.exe");
                    if (File.Exists(exe)) return exe;
                }
                return null;
            }
            finally { Marshal.FreeHGlobal(buffer); Marshal.FreeHGlobal(names); }
        }

        internal static Guid ParseNewSession(string text)
        {
            string candidate = text.Trim();
            if (candidate.StartsWith("{",StringComparison.Ordinal) || candidate.StartsWith("\"",StringComparison.Ordinal))
            {
                object value;
                try { value = new JavaScriptSerializer().DeserializeObject(candidate); }
                catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException)
                { throw new InvalidDataException("沙盒已响应，但其会话标识无法核实。"); }
                if (value is IDictionary<string,object> fields && fields.TryGetValue("Id",out var id)) candidate = id as string;
                else candidate = value as string;
            }
            if (candidate == null || !Guid.TryParseExact(candidate, "D",out var result) || result==Guid.Empty)
                throw new InvalidDataException("沙盒已响应，但其会话标识无法核实，请查看 Windows 沙盒。");
            return result;
        }

    }
}
