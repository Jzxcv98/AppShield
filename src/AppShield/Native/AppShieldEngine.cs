// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using AppShield.Model;
using AppShield.Telegram;

namespace AppShield.Native
{
    internal sealed class AppShieldEngine
    {
        private readonly string root;
        private readonly TransferBroker broker;
        private readonly NativePolicy policy;

        internal AppShieldEngine(string root, TransferBroker broker)
        { this.root = root; this.broker = broker; policy = new NativePolicy(root); }

        internal RuntimeReport Inspect(AppProfile profile)
        {
            var os = Environment.OSVersion.Version;
            bool supported = Environment.Is64BitProcess && os.Major >= 10 && os.Build >= 22000;
            var r = new RuntimeReport
            {
                EngineReady = supported,
                State = "尚未选择应用",
                Detail = "",
                EngineDetail = supported ? "AppShield 原生引擎 · Windows AppContainer、目录 ACL、Job 与包防火墙。实验性文件驱动尚待独立内核验收。"
                : "此版本需要 64 位 Windows 11。"
            };
            if (profile == null || !supported) return r;
            using (var identity = new ContainerIdentity(profile.Id, false))
            {
                var known = policy.Read(profile.Id, identity.Sid.Value);
                var ids = NativeJob.Observe(profile, NativePolicy.Image(root, profile), identity.Sid, out int outside, out int unknown);
                r.Boxed = ids.Count; r.Unboxed = outside; r.Unknown = unknown;
                bool current = known != null && known.Revision == profile.Revision;
                bool changedDirectory = false;
                if (current)
                {
                    foreach (var folder in known.Grants)
                    {
                        try
                        {
                            using (var lease = SafeFiles.PinDirectory(folder.Path))
                                changedDirectory = SafeFiles.DirectoryIdentity(lease) != folder.DirectoryIdentity;
                        }
                        catch (IOException) { changedDirectory = true; }
                        catch (UnauthorizedAccessException) { changedDirectory = true; }
                        if (changedDirectory) break;
                    }
                }
                current = current && !changedDirectory;
                r.Applied = current;
                r.Detail = current ? "已记录本版授权。启动前将重新核对磁盘规则和网络策略。"
                    : changedDirectory ? "已授权目录被移动、替换或无法核对。请先核对或撤销旧授权。"
                    : known?.Revision == 0 ? "上一轮授权或回收尚未完成，请核对目录后重试。" : "本版权限尚未应用。";
                if (profile.IsTelegram && profile.ProductVersion == "7.3.3.0")
                    r.Detail += " 商店版 Telegram 7.3.3 的本地 IPC 在原生 AppContainer 测试中失败。";
                if (profile.IsWeChat && profile.ProductVersion == "4.2.0.53")
                    r.Detail += " 微信 4.2.0.53 的 AppContainer 启动会提前退出。要在当前桌面运行并限制读取目录，请使用“宿主文件保护”。";
                r.State = outside > 0 ? (ids.Count > 0 ? "受管与宿主实例并存" : "有实例在隔离外运行")
                    : unknown > 0 ? "运行归属未确认" : ids.Count > 0 ? "已核对受管进程身份与 Job" : "未观察到运行实例";
                var file = new FileInfo(profile.ExecutablePath);
                if (!file.Exists || file.Length != profile.ImageLength || file.LastWriteTimeUtc.Ticks != profile.ImageWriteUtcTicks)
                {
                    r.State = "程序已更新或移动，请重新导入";
                    r.Applied = false;
                }
                r.Targets = WindowTransfer.List(ids);
                if (profile.IsWeChat && r.Targets.Any(WeChatIntegration.IsLaunchError))
                    r.State = "微信显示启动错误";
                return r;
            }
        }

        internal string Apply(AppProfile p, FileStream image)
        {
            if (NativeJob.Active(p.Id)) throw new InvalidOperationException("请先关闭此应用的受管实例。");
            RequireWeChatInstallDirectory(p);
            using (var identity = new ContainerIdentity(p.Id, true))
            {
                if (NativePolicy.UsesCopy(p)) StageImage(p, image);
                policy.Apply(p, identity, broker);
                return "已为这个应用身份应用目录和网络权限。Job 剪贴板限制会在每次启动时设置并核对。";
            }
        }

        internal string Revoke(AppProfile p)
        {
            using (var identity = new ContainerIdentity(p.Id, false)) policy.Revoke(p, identity);
            return "已撤销目录授权与该配置的网络规则。独立应用数据保留。";
        }

        private void StageImage(AppProfile p, FileStream input)
        {
            var dir = NativePolicy.ImageDirectory(root, p); var file = NativePolicy.Image(root, p);
            using (SafeFiles.PinDirectory(dir, true))
            {
                if (File.Exists(file))
                {
                    using (var existing = SafeFiles.OpenRead(file, true)) CheckHash(existing, p);
                    return;
                }
                string scratch = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    using (var output = new FileStream(scratch, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        input.Position = 0; input.CopyTo(output); output.Flush(true);
                    }
                    File.Move(scratch, file);
                }
                finally { if (File.Exists(scratch)) File.Delete(scratch); }
            }
        }

        internal static void CheckHash(FileStream stream, AppProfile p)
        {
            stream.Position = 0;
            using (var sha = SHA256.Create())
                if (BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "") != p.ImageHash)
                    throw new InvalidDataException("程序内容已变化，请重新导入并核对版本。");
        }

        internal string Launch(AppProfile p, FileStream original)
        {
            if (NativeJob.Active(p.Id)) throw new InvalidOperationException("此配置仍有受管进程。请查看运行详情。");
            RequireWeChatInstallDirectory(p);
            using (var identity = new ContainerIdentity(p.Id, true))
            {
                policy.Verify(p, identity, broker);
                string target = NativePolicy.Image(root, p);
                NativeJob.Observe(p, target, identity.Sid, out int outside, out int unknown);
                if (unknown > 0 || (outside > 0 && !p.IsTelegram))
                    throw new InvalidOperationException(p.IsWeChat
                        ? "发现其他微信实例或无法核实归属的同名进程。请先退出已有微信，再隔离启动。"
                        : "发现盒外或归属不明的实例，无法确认新请求会交给独立进程。");
                string work = Path.Combine(identity.Folder, "AppShieldWork");
                SafeFiles.PlainDirectories(work, true);
                string[] args = new string[0];
                if (p.IsTelegram)
                {
                    PrepareTelegram(work);
                    args = new[] { "-noupdate", "-workdir", work };
                }
                if (NativePolicy.UsesCopy(p))
                {
                    using (var input = SafeFiles.OpenRead(target, true))
                    {
                        CheckHash(input, p);
                        return Start(p, identity, target, work, args);
                    }
                }
                CheckHash(original, p);
                return Start(p, identity, target, work, args);
            }
        }

        private static void RequireWeChatInstallDirectory(AppProfile p)
        {
            if (p.IsWeChat && NativePolicy.UsesCopy(p))
                throw new InvalidOperationException("微信需要同目录的运行文件。请将微信安装目录添加为只读，保存并重新应用权限。");
        }

        private static string Start(AppProfile p, ContainerIdentity identity, string image, string work, string[] args)
        {
            var trace = p.IsTelegram ? new StartupEvidence(work) : null;
            List<int> owned;
            uint? launcherExitCode;
            try { owned = NativeJob.Launch(p, identity, image, work, args, out launcherExitCode); }
            catch (InvalidOperationException ex) when (trace != null)
            {
                throw new InvalidOperationException(ex.Message + " " + trace.FailureStage(), ex);
            }
            var windows = WindowTransfer.List(owned);
            string exitDetail = launcherExitCode.GetValueOrDefault() == 0 ? "" :
                " 启动器退出码为 " + launcherExitCode.Value + "（0x" + launcherExitCode.Value.ToString("X8") + "），仍有已核对的受管子进程。";
            if (p.IsWeChat && windows.Any(WeChatIntegration.IsLaunchError))
                throw new InvalidOperationException("微信显示了启动错误对话框。请查看该窗口中的说明。" + exitDetail);
            string status = windows.Count > 0 ? "已核对受管进程树、AppContainer 身份、Job 和可见窗口。"
                : "已核对受管进程树与 Job，尚未发现成员的可见窗口。";
            return status + exitDetail;
        }

        internal static void PrepareTelegram(string work)
        {
            string dir = Path.Combine(work, "tdata"), file = Path.Combine(dir, "experimental_options.json");
            using (SafeFiles.PinDirectory(dir, true))
            {
                var json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
                var opts = new Dictionary<string, object>();
                bool existed = File.Exists(file);
                if (existed) using (var stream = SafeFiles.OpenRead(file, true))
                    {
                        if (stream.Length > 1024 * 1024) throw new InvalidDataException("Telegram 独立配置过大。");
                        using (var reader = new StreamReader(stream, new UTF8Encoding(false, true)))
                            opts = json.DeserializeObject(reader.ReadToEnd()) as Dictionary<string, object> ??
                                throw new InvalidDataException("Telegram 独立配置格式不正确。");
                    }
                const string key = "skip-url-scheme-register";
                if (opts.TryGetValue(key, out object flag) && flag is bool && (bool)flag) return;
                opts[key] = true;
                string temp = Path.Combine(dir, ".appshield-" + Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    using (var outFile = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        var bytes = Encoding.UTF8.GetBytes(json.Serialize(opts)); outFile.Write(bytes, 0, bytes.Length); outFile.Flush(true);
                    }
                    if (existed) File.Replace(temp, file, null); else File.Move(temp, file);
                }
                finally { if (File.Exists(temp)) File.Delete(temp); }
            }
        }
    }
}
