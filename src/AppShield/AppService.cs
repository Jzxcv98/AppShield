// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Threading;
using AppShield.Native;
using AppShield.Model;
using AppShield.Telegram;

namespace AppShield
{
    public sealed partial class AppService
    {
        private readonly ProfileStore store;
        private readonly TransferBroker broker;
        private readonly AppShieldEngine engine;
        private readonly WeChatFolderGuard accountGuard;
        public string StorageRoot => store.Root;
        public IReadOnlyList<AppProfile> Profiles => store.Read();

        public AppService() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppShield")) { }
        public AppService(string dataRoot)
        {
            store = new ProfileStore(dataRoot);
            broker = new TransferBroker(store.Root);
            engine = new AppShieldEngine(store.Root, broker);
            accountGuard = new WeChatFolderGuard(store.Root);
        }

        public AppProfile AddExecutable(string path)
        {
            path = SafeFiles.LocalPath(path);
            if (!string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("请选择 Windows 可执行文件（.exe）。");
            return Register(path, false);
        }

        public AppProfile ImportTelegram()
        {
            var tg = TelegramIntegration.Detect();
            if (tg == null) throw new InvalidOperationException("未找到签名可验证的 Telegram Desktop。请在已安装它的 Windows 用户会话中运行。");
            return Register(tg.ExecutablePath, true);
        }

        public AppProfile ImportWeChat()
        {
            string path = WeChatIntegration.Detect();
            if (path == null) throw new InvalidOperationException("未找到通过签名验证的微信桌面客户端（Weixin.exe）。");
            return Register(path, false, requireWeChat: true);
        }

        private AppProfile Register(string path, bool requireTelegram, bool requireWeChat = false)
        {
            path = SafeFiles.LocalPath(path);
            if (SafeFiles.AtOrBelow(path, store.Root)) throw new IOException("不能把 AppShield 的中转文件注册为应用。");
            using (var image = SafeFiles.OpenImage(path))
            {
                var tg = string.Equals(Path.GetFileName(path), "Telegram.exe", StringComparison.OrdinalIgnoreCase)
                    ? TelegramIntegration.Identify(path) : null;
                if (requireTelegram && tg == null) throw new InvalidOperationException("当前打开的映像未通过 Telegram 签名检查。");
                using (var reader = new BinaryReader(image, System.Text.Encoding.ASCII, true))
                {
                    if (image.Length < 64 || reader.ReadUInt16() != 0x5a4d) throw new InvalidDataException("文件不是 Windows PE 程序。");
                    image.Position = 60;
                    int pe = reader.ReadInt32();
                    if (pe < 64 || pe > image.Length - 24) throw new InvalidDataException("程序头无效。");
                    image.Position = pe;
                    if (reader.ReadUInt32() != 0x4550) throw new InvalidDataException("文件不是 Windows PE 程序。");
                    image.Position = pe + 22;
                    int characteristics = reader.ReadUInt16();
                    if ((characteristics & 2) == 0 || (characteristics & 0x2000) != 0) throw new InvalidDataException("该文件不能作为独立程序启动。");
                }
                string hash = Hash(image);
                var meta = FileVersionInfo.GetVersionInfo(path);
                string signer = null;
                string publisher = tg != null ? tg.Publisher + "（签名已验证）" : ImageTrust.Describe(path, image, out signer);
                bool wechat = WeChatIntegration.IsOfficialClient(path, meta, signer);
                if (requireWeChat && !wechat) throw new InvalidOperationException("当前映像未通过微信客户端身份核对。");
                return store.Change(items =>
                {
                    var item = items.FirstOrDefault(p => string.Equals(p.ExecutablePath, path, StringComparison.OrdinalIgnoreCase) ||
                        (tg != null && p.IsTelegram && !string.IsNullOrEmpty(tg.PackageFamilyName) && p.PackageFamilyName == tg.PackageFamilyName));
                    if (item == null)
                    {
                        item = new AppProfile { Id = Guid.NewGuid() };
                        items.Add(item);
                    }
                    if (item.IsTelegram && tg == null) throw new InvalidOperationException("Telegram 签名已改变，请核对安装来源。");
                    if (item.IsWeChat && !wechat) throw new InvalidOperationException("微信客户端身份已改变，请核对安装来源。");
                    if (item.Revision > 0 && item.ImageHash == hash && item.ExecutablePath == path && item.IsTelegram == (tg != null)
                        && item.IsWeChat == wechat && item.Publisher == publisher
                        && item.ImageWriteUtcTicks == File.GetLastWriteTimeUtc(path).Ticks)
                        return item;
                    item.Name = wechat ? "微信 (WeChat)" : tg != null ? "Telegram Desktop" : (string.IsNullOrWhiteSpace(meta.ProductName) ? Path.GetFileNameWithoutExtension(path) : meta.ProductName);
                    item.ExecutablePath = path;
                    item.ImageHash = hash;
                    item.ImageLength = image.Length;
                    item.ImageWriteUtcTicks = File.GetLastWriteTimeUtc(path).Ticks;
                    item.ProductVersion = tg?.Version ?? meta.ProductVersion ?? "";
                    item.Publisher = publisher;
                    item.PackageFamilyName = tg?.PackageFamilyName ?? "";
                    item.PackageAppId = tg?.PackageAppId ?? "";
                    item.IsTelegram = tg != null;
                    item.IsWeChat = wechat;
                    ++item.Revision;
                    return item;
                });
            }
        }

        private static string Hash(FileStream stream)
        {
            stream.Position = 0;
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
        }

        private AppProfile Find(Guid id) => Profiles.SingleOrDefault(p => p.Id == id) ??
            throw new InvalidOperationException("找不到应用配置，请刷新列表。");

        private static void Current(AppProfile persisted, AppProfile edited)
        {
            if (persisted.Revision != edited.Revision) throw new InvalidOperationException("配置已由其他窗口更新，请重新载入。");
        }

        private static T WithAppLock<T>(Guid id, Func<T> action)
        {
            using (var gate = new Mutex(false, @"Local\AppShield.Action." + id.ToString("N")))
            {
                bool ok;
                try { ok = gate.WaitOne(TimeSpan.FromSeconds(45)); } catch (AbandonedMutexException) { ok = true; }
                if (!ok) throw new IOException("另一个应用管理操作仍在进行。");
                try { return action(); } finally { gate.ReleaseMutex(); }
            }
        }

        public AppProfile Save(AppProfile edited)
        {
            if (edited == null) throw new ArgumentNullException(nameof(edited));
            if (!edited.BlockLoopback || (!edited.AllowInternet && !edited.BlockLan))
                throw new NotSupportedException("支持离线、仅公网和公网加局域网。请保持本机回环阻断。");
            var rules = new List<FolderRule>();
            foreach (var rule in edited.Folders ?? new List<FolderRule>())
            {
                string path = SafeFiles.LocalPath(rule.Path);
                if (path.Length <= 3 ||
                    SafeFiles.AtOrBelow(path, store.Root) || SafeFiles.AtOrBelow(store.Root, path))
                    throw new IOException("不能授权磁盘根、AppShield 内部数据或其上级目录。");
                if (rule.Writable && SafeFiles.AtOrBelow(edited.ExecutablePath, path))
                    throw new IOException("不能向应用授予其程序安装位置的宿主写权限。");
                SafeFiles.PlainDirectories(path);
                if (rules.Any(r => SafeFiles.AtOrBelow(r.Path, path) || SafeFiles.AtOrBelow(path, r.Path)))
                    throw new IOException("授权目录相互重叠，请为每个范围指定唯一的权限。");
                rules.Add(new FolderRule { Path = path, Writable = rule.Writable });
            }
            return WithAppLock(edited.Id, () => store.Change(items =>
            {
                var item = items.SingleOrDefault(p => p.Id == edited.Id) ?? throw new IOException("配置已移除。");
                Current(item, edited);
                item.Folders = rules;
                item.AllowInternet = edited.AllowInternet;
                item.BlockLoopback = edited.BlockLoopback;
                item.BlockLan = edited.BlockLan;
                item.AllowTextIn = edited.AllowTextIn;
                item.AllowTextOut = edited.AllowTextOut;
                ++item.Revision;
                return item;
            }));
        }

        public string IncomingFolder(Guid id) { Find(id); return broker.Folder(id, true); }
        public string OutgoingFolder(Guid id) { Find(id); return broker.Folder(id, false); }
        public string StageFile(Guid id, string source) { Find(id); return broker.Stage(id, source); }
        public void ExportFile(Guid id, string source, string destination, bool overwrite)
        { Find(id); broker.Export(id, source, destination, overwrite); }
        public string StageText(Guid id, string text)
        {
            if (!Find(id).AllowTextIn) throw new InvalidOperationException("请先保存向应用交付文本的权限。");
            return broker.StageText(id, text);
        }
        public string ReadIncomingText(Guid id, string source)
        {
            if (!Find(id).AllowTextOut) throw new InvalidOperationException("请先保存从应用取出文本的权限。");
            return broker.ReadIncomingText(id, source);
        }

        public RuntimeReport Inspect(AppProfile profile)
        {
            return engine.Inspect(profile == null ? null : Find(profile.Id));
        }

        public string Apply(AppProfile p) => Run(p, false);
        // Existing programmatic callers can explicitly test the native isolation policy.
        // The interactive WeChat entry points select a backend before calling this service.
        public string LaunchAppContainer(AppProfile p) => Run(p, true);
        public string Launch(AppProfile p) => LaunchAppContainer(p);
        public string Launch(Guid id) => Launch(Find(id));
        private AppProfile RegisteredWeChat(AppProfile edited)
        {
            if (edited == null) throw new ArgumentNullException(nameof(edited));
            var saved = Find(edited.Id);
            Current(saved, edited);
            if (!saved.IsWeChat) throw new InvalidOperationException("请先导入通过签名核对的微信。");
            return saved;
        }

        public int LaunchWeChatAsAccount(AppProfile profile, string localUserName, SecureString password) =>
            LaunchWeChatAsAccount(profile, localUserName, password, false);

        private static void RequireNoWeChatInstance(AppProfile p)
        {
            using (var identity = new ContainerIdentity(p.Id, false))
            {
                var managed = NativeJob.Observe(p, p.ExecutablePath, identity.Sid, out int outside, out int unknown);
                if (managed.Count != 0 || outside != 0 || unknown != 0)
                    throw new InvalidOperationException("已有微信或归属未确认的同名进程。要使用新的启动设置，请先自行退出微信。");
            }
        }

        public int LaunchWeChatAsAccount(AppProfile profile, string localUserName, SecureString password, bool limitClipboard)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            return WithAppLock(profile.Id, () =>
            {
                var p = RegisteredWeChat(profile);
                RequireNoWeChatInstance(p);
                SecurityIdentifier expected = null;
                foreach (string dir in accountGuard.List())
                {
                    string sid = accountGuard.AccountSidFor(dir);
                    if (sid == null || !accountGuard.IsApplied(dir) || (expected != null && expected.Value != sid))
                        throw new InvalidOperationException("无法核实已登记的拒读目录。请检查对应记录后再启动。");
                    expected = new SecurityIdentifier(sid);
                }
                return WeChatAccountLauncher.Launch(p.ExecutablePath, p.ImageHash, localUserName, password, expected, limitClipboard);
            });
        }

        public void ProtectWeChatFolder(AppProfile profile, string directory, string localUserName, SecureString password)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            WithAppLock(profile.Id, () =>
            {
                RegisteredWeChat(profile);
                var sid = WeChatAccountLauncher.VerifyAccount(localUserName, password);
                accountGuard.Apply(directory, sid);
                return true;
            });
        }

        public void UnprotectWeChatFolder(AppProfile profile, string directory)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            WithAppLock(profile.Id, () =>
            {
                RegisteredWeChat(profile);
                accountGuard.Revoke(directory);
                return true;
            });
        }

        public WeChatFolderProtection[] WeChatFolderProtections(AppProfile profile)
        {
            RegisteredWeChat(profile);
            return accountGuard.List().Select(path =>
            {
                string value = accountGuard.AccountSidFor(path);
                if (value == null) return null; // A different window already revoked this record.
                var sid = new SecurityIdentifier(value);
                string name;
                try { name = sid.Translate(typeof(NTAccount)).Value; }
                catch (IdentityNotMappedException) { name = value; }
                return new WeChatFolderProtection { Path = path, Sid = value, Account = name, Verified = accountGuard.IsApplied(path) };
            }).Where(row => row != null).ToArray();
        }
        public void CreateShortcut(Guid id, string path, bool overwrite)
        {
            Find(id);
            path = SafeFiles.LocalPath(path);
            if (SafeFiles.AtOrBelow(path, store.Root)) throw new IOException("请选择管理器内部数据目录以外的位置。");
            ManagedShortcut.Write(id, path, overwrite);
        }
        public string Revoke(AppProfile p) => WithAppLock(p.Id, () =>
        {
            var saved = Find(p.Id); Current(saved, p); return engine.Revoke(saved);
        });

        private string Run(AppProfile edited, bool launch)
        {
            if (edited == null) throw new ArgumentNullException(nameof(edited));
            return WithAppLock(edited.Id, () =>
            {
                var p = Find(edited.Id);
                Current(p, edited);
                using (var image = SafeFiles.OpenImage(p.ExecutablePath))
                {
                    AppShieldEngine.CheckHash(image, p);
                    return launch ? engine.Launch(p, image) : engine.Apply(p, image);
                }
            });
        }

        public void PasteText(Guid id, TextTarget target, string text)
        {
            if (target == null) throw new InvalidOperationException("请选择目标窗口。");
            WithAppLock(id, () =>
            {
                var p = Find(id);
                if (!p.AllowTextIn) throw new InvalidOperationException("请先保存向应用交付文本的权限。");
                var report = Inspect(p);
                if (!report.EngineReady || !report.Targets.Any(t => t.ProcessId == target.ProcessId &&
                    t.WindowHandle == target.WindowHandle && t.ProcessStartUtcTicks == target.ProcessStartUtcTicks))
                    throw new InvalidOperationException("窗口归属已变化，请刷新后重新选择。");
                WindowTransfer.Paste(target, text);
                return true;
            });
        }
    }
}
