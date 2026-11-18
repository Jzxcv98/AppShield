// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Xml;
using Microsoft.Win32;

namespace AppShield.Native
{
    // This policy belongs to a Windows user SID. It affects all of that user's
    // processes, including future opens by processes that are already running.
    internal sealed class WeChatFolderGuard
    {
        private readonly string dataRoot;
        private readonly string journal;
        private readonly SecurityIdentifier owner;
        private const InheritanceFlags Children = InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit;
        private const FileSystemRights Denied = FileSystemRights.ReadData | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        private sealed class Entry
        {
            internal string Path, Id, Sid, InitialAcl;
            internal bool Pending;
        }

        internal WeChatFolderGuard(string storageRoot)
        {
            dataRoot = SafeFiles.LocalPath(storageRoot);
            journal = Path.Combine(dataRoot, "WeChatFolderGuard");
            using (var identity = WindowsIdentity.GetCurrent()) owner = identity.User;
        }

        private static string Digest(string text)
        {
            using (var h = SHA256.Create())
                return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "");
        }
        private string RecordPath(string path) => Path.Combine(journal, Digest(path.ToUpperInvariant()) + ".xml");
        private static bool Overlap(string a, string b) => SafeFiles.AtOrBelow(a,b) || SafeFiles.AtOrBelow(b,a);

        private T Locked<T>(Func<T> action)
        {
            using (var gate = new Mutex(false, @"Local\AppShield.WeChatFolderGuard." + Digest(dataRoot.ToUpperInvariant())))
            {
                bool acquired;
                try { acquired = gate.WaitOne(TimeSpan.FromSeconds(15)); } catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("另一个窗口正在更新微信目录权限。");
                try
                {
                    using (SafeFiles.PinDirectory(dataRoot, true))
                    {
                        if (!Directory.Exists(journal))
                        {
                            var privateAcl = new DirectorySecurity();
                            privateAcl.SetAccessRuleProtection(true, false);
                            privateAcl.SetOwner(owner);
                            foreach (var sid in new[] { owner, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
                                privateAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, Children,
                                    PropagationFlags.None, AccessControlType.Allow));
                            Directory.CreateDirectory(journal, privateAcl);
                        }
                        using (SafeFiles.PinDirectory(journal))
                        {
                            var acl = new DirectoryInfo(journal).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                            if (!owner.Equals(acl.GetOwner(typeof(SecurityIdentifier))) || !acl.AreAccessRulesProtected ||
                                acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(a =>
                                !owner.Equals(a.IdentityReference) && !((SecurityIdentifier)a.IdentityReference).IsWellKnown(WellKnownSidType.LocalSystemSid)))
                                throw new IOException("目录权限日志的归属或访问权限已变化。");
                            // Serializes different logon sessions of the same user as well.
                            using (new FileStream(Path.Combine(journal, "lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                                return action();
                        }
                    }
                }
                finally { gate.ReleaseMutex(); }
            }
        }

        private Entry Read(string file)
        {
            using (var input = SafeFiles.OpenRead(file, true))
            using (var xml = XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null, MaxCharactersInDocument = 32768 }))
            {
                xml.MoveToContent();
                if (xml.Name != "folder" || xml.GetAttribute("owner") != owner.Value) throw InvalidJournal();
                var e = new Entry { Path = SafeFiles.LocalPath(xml.GetAttribute("path")), Id = xml.GetAttribute("id"),
                    Sid = xml.GetAttribute("account"), InitialAcl = xml.GetAttribute("before"), Pending = xml.GetAttribute("state") == "applying" };
                if ((!e.Pending && xml.GetAttribute("state") != "applied") || e.Id == null || e.Id.Length != 25 || e.InitialAcl == null ||
                    e.InitialAcl.Length != 64 || !string.Equals(file, RecordPath(e.Path), StringComparison.OrdinalIgnoreCase) ||
                    !EligibleSid(new SecurityIdentifier(e.Sid))) throw InvalidJournal();
                return e;
            }
        }
        private static IOException InvalidJournal() => new IOException("微信目录权限日志无效；已停止修改。");
        private Entry[] ReadAll() => Directory.GetFiles(journal, "*.xml").Select(Read).ToArray();

        private void Write(Entry entry)
        {
            string file = RecordPath(entry.Path);
            string tmp = Path.Combine(journal, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    using (var xml = XmlWriter.Create(stream, new XmlWriterSettings { Encoding = new UTF8Encoding(false) }))
                    {
                        xml.WriteStartElement("folder"); xml.WriteAttributeString("owner", owner.Value);
                        xml.WriteAttributeString("account", entry.Sid); xml.WriteAttributeString("path", entry.Path);
                        xml.WriteAttributeString("id", entry.Id); xml.WriteAttributeString("before", entry.InitialAcl);
                        xml.WriteAttributeString("state", entry.Pending ? "applying" : "applied"); xml.WriteEndElement();
                    }
                    stream.Flush(true);
                }
                if (File.Exists(file)) File.Replace(tmp, file, null); else File.Move(tmp, file);
            }
            finally { if (File.Exists(tmp)) File.Delete(tmp); }
        }

        private bool EligibleSid(SecurityIdentifier sid)
        {
            if (sid == null || sid.Equals(owner) || !sid.IsAccountSid()) return false;
            string value = sid.Value;
            return value.StartsWith("S-1-5-21-", StringComparison.Ordinal) && value.Split('-').Length == 8 &&
                uint.TryParse(value.Substring(value.LastIndexOf('-')+1), NumberStyles.None, CultureInfo.InvariantCulture, out var rid) && rid >= 1000;
        }

        private void CheckSelection(string path, SecurityIdentifier sid)
        {
            if (path.Length <= 3 || Overlap(path, dataRoot) || Overlap(path, Path.GetDirectoryName(typeof(WeChatFolderGuard).Assembly.Location)))
                throw new IOException("请选择自己的普通数据目录。");
            foreach (var folder in new[] {Environment.SpecialFolder.Windows, Environment.SpecialFolder.ProgramFiles,
                Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.CommonApplicationData})
            {
                string system = Environment.GetFolderPath(folder);
                if (system.Length > 0 && Overlap(path, system)) throw new IOException("不能选择系统或程序目录。");
            }
            foreach (var folder in new[] {Environment.SpecialFolder.UserProfile, Environment.SpecialFolder.ApplicationData, Environment.SpecialFolder.LocalApplicationData})
            {
                string profile = Environment.GetFolderPath(folder);
                if (profile.Length > 0 && SafeFiles.AtOrBelow(profile, path)) throw new IOException("不能选择用户资料或应用数据根目录。");
            }
            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid.Value))
            {
                string home = key?.GetValue("ProfileImagePath") as string;
                if (!string.IsNullOrEmpty(home) && Overlap(path, SafeFiles.LocalPath(Environment.ExpandEnvironmentVariables(home))))
                    throw new IOException("不能保护微信专用账号自己的资料目录。");
            }
            var install = WeChatIntegration.Detect();
            if (install != null && Overlap(path, Path.GetDirectoryName(install))) throw new IOException("不能选择微信的安装目录。");
            if (path.Split('\\').Any(s => string.Equals(s, "xwechat_files", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s, "WeChat Files", StringComparison.OrdinalIgnoreCase)))
                throw new IOException("不能选择微信账号数据目录。");
        }

        private static FileSystemAccessRule Rule(SecurityIdentifier sid) => new FileSystemAccessRule(sid,
            Denied, Children, PropagationFlags.None, AccessControlType.Deny);
        private static FileSystemAccessRule[] Entries(DirectorySecurity acl, SecurityIdentifier sid) =>
            acl.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Where(a => sid.Equals(a.IdentityReference)).ToArray();
        private static bool Exact(FileSystemAccessRule[] seen) => seen.Length == 1 && seen[0].AccessControlType == AccessControlType.Deny &&
            seen[0].FileSystemRights == Denied && seen[0].InheritanceFlags == Children && seen[0].PropagationFlags == PropagationFlags.None;
        private static IOException AclChanged() => new IOException("该账号的目录权限已被其他程序修改，已保留日志；请核对该目录的安全设置。");
        private static string AclFingerprint(DirectorySecurity acl)
        {
            var dacl = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl;
            if (dacl == null) throw AclChanged();
            var bytes = new byte[dacl.BinaryLength];
            dacl.GetBinaryForm(bytes, 0);
            // SetSecurityInfo can set SE_DACL_AUTO_INHERITED without changing any ACEs.
            return Digest((acl.AreAccessRulesProtected ? "P:" : "I:") + Convert.ToBase64String(bytes));
        }

        private static void VerifyPending(Entry entry, DirectorySecurity acl, FileSystemAccessRule[] seen)
        {
            if (!entry.Pending) return;
            var baseline = new DirectorySecurity();
            baseline.SetSecurityDescriptorBinaryForm(acl.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
            if (seen.Length != 0)
            {
                if (!Exact(seen)) throw AclChanged();
                baseline.RemoveAccessRuleSpecific(seen[0]);
            }
            if (entry.InitialAcl != AclFingerprint(baseline)) throw AclChanged();
        }

        // Traverse only plain entries while their directory names are pinned. Opening the
        // file for metadata through SafeFiles also rejects hard links; no file contents are read.
        // A caller with the normal traverse privilege can open a child by a known path, even
        // when it cannot list the parent. A root-only check would miss protected child DACLs
        // and explicit allows which take precedence over inherited denies.
        private void CheckContents(string root, SecurityIdentifier sid, bool requireDeny)
        {
            var todo = new Stack<string>();
            todo.Push(root);
            while (todo.Count != 0)
            {
                string dir = todo.Pop();
                using (SafeFiles.PinDirectory(dir))
                {
                    if (dir != root) CheckChild(Directory.GetAccessControl(dir), sid, requireDeny);
                    foreach (var item in new DirectoryInfo(dir).EnumerateFileSystemInfos())
                    {
                        if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
                            throw new IOException("所选目录包含重解析点，无法核实整个目录的拒读范围。");
                        if ((item.Attributes & FileAttributes.Directory) != 0) todo.Push(item.FullName);
                        else using (SafeFiles.PinFileMetadata(item.FullName))
                            CheckChild(File.GetAccessControl(item.FullName), sid, requireDeny);
                    }
                }
            }
        }

        private void CheckChild(FileSystemSecurity acl, SecurityIdentifier sid, bool requireDeny)
        {
            var childOwner = (SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier));
            if (acl.AreAccessRulesProtected || !acl.AreAccessRulesCanonical || !TrustedOwner(childOwner))
                throw new IOException("有子项关闭了继承、使用非标准 ACL 或有其他所有者，无法保证拒读。");
            foreach (FileSystemAccessRule ace in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            {
                if ((ace.FileSystemRights & Denied) == 0) continue;
                if (requireDeny && (ace.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                var who = (SecurityIdentifier)ace.IdentityReference;
                if (requireDeny && ace.IsInherited && who.Equals(sid) && ace.AccessControlType == AccessControlType.Deny &&
                    (ace.FileSystemRights & Denied) == Denied) return;
                if (ace.AccessControlType != AccessControlType.Allow || (!requireDeny && ace.IsInherited)) continue;
                if (TrustedOwner(who)) continue;
                throw new IOException("有子项的优先允许规则可能覆盖继承的拒读权限；请选择权限继承一致的目录。");
            }
            if (requireDeny) throw new IOException("Windows 未在所选目录的全部普通子项上确认拒读权限。");
        }
        private bool TrustedOwner(SecurityIdentifier who) => who != null && (who.Equals(owner) ||
            who.IsWellKnown(WellKnownSidType.LocalSystemSid) || who.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

        private T WithAcl<T>(string id, Func<T> operation)
        {
            using (var gate = new Mutex(false, @"Local\AppShield.DirectoryAcl." + id))
            {
                bool acquired;
                try { acquired = gate.WaitOne(TimeSpan.FromSeconds(10)); } catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("目录权限正在被另一操作更新。");
                try { return operation(); } finally { gate.ReleaseMutex(); }
            }
        }

        internal string[] List() => Locked(() => ReadAll().Select(e => e.Path).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToArray());
        internal string AccountSidFor(string directory) => Locked(() => {
            string file = RecordPath(SafeFiles.LocalPath(directory)); return File.Exists(file) ? Read(file).Sid : null;
        });
        internal bool IsApplied(string directory) => Locked(() => {
            string path = SafeFiles.LocalPath(directory), file = RecordPath(path);
            if (!File.Exists(file)) return false;
            var entry = Read(file);
            if (entry.Pending) return false;
            try
            {
                using (var lease = SafeFiles.PinDirectory(path))
                using (var handle = SafeFiles.OpenDirectoryAcl(path, entry.Id))
                {
                    var sid = new SecurityIdentifier(entry.Sid);
                    var acl = NativePolicy.ReadAcl(handle);
                    if (!owner.Equals(Directory.GetAccessControl(path, AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))) ||
                        !acl.AreAccessRulesCanonical || !Exact(Entries(acl, sid))) return false;
                    CheckContents(path, sid, true);
                    return true;
                }
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        });

        internal void Apply(string directory, SecurityIdentifier verifiedAccount)
        {
            if (!EligibleSid(verifiedAccount) ||
                !((NTAccount)verifiedAccount.Translate(typeof(NTAccount))).Value.StartsWith(Environment.MachineName + @"\", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("请选择与当前用户不同的本机专用标准账号。");
            ApplyOwnedDirectory(directory, verifiedAccount);
        }

        // The caller of Apply authenticated the account and verified its standard token.
        // Tests exercise the ACL protocol with a non-existent synthetic account SID.
        internal void ApplyOwnedDirectory(string directory, SecurityIdentifier sid)
        {
            if (!EligibleSid(sid)) throw new InvalidOperationException("不能为此身份添加拒读权限。");
            string path = SafeFiles.LocalPath(directory);
            CheckSelection(path, sid);
            Locked(() => {
                var all = ReadAll();
                if (all.Any(e => e.Sid != sid.Value)) throw new IOException("切换微信专用账号前，请先撤销原账号的目录规则。");
                var entry = all.SingleOrDefault(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase));
                if (all.Any(e => e != entry && Overlap(path, e.Path))) throw new IOException("此目录与已有拒读规则重叠。");
                using (var lease = SafeFiles.PinDirectory(path))
                {
                    string id = SafeFiles.DirectoryIdentity(lease);
                    if (entry != null && entry.Id != id || all.Any(e => e != entry && e.Id == id))
                        throw new IOException("目录已移动或替换，请先撤销原目录规则。");
                    if (!owner.Equals(new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))))
                        throw new IOException("只能保护当前用户拥有的目录。");
                    using (var handle = SafeFiles.OpenDirectoryAcl(path, id))
                    return WithAcl(id, () => {
                        var acl = NativePolicy.ReadAcl(handle);
                        var seen = Entries(acl, sid);
                        var raw = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
                        if (!acl.AreAccessRulesCanonical || raw.DiscretionaryAcl == null || raw.DiscretionaryAcl.Count == 0) throw AclChanged();
                        if (entry == null)
                        {
                            if (seen.Length != 0) throw new IOException("目录已有此账号的显式权限，已保留原有设置。");
                            string before = AclFingerprint(acl);
                            CheckContents(path, sid, false);
                            acl = NativePolicy.ReadAcl(handle);
                            if (before != AclFingerprint(acl) ||
                                !owner.Equals(Directory.GetAccessControl(path, AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))))
                                throw new IOException("检查子项时目录权限或所有者发生变化，请重新核对。");
                            entry = new Entry {Path=path, Id=id, Sid=sid.Value, Pending=true,
                                InitialAcl = before};
                            Write(entry);
                        }
                        acl = NativePolicy.ReadAcl(handle);
                        seen = Entries(acl,sid);
                        VerifyPending(entry, acl, seen);
                        if (seen.Length == 0)
                        {
                            if (!entry.Pending) throw AclChanged();
                            acl.AddAccessRule(Rule(sid));
                            NativePolicy.WriteAcl(handle, acl);
                            seen = Entries(NativePolicy.ReadAcl(handle), sid);
                        }
                        if (!Exact(seen)) throw AclChanged();
                        CheckContents(path, sid, true);
                        if (entry.Pending) { entry.Pending=false; Write(entry); }
                        return true;
                    });
                }
            });
        }

        internal void Revoke(string directory)
        {
            string path = SafeFiles.LocalPath(directory), file = RecordPath(path);
            Locked(() => {
                if (!File.Exists(file)) return false;
                var entry = Read(file);
                using (var handle = SafeFiles.OpenRecordedDirectory(entry.Path, entry.Id))
                return WithAcl(entry.Id, () => {
                    if (handle != null)
                    {
                        var sid = new SecurityIdentifier(entry.Sid);
                        var acl = NativePolicy.ReadAcl(handle);
                        var seen = Entries(acl, sid);
                        if (seen.Length != 0)
                        {
                            if (!Exact(seen)) throw AclChanged();
                            VerifyPending(entry, acl, seen);
                            acl.RemoveAccessRuleSpecific(seen[0]);
                            NativePolicy.WriteAcl(handle, acl);
                            if (Entries(NativePolicy.ReadAcl(handle), sid).Length != 0) throw AclChanged();
                        }
                    }
                    File.Delete(file);
                    return true;
                });
            });
        }
    }
}
