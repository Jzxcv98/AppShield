// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;
using AppShield.Model;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Native
{
    public sealed class AppliedPolicy
    {
        public Guid Profile { get; set; }
        public string Sid { get; set; }
        public long Revision { get; set; }
        public List<FolderRule> Grants { get; set; } = new List<FolderRule>();
        // Recorded before an in-place permission mode change, so a failed apply
        // can reclaim precisely the old or the intended new explicit ACE.
        public List<FolderRule> PendingModes { get; set; } = new List<FolderRule>();
    }

    internal sealed class NativePolicy
    {
        private readonly string dataRoot;
        private static readonly XmlSerializer Serializer = new XmlSerializer(typeof(AppliedPolicy));
        private const InheritanceFlags Children = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        internal NativePolicy(string root) { dataRoot = root; }
        private string FileFor(Guid id) => Path.Combine(dataRoot, "Policies", id.ToString("N") + ".xml");
        internal AppliedPolicy Read(Guid id, string sid)
        {
            string file = FileFor(id);
            if (!File.Exists(file)) return null;
            using (var stream = SafeFiles.OpenRead(file, true))
            using (var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 4 * 1024 * 1024 }))
            {
                var p = (AppliedPolicy)Serializer.Deserialize(reader);
                if (p == null || p.Profile != id || p.Sid != sid || p.Grants == null) throw new InvalidDataException("应用权限记录与所选身份不匹配。");
                return p;
            }
        }
        private void Write(AppliedPolicy record)
        {
            string file = FileFor(record.Profile);
            using (SafeFiles.PinDirectory(Path.GetDirectoryName(file), true))
            {
                string temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        Serializer.Serialize(output, record); output.Flush(true);
                    }
                    if (File.Exists(file)) File.Replace(temp, file, null); else File.Move(temp, file);
                }
                finally { if (File.Exists(temp)) File.Delete(temp); }
            }
        }
        internal static string ImageDirectory(string root, AppProfile p) => Path.Combine(root, "Images", p.Id.ToString("N"), p.ImageHash);
        internal static bool UsesCopy(AppProfile p)
        {
            if (p.IsTelegram) return true;
            if (p.Folders.Any(f => !f.Writable && SafeFiles.AtOrBelow(p.ExecutablePath, f.Path))) return false;
            foreach (var location in new[] { Environment.SpecialFolder.Windows, Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                string system = Environment.GetFolderPath(location);
                if (system.Length != 0 && SafeFiles.AtOrBelow(p.ExecutablePath, system)) return false;
            }
            return true;
        }
        internal static string Image(string root, AppProfile p) => UsesCopy(p)
            ? Path.Combine(ImageDirectory(root, p), Path.GetFileName(p.ExecutablePath)) : p.ExecutablePath;

        private List<FolderRule> Desired(AppProfile p, TransferBroker broker)
        {
            var result = p.Folders.Select(f => new FolderRule { Path = SafeFiles.LocalPath(f.Path), Writable = f.Writable }).ToList();
            if (result.Any(f => SafeFiles.AtOrBelow(f.Path, dataRoot) || SafeFiles.AtOrBelow(dataRoot, f.Path)))
                throw new InvalidDataException("授权范围与管理器私有数据重叠。");
            foreach (var f in result.Where(f => f.Writable))
                if (SafeFiles.AtOrBelow(p.ExecutablePath, f.Path) ||
                    SafeFiles.AtOrBelow(typeof(NativePolicy).Assembly.Location, f.Path) ||
                    SafeFiles.AtOrBelow(f.Path, Path.GetDirectoryName(typeof(NativePolicy).Assembly.Location)))
                    throw new InvalidDataException("不能向受管应用授予程序或管理器安装位置的写权限。");
            result.Add(new FolderRule { Path = broker.Folder(p.Id, false) });
            result.Add(new FolderRule { Path = broker.Folder(p.Id, true), Writable = true });
            if (UsesCopy(p)) result.Add(new FolderRule { Path = ImageDirectory(dataRoot, p) });
            return result;
        }
        private static FileSystemAccessRule Rule(SecurityIdentifier sid, bool write)
        {
            var rights = write ? FileSystemRights.Modify : FileSystemRights.ReadAndExecute;
            return new FileSystemAccessRule(sid, rights, Children, PropagationFlags.None, AccessControlType.Allow);
        }
        private static IEnumerable<FileSystemAccessRule> ExplicitRules(DirectorySecurity acl, SecurityIdentifier sid) =>
            acl.GetAccessRules(true, false, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>()
                .Where(r => r.IdentityReference.Equals(sid));
        private static bool Same(FileSystemAccessRule a, FileSystemAccessRule b) => a.FileSystemRights == b.FileSystemRights &&
            a.AccessControlType == b.AccessControlType && a.InheritanceFlags == b.InheritanceFlags && a.PropagationFlags == b.PropagationFlags;

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint information, IntPtr owner,
            IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint SetSecurityInfo(SafeFileHandle handle, int objectType, uint information, IntPtr owner,
            IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,
            out bool present, out IntPtr dacl, out bool defaulted);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);

        internal static DirectorySecurity ReadAcl(SafeFileHandle handle)
        {
            uint error = GetSecurityInfo(handle, 1, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var sd);
            if (error != 0) throw new IOException("无法读取原授权对象的 ACL。", new Win32Exception((int)error));
            try
            {
                var bytes = new byte[checked((int)GetSecurityDescriptorLength(sd))];
                Marshal.Copy(sd, bytes, 0, bytes.Length);
                var acl = new DirectorySecurity();
                acl.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access);
                return acl;
            }
            finally { LocalFree(sd); }
        }

        internal static void WriteAcl(SafeFileHandle handle, DirectorySecurity acl)
        {
            var bytes = GCHandle.Alloc(acl.GetSecurityDescriptorBinaryForm(), GCHandleType.Pinned);
            try
            {
                if (!GetSecurityDescriptorDacl(bytes.AddrOfPinnedObject(), out bool present, out var dacl, out _) || !present || dacl == IntPtr.Zero)
                    throw new IOException("更新后的显式 DACL 无效。");
                uint error = SetSecurityInfo(handle, 1, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (error != 0) throw new IOException("无法更新原授权对象的 ACL。", new Win32Exception((int)error));
            }
            finally { bytes.Free(); }
        }

        private static void Reconcile(FolderRule folder, SecurityIdentifier sid, bool? desired, bool owned, bool? pendingMode = null)
        {
            string identity = folder.DirectoryIdentity;
            using (var parent = desired.HasValue ? SafeFiles.PinDirectory(folder.Path) : null)
            using (var handle = desired.HasValue ? SafeFiles.OpenDirectoryAcl(folder.Path, identity) :
                SafeFiles.OpenRecordedDirectory(folder.Path, identity))
            {
                if (handle == null) return; // Original directory has been deleted on the verified volume.
                using (var gate = new Mutex(false, @"Local\AppShield.DirectoryAcl." + identity))
                {
                    bool acquired;
                    try { acquired = gate.WaitOne(TimeSpan.FromSeconds(10)); } catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired) throw new IOException("另一个应用正在处理此目录的 ACL，请重试。");
                    try { ReconcileHandle(handle, folder, sid, desired, owned, pendingMode); }
                    finally { gate.ReleaseMutex(); }
                }
            }
        }

        private static void ReconcileHandle(SafeFileHandle handle, FolderRule folder, SecurityIdentifier sid,
            bool? desired, bool owned, bool? pendingMode)
        {
            var acl = ReadAcl(handle);
            var existing = ExplicitRules(acl, sid).ToArray();
            var want = desired.HasValue ? Rule(sid, desired.Value) : null;
            if (existing.Length == 0 && want == null) return;
            if (existing.Length == 1 && want != null && Same(existing[0], want))
            {
                if (!owned) throw new IOException("此应用 SID 已有外部目录授权，请先核对。");
                return;
            }
            var allowedModes = pendingMode.HasValue ? new[] { folder.Writable, pendingMode.Value } : new[] { folder.Writable };
            if (existing.Any(r => !allowedModes.Any(mode => Same(r, Rule(sid, mode)))) || (existing.Length != 0 && !owned))
                throw new IOException("目录上存在管理器无法认领的权限，请先核对。");
            foreach (var rule in existing) acl.RemoveAccessRuleSpecific(rule);
            if (want != null) acl.AddAccessRule(want);
            WriteAcl(handle, acl);
            var after = ExplicitRules(ReadAcl(handle), sid).ToArray();
            if (want == null ? after.Length != 0 : after.Length != 1 || !Same(after[0], want))
                throw new IOException("Windows 未确认目录权限。");
        }

        internal void Apply(AppProfile p, ContainerIdentity identity, TransferBroker broker)
        {
            if (NativeJob.Active(p.Id)) throw new InvalidOperationException("请先关闭该应用的受管进程，再更改权限。");
            var previous = Read(p.Id, identity.Sid.Value);
            if (previous != null) MigrateInternalRoots(previous, p, identity.Sid);
            var desired = Desired(p, broker);
            var old = (previous?.Grants ?? new List<FolderRule>()).ToDictionary(r => r.Path, StringComparer.OrdinalIgnoreCase);
            var next = desired.ToDictionary(r => r.Path, StringComparer.OrdinalIgnoreCase);
            foreach (var rule in desired) using (var lease = SafeFiles.PinDirectory(rule.Path))
                {
                    rule.DirectoryIdentity = SafeFiles.DirectoryIdentity(lease);
                    if (old.TryGetValue(rule.Path, out var prior) && prior.DirectoryIdentity != rule.DirectoryIdentity)
                        throw new IOException("已授权目录的实际对象发生变化，暂停更新。");
                }
            foreach (var rule in desired.Where(r => !old.ContainsKey(r.Path)))
                using (SafeFiles.PinDirectory(rule.Path))
                    if (ExplicitRules(new DirectoryInfo(rule.Path).GetAccessControl(AccessControlSections.Access), identity.Sid).Any())
                        throw new IOException("此应用身份在新授权目录上已有外部权限，无法认领。");
            // The journal covers both sets until every ACL and network constraint has succeeded.
            // Revision zero prevents launching after interruption, including a concurrent restart.
            var journal = new AppliedPolicy
            {
                Profile = p.Id,
                Sid = identity.Sid.Value,
                Revision = 0,
                Grants = old.Values.Concat(desired.Where(r => !old.ContainsKey(r.Path))).ToList(),
                PendingModes = (previous?.PendingModes ?? new List<FolderRule>()).Concat(
                    desired.Where(r => old.TryGetValue(r.Path, out var prior) && prior.Writable != r.Writable))
                    .GroupBy(r => new { r.Path, r.DirectoryIdentity, r.Writable }).Select(g => g.First()).ToList()
            };
            Write(journal);
            PackageNetwork.Apply(p.Id, identity.Sid.Value, p);
            foreach (var rule in old.Values.Where(r => !next.ContainsKey(r.Path)))
            {
                Reconcile(rule, identity.Sid, null, true, OtherMode(journal, rule));
            }
            foreach (var rule in desired)
            {
                bool existed = old.TryGetValue(rule.Path, out var prior);
                bool? alternate = existed && prior.Writable != rule.Writable ? prior.Writable : OtherMode(journal, rule);
                Reconcile(rule, identity.Sid, rule.Writable, existed, alternate);
            }
            journal.Grants = desired; journal.PendingModes.Clear(); journal.Revision = p.Revision; Write(journal);
        }

        // Explicit Apply is the only migration entry. Never infer the identity of an
        // externally selected legacy path from whichever object now happens to be there.
        internal void MigrateInternalRoots(AppliedPolicy state, AppProfile p, SecurityIdentifier sid)
        {
            if (state.Profile != p.Id || p.Id == Guid.Empty || state.Sid != sid.Value)
                throw new InvalidDataException("旧授权记录与应用身份不符。");
            if (!state.Grants.Any(r => string.IsNullOrEmpty(r.DirectoryIdentity))) return;
            var transfer = Path.Combine(dataRoot, "Transfers", p.Id.ToString("N"));
            var managed = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase) {
                { Path.Combine(transfer, "Outgoing"), false }, { Path.Combine(transfer, "Inbox"), true }
            };
            if (p.ImageHash != null && p.ImageHash.Length == 64 && p.ImageHash.All(Uri.IsHexDigit) && UsesCopy(p))
                managed.Add(ImageDirectory(dataRoot, p), false);
            bool migrated = false;
            foreach (var rule in state.Grants.Where(r => string.IsNullOrEmpty(r.DirectoryIdentity)))
            {
                if (!managed.TryGetValue(rule.Path, out bool writable)) continue;
                if (rule.Writable != writable) throw new IOException("旧内部目录的授权种类不匹配，已停止迁移。");
                using (var pinned = SafeFiles.PinDirectory(rule.Path))
                {
                    string identity = SafeFiles.DirectoryIdentity(pinned);
                    using (var handle = SafeFiles.OpenDirectoryAcl(rule.Path, identity))
                    {
                        var seen = ExplicitRules(ReadAcl(handle), sid).ToArray();
                        if (seen.Length != 1 || !Same(seen[0], Rule(sid, writable)))
                            throw new IOException("旧内部目录上的应用 ACL 与记录不符，不能补录目录身份。");
                    }
                    rule.DirectoryIdentity = identity;
                    migrated = true;
                }
            }
            if (migrated) { state.Revision = 0; Write(state); }
        }

        private static bool? OtherMode(AppliedPolicy state, FolderRule root) =>
            state.PendingModes?.FirstOrDefault(r => r.DirectoryIdentity == root.DirectoryIdentity &&
                r.Writable != root.Writable && string.Equals(r.Path, root.Path, StringComparison.OrdinalIgnoreCase))?.Writable;

        internal void RevokeDirectoryGrants(AppliedPolicy record, SecurityIdentifier sid)
        {
            record.Revision = 0; Write(record);
            Exception unresolved = null;
            foreach (var rule in record.Grants.ToArray())
            {
                try { Reconcile(rule, sid, null, true, OtherMode(record, rule)); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
                {
                    if (unresolved == null) unresolved = e;
                    continue;
                }
                record.Grants.Remove(rule);
                record.PendingModes?.RemoveAll(p => string.Equals(p.Path, rule.Path, StringComparison.OrdinalIgnoreCase));
                Write(record); // A later absent volume must not resurrect already completed work.
            }
            if (unresolved != null) throw new IOException("仍有 " + record.Grants.Count + " 项目录撤销待处理。" + unresolved.Message, unresolved);
        }

        internal void Revoke(AppProfile p, ContainerIdentity identity)
        {
            if (NativeJob.Active(p.Id)) throw new InvalidOperationException("请先关闭所有受管进程。");
            var record = Read(p.Id, identity.Sid.Value);
            if (record == null) return;
            RevokeDirectoryGrants(record, identity.Sid);
            PackageNetwork.Remove(p.Id, identity.Sid.Value);
            File.Delete(FileFor(p.Id));
        }

        internal void Verify(AppProfile p, ContainerIdentity identity, TransferBroker broker)
        {
            var state = Read(p.Id, identity.Sid.Value);
            if (state == null || state.Revision != p.Revision)
                throw new InvalidOperationException("请先对当前已保存的版本应用权限。");
            var desired = Desired(p, broker);
            if (state.Grants.Count != desired.Count || desired.Any(w => !state.Grants.Any(r => w.Writable == r.Writable &&
                r.Path.Equals(w.Path, StringComparison.OrdinalIgnoreCase)))) throw new InvalidOperationException("目录授权记录不一致。");
            foreach (var rule in desired) using (var lease = SafeFiles.PinDirectory(rule.Path))
                {
                    var recorded = state.Grants.Single(r => r.Path.Equals(rule.Path, StringComparison.OrdinalIgnoreCase));
                    if (recorded.DirectoryIdentity == null || SafeFiles.DirectoryIdentity(lease) != recorded.DirectoryIdentity)
                        throw new InvalidOperationException("目录身份需要重新确认，请应用当前权限。");
                    var acl = new DirectoryInfo(rule.Path).GetAccessControl(AccessControlSections.Access);
                    var seen = ExplicitRules(acl, identity.Sid).ToArray();
                    if (seen.Length != 1 || !Same(seen[0], Rule(identity.Sid, rule.Writable)))
                        throw new InvalidOperationException("目录 ACL 已变化，请重新应用。");
                }
            PackageNetwork.Verify(p.Id, identity.Sid.Value, p);
        }
    }
}
