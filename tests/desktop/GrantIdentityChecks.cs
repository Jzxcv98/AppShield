// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using AppShield;
using AppShield.Model;
using AppShield.Native;

internal static class GrantIdentityChecks
{
    private static SecurityIdentifier NewSid()
    {
        var bytes = Guid.NewGuid().ToByteArray();
        return new SecurityIdentifier("S-1-15-2-" + BitConverter.ToUInt32(bytes, 0) + "-" +
            BitConverter.ToUInt32(bytes, 4) + "-" + BitConverter.ToUInt32(bytes, 8) + "-" +
            BitConverter.ToUInt32(bytes, 12) + "-13-17-23");
    }
    private static void Grant(string path, SecurityIdentifier sid, FileSystemRights rights)
    {
        var d = new DirectoryInfo(path);
        var acl = d.GetAccessControl(AccessControlSections.Access);
        acl.AddAccessRule(new FileSystemAccessRule(sid, rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        d.SetAccessControl(acl);
        if (!d.GetAccessControl(AccessControlSections.Access).GetAccessRules(true, false, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>().Any(r => r.IdentityReference.Equals(sid)))
            throw new InvalidOperationException("Windows did not persist the synthetic fixture ACL. Run ACL checks from an ordinary Windows user process.");
    }
    private static string Dacl(string path) => new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
        .GetSecurityDescriptorSddlForm(AccessControlSections.Access);
    private static FolderRule RecordFolder(string path)
    {
        using (var lease = SafeFiles.PinDirectory(path))
            return new FolderRule {Path = path, Writable = false, DirectoryIdentity = SafeFiles.DirectoryIdentity(lease)};
    }
    private static void Assert(bool ok, string text)
    {
        if (!ok) throw new InvalidOperationException(text);
        Console.WriteLine("PASS " + text);
    }
    private static void CheckLegacy(string root, NativePolicy policy, SecurityIdentifier sid)
    {
        var app = new AppProfile { Id = Guid.NewGuid(), IsTelegram = true, ImageHash = new string('A', 64) };
        var state = new AppliedPolicy { Profile = app.Id, Sid = sid.Value, Revision = 7 };
        var transfer = Path.Combine(root, "Transfers", app.Id.ToString("N"));
        var images = Path.Combine(root, "Images", app.Id.ToString("N"));
        string outgoing = Path.Combine(transfer, "Outgoing"), inbox = Path.Combine(transfer, "Inbox");
        string image = Path.Combine(images, app.ImageHash), outside = Path.Combine(root, "user-choice");
        try
        {
            foreach (var path in new[] { outgoing, inbox, image, outside })
            {
                Directory.CreateDirectory(path);
                bool writable = path == inbox;
                Grant(path, sid, writable ? FileSystemRights.Modify : FileSystemRights.ReadAndExecute);
                state.Grants.Add(new FolderRule {Path = path, Writable = writable});
            }
            policy.MigrateInternalRoots(state, app, sid);
            var journal = policy.Read(app.Id, sid.Value);
            Assert(journal.Revision == 0 && journal.Grants.All(r => r.Path == outside ?
                r.DirectoryIdentity == null : r.DirectoryIdentity == RecordFolder(r.Path).DirectoryIdentity),
                "legacy migration identifies only the verified app-owned transfer and current image directories");
            try { policy.RevokeDirectoryGrants(journal, sid); throw new Exception("unexpected claim of unidentified user folder"); }
            catch (IOException) { }
            var left = policy.Read(app.Id, sid.Value);
            Assert(left.Grants.Count == 1 && left.Grants[0].Path == outside && Dacl(outside).Contains(sid.Value) &&
                new[] {outgoing, inbox, image}.All(path => !Dacl(path).Contains(sid.Value)),
                "legacy external identity remains pending while independently owned ACLs are removed");
        }
        finally
        {
            foreach (var path in new[] {outgoing, inbox, image, outside, transfer, images,
                Path.GetDirectoryName(transfer), Path.GetDirectoryName(images)})
                if (Directory.Exists(path)) Directory.Delete(path);
            File.Delete(Path.Combine(root, "Policies", app.Id.ToString("N") + ".xml"));
        }
    }
    public static void Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "AppShield.GrantId." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var policy = new NativePolicy(root);
        var sid = NewSid();
        var other = NewSid();
        string old = Path.Combine(root, "selected"), moved = Path.Combine(root, "renamed");
        string deleted = Path.Combine(root, "deleted"), foreign = Path.Combine(root, "wrong-volume");
        var state = new AppliedPolicy { Profile = Guid.NewGuid(), Sid = sid.Value, Revision = 5 };
        var firstProfile = state.Profile;
        try
        {
            Directory.CreateDirectory(old);
            Grant(old, other, FileSystemRights.Read);
            string unrelated = Dacl(old);
            Grant(old, sid, FileSystemRights.ReadAndExecute);
            state.Grants.Add(RecordFolder(old));
            Directory.Move(old, moved);
            Directory.CreateDirectory(old);
            Grant(old, sid, FileSystemRights.ReadAndExecute);
            string replacement = Dacl(old);
            policy.RevokeDirectoryGrants(state, sid);
            Assert(Dacl(old) == replacement && Dacl(moved) == unrelated, "revocation follows renamed NTFS directory ID and leaves replacement and unrelated ACL intact");
            Assert(policy.Read(state.Profile, sid.Value).Grants.Count == 0, "completed directory removal journalled");

            Directory.CreateDirectory(deleted);
            Grant(deleted, sid, FileSystemRights.ReadAndExecute);
            state.Grants.Add(RecordFolder(deleted));
            Directory.Delete(deleted);
            Directory.CreateDirectory(deleted);
            Grant(deleted, sid, FileSystemRights.ReadAndExecute);
            string newAcl = Dacl(deleted);
            try
            {
                policy.RevokeDirectoryGrants(state, sid);
                Assert(policy.Read(state.Profile, sid.Value).Grants.Count == 0, "verified absent NTFS ID removes only the deleted grant record");
            }
            catch (IOException ex) when ((ex.GetBaseException() as Win32Exception)?.NativeErrorCode == 87)
            {
                var leftover = policy.Read(state.Profile, sid.Value);
                Assert(leftover.Revision == 0 && leftover.Grants.Count == 1 && leftover.Grants[0].DirectoryIdentity != RecordFolder(deleted).DirectoryIdentity,
                    "ambiguous NTFS stale-ID result retains deleted grant as pending");
            }
            Assert(Dacl(deleted) == newAcl, "after original deletion the replacement ACL is unchanged");

            state = new AppliedPolicy { Profile = Guid.NewGuid(), Sid = sid.Value, Revision = 9 };
            Directory.CreateDirectory(foreign);
            Grant(foreign, sid, FileSystemRights.ReadAndExecute);
            var wrong = RecordFolder(foreign);
            var identity = wrong.DirectoryIdentity;
            wrong.DirectoryIdentity = (identity[0] == '0' ? "1" : "0") + identity.Substring(1);
            state.Grants.Add(wrong);
            string before = Dacl(foreign);
            try { policy.RevokeDirectoryGrants(state, sid); throw new Exception("unexpected removal on another volume"); }
            catch (IOException) { }
            var pending = policy.Read(state.Profile, sid.Value);
            Assert(pending.Revision == 0 && pending.Grants.Count == 1 && Dacl(foreign) == before,
                "unverified volume leaves ACL intact and retains a pending journal");
            wrong.DirectoryIdentity = identity;
            policy.RevokeDirectoryGrants(state, sid);
            CheckLegacy(root, policy, sid);
        }
        finally
        {
            foreach (var path in new[] {old, moved, deleted, foreign}) if (Directory.Exists(path)) Directory.Delete(path);
            string policies = Path.Combine(root, "Policies");
            File.Delete(Path.Combine(policies, firstProfile.ToString("N") + ".xml"));
            File.Delete(Path.Combine(policies, state.Profile.ToString("N") + ".xml"));
            if (Directory.Exists(policies)) Directory.Delete(policies);
            Directory.Delete(root);
        }
    }
}
