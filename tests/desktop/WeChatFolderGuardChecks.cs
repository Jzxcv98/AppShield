// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml;
using AppShield.Native;

internal static class WeChatFolderGuardChecks
{
    private static bool Marker(string path, SecurityIdentifier sid, bool inherited)
    {
        var acl = File.Exists(path) ? (FileSystemSecurity)File.GetAccessControl(path) : Directory.GetAccessControl(path);
        return acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>().Any(r =>
            r.IdentityReference.Equals(sid) && r.AccessControlType == AccessControlType.Deny &&
            r.IsInherited == inherited && (r.FileSystemRights & FileSystemRights.ReadData) != 0);
    }

    private static void ExpectRefused(Action action, string text)
    {
        try { action(); }
        catch (IOException) { Console.WriteLine("PASS " + text); return; }
        catch (InvalidOperationException) { Console.WriteLine("PASS " + text); return; }
        throw new Exception("Expected refusal: " + text);
    }

    private static void AddExplicit(string path, SecurityIdentifier sid, FileSystemRights rights, AccessControlType kind)
    {
        var acl = Directory.GetAccessControl(path);
        acl.AddAccessRule(new FileSystemAccessRule(sid, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, kind));
        Directory.SetAccessControl(path, acl);
    }

    internal static void Run(string dir)
    {
        string root = Path.Combine(dir,"wechat-guard"), home = Path.Combine(root,"private-store");
        string selected = Path.Combine(root,"selected"), moved = Path.Combine(root,"original");
        var guard = new WeChatFolderGuard(home);
        Directory.CreateDirectory(selected);
        var sid = new SecurityIdentifier("S-1-5-21-123456-234567-345678-23001");
        var other = new SecurityIdentifier("S-1-5-21-123456-234567-345678-23002");
        var privateChild = Directory.CreateDirectory(Path.Combine(selected,"protected"));
        var privateAcl = privateChild.GetAccessControl();
        privateAcl.SetAccessRuleProtection(true,true); privateChild.SetAccessControl(privateAcl);
        ExpectRefused(() => guard.ApplyOwnedDirectory(selected,sid),"closed child inheritance refuses whole-tree claim");
        DesktopChecks.Assert(guard.List().Length==0 && !Marker(selected,sid,false),"unsupported child makes no root ACL or journal change");
        privateChild.Delete();
        string nested = Path.Combine(selected, "child");
        Directory.CreateDirectory(nested);
        string before = Path.Combine(nested, "before.txt");
        File.WriteAllText(before,"marker");
        using (var host = WindowsIdentity.GetCurrent())
            ExpectRefused(() => guard.ApplyOwnedDirectory(selected,host.User),"read-deny refuses host identity");
        ExpectRefused(() => guard.ApplyOwnedDirectory(selected,new SecurityIdentifier(WellKnownSidType.WorldSid,null)),
            "read-deny refuses built-in principals");
        AddExplicit(selected,other,FileSystemRights.ReadData,AccessControlType.Allow);
        var original = Directory.GetAccessControl(selected).GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        using (var writer = new FileStream(before, FileMode.Open, FileAccess.Write, FileShare.Read))
        {
            guard.ApplyOwnedDirectory(selected,sid);
            DesktopChecks.Assert(guard.IsApplied(selected),"ACL verification operates while a shared writer has the file open");
        }
        guard.ApplyOwnedDirectory(selected,sid);
        // Simulate interruption after the kernel update but before committing the journal.
        string record=Directory.GetFiles(Path.Combine(home,"WeChatFolderGuard"),"*.xml").Single();
        var xml=new XmlDocument {XmlResolver=null};
        xml.Load(record); xml.DocumentElement.SetAttribute("state","applying"); xml.Save(record);
        DesktopChecks.Assert(!guard.IsApplied(selected),"interrupted apply is not reported complete");
        guard.ApplyOwnedDirectory(selected,sid);
        DesktopChecks.Assert(guard.IsApplied(selected),"retry verifies the original ACL and finishes an interrupted apply");
        string later=Path.Combine(nested,"later.txt"); File.WriteAllText(later,"later");
        DesktopChecks.Assert(guard.List().SequenceEqual(new[]{selected}) && guard.AccountSidFor(selected)==sid.Value &&
            guard.IsApplied(selected) && Marker(selected,sid,false) && Marker(nested,sid,true) &&
            Marker(before,sid,true) && Marker(later,sid,true), "deny rule is idempotent and inherited by old/new synthetic files");
        var altered=File.GetAccessControl(later);
        altered.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.ReadData,AccessControlType.Allow));
        File.SetAccessControl(later,altered);
        DesktopChecks.Assert(!guard.IsApplied(selected),"known-path explicit child allow prevents whole-tree protection claim");
        File.Delete(later);
        ExpectRefused(() => guard.ApplyOwnedDirectory(nested,other),"directory policy refuses silent account switch");
        Directory.Move(selected,moved); Directory.CreateDirectory(selected);
        AddExplicit(selected,sid,FileSystemRights.ReadData,AccessControlType.Deny);
        DesktopChecks.Assert(!guard.IsApplied(selected),"replacement path is never shown as protected by the original record");
        guard.Revoke(selected);
        DesktopChecks.Assert(guard.List().Length==0 && Marker(selected,sid,false) &&
            Directory.GetAccessControl(moved).GetSecurityDescriptorSddlForm(AccessControlSections.Access)==original &&
            !Marker(Path.Combine(moved,"child","before.txt"),sid,true), "revocation follows the original NTFS identity and preserves replacement ACL");
        ExpectRefused(() => guard.ApplyOwnedDirectory(selected,sid),"pre-existing explicit deny is never adopted");
        guard.ApplyOwnedDirectory(moved,sid);
        AddExplicit(moved,sid,FileSystemRights.WriteData,AccessControlType.Deny);
        DesktopChecks.Assert(!guard.IsApplied(moved),"changed target ACE no longer reported intact");
        ExpectRefused(() => guard.Revoke(moved),"externally modified target ACE is preserved with recovery record");
        DesktopChecks.Assert(guard.List().Single()==moved,"conflicting revoke retains recovery journal");
        ExpectRefused(() => guard.ApplyOwnedDirectory(home,sid),"cannot guard the manager's state directory");
    }
}
