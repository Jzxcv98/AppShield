// SPDX-License-Identifier: GPL-3.0-only
using System;
using AppShield.Model;
using AppShield.Native;

internal static class NetworkChecks
{
    internal static void Run()
    {
        var p = new AppProfile { Id = Guid.NewGuid() };
        using (var identity = new ContainerIdentity(p.Id, false))
        {
            string sid = identity.Sid.Value;
            DesktopChecks.Assert(PackageNetwork.Scope(p.Id, sid, p) == "public", "default network intent is public with LAN and loopback blocked");
            p.BlockLan = false;
            DesktopChecks.Assert(PackageNetwork.Scope(p.Id, sid, p) == "network", "explicit LAN network intent");
            p.AllowInternet = false;
            try { PackageNetwork.Scope(p.Id, sid, p); throw new Exception("Unsupported LAN-only setting was accepted."); }
            catch (NotSupportedException) { }
            p.BlockLan = true;
            DesktopChecks.Assert(PackageNetwork.Scope(p.Id, sid, p) == "offline", "offline intent blocks all destinations");
            try { PackageNetwork.Scope(p.Id, "S-1-1-0", p); throw new Exception("Wrong package SID was accepted."); }
            catch (InvalidOperationException) { }
            p.BlockLoopback = false;
            try { PackageNetwork.Scope(p.Id, sid, p); throw new Exception("Unverified loopback permission was accepted."); }
            catch (NotSupportedException) { }
        }
    }
}
