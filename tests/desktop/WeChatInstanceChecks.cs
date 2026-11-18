// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using AppShield.Model;
using AppShield.Native;

internal static class WeChatInstanceChecks
{
    private static string CopyFixture(string dir, string name)
    {
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, name);
        File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), path);
        return path;
    }

    private static Process StartFixture(string path)
    {
        // An idle command interpreter waits on our pipe and never launches the actual client.
        return Process.Start(new ProcessStartInfo(path, "/d /q")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(path)
        });
    }

    internal static void Run(string dir)
    {
        string root = Path.Combine(dir, "wechat-instance-checks");
        string installed = CopyFixture(Path.Combine(root, "installed"), "Weixin.exe");
        string other = CopyFixture(Path.Combine(root, "other"), "Weixin.exe");
        string legacy = CopyFixture(Path.Combine(root, "legacy"), "WeChat.exe");
        var profile = new AppProfile { Id = Guid.NewGuid(), ExecutablePath = installed, IsWeChat = true };
        var fixtures = new List<Process>();
        try
        {
            using (var identity = new ContainerIdentity(profile.Id, false))
            {
                var generic = new AppProfile { Id = profile.Id, ExecutablePath = installed };
                NativeJob.Observe(generic, installed, identity.Sid, out int genericOutside, out int genericUnknown);
                NativeJob.Observe(profile, installed, identity.Sid, out int beforeOutside, out int beforeUnknown);
                foreach (string image in new[] { installed, other, legacy }) fixtures.Add(StartFixture(image));
                var owned = NativeJob.Observe(profile, installed, identity.Sid, out int outside, out int unknown);
                DesktopChecks.Assert(owned.Count == 0 && outside == beforeOutside + 1 && unknown == beforeUnknown + 2,
                    "WeChat preflight counts the registered host image and both unverified installation candidates exactly once");
                owned = NativeJob.Observe(generic, installed, identity.Sid, out outside, out unknown);
                DesktopChecks.Assert(owned.Count == 0 && outside == genericOutside + 1 && unknown == genericUnknown,
                    "generic profiles ignore unrelated accessible images with matching or legacy client filenames");
                DesktopChecks.Assert(fixtures.TrueForAll(p => !p.HasExited),
                    "instance inspection leaves all three host fixture processes running");
            }
        }
        finally
        {
            foreach (var process in fixtures)
                using (process)
                {
                    process.StandardInput.Close();
                    if (!process.WaitForExit(3000)) { process.Kill(); process.WaitForExit(); }
                }
        }
    }
}
