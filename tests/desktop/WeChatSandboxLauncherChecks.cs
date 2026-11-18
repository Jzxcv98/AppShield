// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using AppShield.Native;

internal static class WeChatSandboxLauncherChecks
{
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
    [DllImport("kernelbase.dll", SetLastError=true)] private static extern bool CompareObjectHandles(IntPtr first, IntPtr second);
    [DllImport("kernel32.dll")] private static extern IntPtr GetStdHandle(int id);
    [DllImport("kernel32.dll")] private static extern uint GetFileType(IntPtr h);

    private static string EventName(Guid id,string suffix) => @"Local\AppShield.SandboxPipeTest." + id.ToString("N") + "." + suffix;

    internal static int RunHelper(string[] args)
    {
        if (args.Length!=4 || !Guid.TryParseExact(args[2],"N",out var id) || !long.TryParse(args[3],out var value)) return 2;
        using (var ready=EventWaitHandle.OpenExisting(EventName(id,"ready")))
        {
            var handle=new IntPtr(value);
            if (args[1]=="hold")
            {
                if (GetFileType(handle)!=3 /* FILE_TYPE_PIPE */) return 3;
                using (var stop=EventWaitHandle.OpenExisting(EventName(id,"stop")))
                { ready.Set(); return stop.WaitOne(15000) ? 0 : 4; }
            }
            using (var marker=EventWaitHandle.OpenExisting(EventName(id,"marker")))
            using (var leak=EventWaitHandle.OpenExisting(EventName(id,"leak")))
                if (CompareObjectHandles(handle,marker.SafeWaitHandle.DangerousGetHandle())) leak.Set();
            if (args[1]=="check") { ready.Set(); return 0; }
            if (args[1]!="parent") return 2;
            var stdout=GetStdHandle(-11);
            if (GetFileType(stdout)!=3 || !SetHandleInformation(stdout,1,1)) return 3;
            using (Process.Start(new ProcessStartInfo(typeof(WeChatSandboxLauncherChecks).Assembly.Location,
                "--sandbox-handle-test hold "+id.ToString("N")+" "+stdout.ToInt64()) {UseShellExecute=false, CreateNoWindow=true}))
            {
                if (!ready.WaitOne(8000)) return 4;
                Console.WriteLine("sandbox-fixture");
                return 0;
            }
        }
    }

    private static void CheckProcessHandles()
    {
        var id=Guid.NewGuid();
        string test=typeof(WeChatSandboxLauncherChecks).Assembly.Location;
        using (var marker=new EventWaitHandle(false,EventResetMode.ManualReset,EventName(id,"marker")))
        using (var leak=new EventWaitHandle(false,EventResetMode.ManualReset,EventName(id,"leak")))
        using (var ready=new EventWaitHandle(false,EventResetMode.ManualReset,EventName(id,"ready")))
        using (var stop=new EventWaitHandle(false,EventResetMode.ManualReset,EventName(id,"stop")))
        {
            var raw=marker.SafeWaitHandle.DangerousGetHandle();
            if (!SetHandleInformation(raw,1,1)) throw new Exception("Could not create an inheritable host marker.");
            string value=raw.ToInt64().ToString(), run=id.ToString("N");
            try
            {
                WeChatSandboxProcess.StartDetached(test,"--sandbox-handle-test","check",run,value);
                DesktopChecks.Assert(ready.WaitOne(5000) && !leak.WaitOne(0),"connected guest UI cannot inherit an external CLI handle");
                ready.Reset();
                var query=Task.Run(()=>WeChatSandboxProcess.Query(test,"--sandbox-handle-test","parent",run,value));
                DesktopChecks.Assert(query.Wait(10000) && query.Result.Trim()=="sandbox-fixture" &&
                    ready.WaitOne(0) && !leak.WaitOne(0),
                    "sandbox command returns after its CLI exits while its descendant still holds the private stdout pipe");
            }
            finally { stop.Set(); }
        }
    }

    internal static void Run(string dir)
    {
        CheckProcessHandles();
        var id = Guid.NewGuid();
        string input = Path.Combine(dir,"Sandbox & Input");
        foreach (bool network in new[]{false,true})
        {
            var config = new XmlDocument();
            config.LoadXml(WeChatSandboxLauncher.BuildConfig(input, network, id));
            var share = config.SelectNodes("/Configuration/MappedFolders/MappedFolder");
            DesktopChecks.Assert(share.Count==1 && share[0]["HostFolder"].InnerText==input &&
                share[0]["ReadOnly"].InnerText=="true" && share[0]["SandboxFolder"].InnerText==@"C:\AppShieldInput",
                "guest receives exactly one read-only installer directory");
            foreach (var key in new[]{"ClipboardRedirection","AudioInput","VideoInput","PrinterRedirection","VGpu"})
                if (config.DocumentElement[key]?.InnerText!="Disable") throw new Exception("Unexpected guest sharing");
            string command = config.DocumentElement["LogonCommand"]["Command"].InnerText;
            var guest = Encoding.Unicode.GetString(Convert.FromBase64String(command.Split(' ').Last()));
            DesktopChecks.Assert(config.DocumentElement["Networking"].InnerText==(network?"Enable":"Disable") &&
                guest.Contains(WeChatSandboxLauncher.InstallerHash) && guest.Contains(id.ToString("D")) &&
                !guest.Contains("__VERSION__") && command.Length < 8191, "guest mode, embedded verified installer and run identifier");
        }
        DesktopChecks.Assert(WeChatSandboxLauncher.ParseNewSession("{\"Id\":\""+id.ToString("D")+"\"}")==id,
            "only a new session ID from Sandbox start is accepted");
        try {WeChatSandboxLauncher.ParseNewSession("{\"message\":\""+id+"\"}"); throw new Exception("Accepted unrelated ID");}
        catch (InvalidDataException) { }
        var launcher = new WeChatSandboxLauncher(Path.Combine(dir,"sandbox-manager"));
        string fixture = Path.Combine(dir,"not-wechat-setup.exe");
        File.WriteAllText(fixture,"synthetic");
        try {launcher.ImportInstaller(fixture,WeChatSandboxLauncher.SupportedVersion); throw new Exception("Unexpected installer accepted");}
        catch (InvalidDataException) { }
        DesktopChecks.Assert(!launcher.HasInstaller(WeChatSandboxLauncher.SupportedVersion),"a rejected installer never populates the share");
    }
}
