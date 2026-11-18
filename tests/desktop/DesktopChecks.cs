// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using AppShield;
using AppShield.Model;
using AppShield.Native;
using AppShield.Telegram;

internal static class DesktopChecks
{
    internal static void Assert(bool ok,string detail) { if(!ok) throw new Exception(detail);Console.WriteLine("PASS "+detail); }
    private static void Reject(Action action,string detail) {
        try {action();}
        catch(Exception){Console.WriteLine("PASS "+detail);return;}
        throw new Exception("Unexpected success: "+detail);
    }
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)]
    private static extern int DeleteAppContainerProfile(string name);

    private static void ProfileAndSettings(string dir)
    {
        var app=new AppService(Path.Combine(dir,"data"));
        var p=app.AddExecutable(typeof(DesktopChecks).Assembly.Location);
        var other=new AppService(app.StorageRoot);
        var old=other.Profiles.Single();
        Assert(p.Id==old.Id && p.ImageHash.Length==64,"persistent application identity");
        p.AllowTextIn=true;p=app.Save(p);
        Reject(()=>other.Save(old),"stale permission edit rejected");
        Assert(other.Profiles.Single().AllowTextIn,"saved permission reloaded");
        var shortcut=Path.Combine(dir,"managed.lnk");
        app.CreateShortcut(p.Id,shortcut,false);
        Assert(File.Exists(shortcut),"verified shortcut routes through the AppShield launcher");
        Reject(()=>app.CreateShortcut(p.Id,shortcut,false),"shortcut overwrite requires consent");
        Assert(File.Exists(app.StageText(p.Id,"demo")),"explicit synthetic text transfer");
        Reject(()=>app.ReadIncomingText(p.Id,"unused.txt"),"text export defaults to off");
        Assert(TelegramIntegration.Identify("Telegram.exe")==null,"relative executable rejected for trusted profile");
        string work=Path.Combine(dir,"blank");
        AppShieldEngine.PrepareTelegram(work);
        string opts=Path.Combine(work,"tdata","experimental_options.json");
        Assert(File.ReadAllText(opts).Contains("\"skip-url-scheme-register\":true"),"Telegram prevents first-run protocol registration");
        File.WriteAllText(opts,"{\"feature\":1,\"skip-url-scheme-register\":false}");
        AppShieldEngine.PrepareTelegram(work);var seeded=File.ReadAllText(opts);AppShieldEngine.PrepareTelegram(work);
        Assert(File.ReadAllText(opts)==seeded && seeded.Contains("\"feature\":1"),"Telegram seed preserves other options and is idempotent");
        File.WriteAllText(opts,"malformed");
        Reject(()=>AppShieldEngine.PrepareTelegram(work),"invalid Telegram options preserved");
    }

    private static void Live(string dir,string executable,IPAddress publicEndpoint = null)
    {
        var address=NetworkInterface.GetAllNetworkInterfaces().Where(i=>i.OperationalStatus==OperationalStatus.Up &&
            i.NetworkInterfaceType!=NetworkInterfaceType.Loopback).SelectMany(i=>i.GetIPProperties().UnicastAddresses)
            .Select(a=>a.Address).First(a=>a.AddressFamily==AddressFamily.InterNetwork && !IPAddress.IsLoopback(a));
        var listener=new TcpListener(IPAddress.Any,0);
        var ipv6=new TcpListener(IPAddress.IPv6Loopback,0);
        listener.Start();
        try {
            ipv6.Start();
            int port=((IPEndPoint)listener.LocalEndpoint).Port;
            int port6=((IPEndPoint)ipv6.LocalEndpoint).Port;
            VerifyListener(listener,IPAddress.Loopback,port);
            VerifyListener(listener,address,port);
            VerifyListener(ipv6,IPAddress.IPv6Loopback,port6);
            RunLive(dir,executable,address,port,port6,publicEndpoint);
        } finally{ipv6.Stop();listener.Stop();}
    }

    private static void VerifyListener(TcpListener listener,IPAddress address,int port)
    {
        using(var test=new TcpClient(address.AddressFamily)) {
            test.Connect(address,port);
            using(var received=listener.AcceptTcpClient())
                Assert(received.Connected,"reachable host-side "+address.AddressFamily+" control listener");
        }
    }

    private static void CloseFixtureImage(string image)
    {
        foreach(var proc in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(image))) using(proc) {
            if(!NativeJob.Image(proc.Handle).Equals(image,StringComparison.OrdinalIgnoreCase)) continue;
            if(!proc.CloseMainWindow() || !proc.WaitForExit(3000)) proc.Kill();
            if(!proc.WaitForExit(5000))throw new Exception("synthetic window did not close");
        }
    }

    private static void CheckHandoff(AppService app,AppProfile p,string work,string childImage,string expectedData)
    {
        File.Delete(Path.Combine(work,"fixture-result.txt"));
        File.WriteAllText(Path.Combine(work,"fixture-handoff.test"),"synthetic");
        try { Console.WriteLine(app.Launch(p)); }
        catch(Exception) {
            var markerPath=Path.Combine(work,"fixture-stage.txt");
            string marker=File.Exists(markerPath)?File.ReadAllText(markerPath):"not-written";
            if(marker.StartsWith("spawn-worker:",StringComparison.Ordinal) &&
                uint.TryParse(marker.Substring("spawn-worker:".Length),out uint reason))
                Console.WriteLine("UNCONFIRMED: Windows refused to create the synthetic helper, Win32="+reason);
            throw;
        }
        var watch=Stopwatch.StartNew();
        var report=app.Inspect(p);
        while(report.Targets.Count!=1 && watch.ElapsedMilliseconds<15000) {
            System.Threading.Thread.Sleep(100);report=app.Inspect(p);
        }
        Assert(report.Boxed==1 && report.Targets.Count==1 && report.Unknown==0,
            "launcher exited and its differently named child remains in the verified job and SID");
        using(var worker=Process.GetProcessById(report.Targets[0].ProcessId))
            Assert(NativeJob.Image(worker.Handle).Equals(childImage,StringComparison.OrdinalIgnoreCase),
                "actual child image owns the observed window");
        Assert(File.ReadAllText(Path.Combine(work,"fixture-result.txt"))==expectedData,
            "descendant exercises inherited file and network boundaries");
        Reject(()=>app.Apply(p),"verified descendant blocks policy replacement after launcher exit");
        Reject(()=>app.Launch(p),"a second launch cannot take ownership of an active job");
        Assert(app.Inspect(p).Targets.Any(t=>t.ProcessId==report.Targets[0].ProcessId),
            "existing job survives the rejected concurrent launch");
        CloseFixtureImage(childImage);
        File.WriteAllText(Path.Combine(work,"fixture-nonzero-handoff.test"),"synthetic");
        string handoff = app.Launch(p);
        var surviving = app.Inspect(p);
        Assert(handoff.Contains("0x00000021") && surviving.Boxed==1 && surviving.Unknown==0,
            "nonzero launcher exit is reported while its verified helper remains managed");
        CloseFixtureImage(childImage);
        File.WriteAllText(Path.Combine(work,"fixture-exit.test"),"synthetic");
        string reasonText="";
        try { app.Launch(p); }
        catch(InvalidOperationException ex) { reasonText=ex.Message; }
        Assert(reasonText.Contains("32") && !NativeJob.Active(p.Id),
            "launcher exit without a descendant reports its real code and leaves an empty job");
    }

    private static void RunLive(string dir,string executable,IPAddress lan,int port,int port6,IPAddress publicEndpoint)
    {
        var app=new AppService(Path.Combine(dir,"live-state"));
        Assert(app.Inspect(null).EngineReady,"live verifier uses the desktop application's Windows compatibility declaration");
        string privateFile=Path.Combine(dir,"private.txt");
        string readOnly=Path.Combine(dir,"readonly"),writable=Path.Combine(dir,"writable");
        Directory.CreateDirectory(readOnly); Directory.CreateDirectory(writable);
        string roFile=Path.Combine(readOnly,"sample.txt"),rwFile=Path.Combine(writable,"new.txt");
        string helper=Path.Combine(readOnly,"AppShieldFixtureChild.exe");
        File.WriteAllText(privateFile,"secret");File.WriteAllText(roFile,"allowed");
        File.Copy(executable,helper);
        // Ensure inherited package access cannot invalidate the negative control.
        var user=WindowsIdentity.GetCurrent().User;
        var acl=new FileSecurity();acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(new FileSystemAccessRule(user,FileSystemRights.FullControl,AccessControlType.Allow));
        File.SetAccessControl(privateFile,acl);
        var p=app.AddExecutable(executable);
        p.AllowInternet=publicEndpoint!=null;p.BlockLan=true;p.BlockLoopback=true;
        p.AllowTextIn=publicEndpoint==null;
        p.Folders.Add(new FolderRule{Path=readOnly});p.Folders.Add(new FolderRule{Path=writable,Writable=true});
        p=app.Save(p);
        Console.WriteLine("Live fixture id: "+p.Id.ToString("N"));
        bool ownsProfile=false;
        try {
            using(var identity=new ContainerIdentity(p.Id,true)) {
                ownsProfile=true;
                string work=Path.Combine(identity.Folder,"AppShieldWork");Directory.CreateDirectory(work);
                string nonce=Guid.NewGuid().ToString("N");
                if(publicEndpoint==null) File.WriteAllText(Path.Combine(work,"fixture-text-nonce.txt"),nonce,new UTF8Encoding(false));
                var config=new[]{privateFile,roFile,rwFile,lan.ToString(),port.ToString(),port6.ToString()};
                if(publicEndpoint!=null) config=config.Concat(new[]{publicEndpoint.ToString()}).ToArray();
                File.WriteAllBytes(Path.Combine(work,"fixture.txt"),Encoding.Unicode.GetBytes(string.Join("\n",config)+"\n"));
                app.Apply(p); Console.WriteLine("PASS real native policy application");
                Console.WriteLine(app.Launch(p));
                // Retain a query handle while this fixture is alive so that failures
                // after Launch returns have an observable exit code.
                var expectedImage=NativePolicy.Image(app.StorageRoot,p);
                Process fixtureProcess=null;
                foreach(var candidate in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(executable))) {
                    try {
                        if(fixtureProcess==null && NativeJob.Image(candidate.Handle).Equals(expectedImage,StringComparison.OrdinalIgnoreCase)) {
                            fixtureProcess=candidate;continue;
                        }
                    }catch(InvalidOperationException){} catch(System.ComponentModel.Win32Exception){}
                    candidate.Dispose();
                }
                using(fixtureProcess) {
                string resultPath=Path.Combine(work,"fixture-result.txt");
                var deadline=Stopwatch.StartNew();
                while(!File.Exists(resultPath) && deadline.ElapsedMilliseconds<10000) System.Threading.Thread.Sleep(100);
                var report=app.Inspect(p);
                while(report.Targets.Count==0 && deadline.ElapsedMilliseconds<12000){System.Threading.Thread.Sleep(100); report=app.Inspect(p);}
                if(report.Targets.Count!=1 || !File.Exists(resultPath)) {
                    var stagePath=Path.Combine(work,"fixture-stage.txt");
                    var stage=File.Exists(stagePath)?File.ReadAllText(stagePath):"not-written";
                    // Stage data is generated exclusively by the synthetic fixture.
                    if(stage.Length>48 || !stage.All(c=>char.IsLetterOrDigit(c)||c=='-'||c==':'))stage="unrecognized";
                    Console.WriteLine("DIAGNOSTIC stage="+stage+" result="+File.Exists(resultPath)+" engine="+report.EngineReady+" boxed="+report.Boxed+
                        " unknown="+report.Unknown+" windows="+report.Targets.Count+" process="+
                        (fixtureProcess==null?"not-observed":fixtureProcess.HasExited?"exit-0x"+fixtureProcess.ExitCode.ToString("x8"):"alive"));
                }
                Assert(report.Boxed==1 && report.Targets.Count==1 && report.Applied,"actual package SID, named job and GUI window");
                var result=File.ReadAllText(resultPath);
                string wanted=publicEndpoint==null?"1111111":"11111110";
                if(publicEndpoint!=null) Assert(PublicNetworkChecks.Connect(publicEndpoint),"host can still reach the same official TCP endpoint after the sandbox trial");
                Assert(result==wanted,"private/read-only/write-denied/read-write/IPv4 loopback/LAN/IPv6 loopback"+
                    (publicEndpoint==null?"":"/public TCP handshake")+" checks ("+result+")");
                Assert(File.ReadAllText(roFile)=="allowed" && File.ReadAllText(rwFile)=="approved","host permissions match actual file content");
                if(publicEndpoint==null) {
                    var target=report.Targets.Single();
                    var stale=new TextTarget {WindowHandle=target.WindowHandle,ProcessId=target.ProcessId,
                        ProcessStartUtcTicks=target.ProcessStartUtcTicks-1};
                    string sample="AppShield \u6587\u672c "+nonce;
                    string receipt=Path.Combine(work,"fixture-text-receipt.txt");
                    Reject(()=>app.PasteText(p.Id,stale,sample),"stale target identity rejected before text delivery");
                    Assert(!File.Exists(receipt) || File.ReadAllText(receipt)!="1","stale target did not receive text");
                    var window=System.Windows.Automation.AutomationElement.FromHandle(new IntPtr(target.WindowHandle));
                    var match=new System.Windows.Automation.PropertyCondition(
                        System.Windows.Automation.AutomationElement.ControlTypeProperty,System.Windows.Automation.ControlType.Edit);
                    var input=window.FindAll(System.Windows.Automation.TreeScope.Children,match);
                    Assert(input.Count==1 && input[0].Current.ProcessId==target.ProcessId,
                        "selected the synthetic window's own standard Edit control");
                    input[0].SetFocus();
                    app.PasteText(p.Id,target,sample);
                    var until=Stopwatch.StartNew();
                    while(!File.Exists(receipt) && until.ElapsedMilliseconds<2500) System.Threading.Thread.Sleep(50);
                    Assert(File.Exists(receipt) && File.ReadAllText(receipt)=="1",
                        "explicit Unicode text arrived in the verified native Edit; recipient confirmed the one-time marker");
                    File.Delete(Path.Combine(work,"fixture-text-nonce.txt"));
                }
                Reject(()=>app.Apply(p),"live process blocks policy replacement");
                }
                CloseFixtureImage(expectedImage);
                if(publicEndpoint==null) CheckHandoff(app,p,work,helper,"1111111");
            }
        } catch(Exception ex) {
            Console.Error.WriteLine("Live check: "+ex.GetBaseException().Message);throw;
        } finally {
            if(ownsProfile){
                // Account for a failed startup/observation as well as a successful window:
                // the only executable eligible for cleanup is this run's unique copied fixture.
                CloseFixtureImage(NativePolicy.Image(app.StorageRoot,p));
                CloseFixtureImage(helper);
                app.Revoke(p);
                Assert(!app.Inspect(p).Applied,"revocation clears active policy");
                int removed=DeleteAppContainerProfile(ContainerIdentity.NameFor(p.Id));
                for(int retry=0;retry<5 && removed==unchecked((int)0x80070005);retry++) {
                    System.Threading.Thread.Sleep(400);removed=DeleteAppContainerProfile(ContainerIdentity.NameFor(p.Id));
                }
                Assert(removed==0,"removed only the newly created test profile");
            }
        }
    }

    [STAThread] static int Main(string[] args) {
        if (args.Length > 0 && args[0] == "--sandbox-handle-test") return WeChatSandboxLauncherChecks.RunHelper(args);
        if (args.Length == 1 && args[0] == "--conversation-gpt-synthetic") return ConversationDraftChecks.SyntheticApi();
        if (args.Length > 0 && args[0] == "--conversation-phone-marker") return ConversationPhoneChecks.Run(args.Skip(1).ToArray());
        if (args.Length == 1 && args[0] == "--conversation-uia-fixture") {
            try { WeChatVisibleConversationChecks.Run(); return 0; }
            catch (Exception ex) { Console.Error.WriteLine(ex.GetBaseException().Message); return 1; }
        }
        if (args.Length == 1 && args[0] == "--wechat-prelogin") return WeChatPreloginChecks.Run();
        if (args.Length > 0 && args[0] == "--wechat-clipboard-test") return WeChatClipboardChecks.Run(args.Skip(1).ToArray());
        if (args.Length == 1 && args[0] == "--wechat-window-markers") {
            try { WeChatWindowMarkerChecks.Run(); return 0; }
            catch (Exception e) { Console.Error.WriteLine(e.GetBaseException().Message); return 1; }
        }
        string temp=Path.GetFullPath(Path.GetTempPath()).TrimEnd('\\');
        string dir=Path.Combine(temp,"AppShield.DesktopChecks."+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try {
            if(args.Length==1 && args[0]=="--conversation-panel") { ConversationPanelChecks.Run(dir); return 0; }
            if(args.Length==1 && args[0]=="--wechat-launch-dialog") { WeChatLaunchDialogChecks.Run(dir); return 0; }
            if(args.Length==1 && args[0]=="--conversation-auto-gpt-synthetic") { ConversationPanelChecks.RunAutoSyntheticApi(dir); return 0; }
            TransferChecks.Run();Console.WriteLine("PASS file broker regression suite");
            NetworkChecks.Run();Console.WriteLine("PASS package network identity and combinations");
            ConversationDraftChecks.Run(dir);
            WeChatBubbleSideChecks.Run();
            ConversationHistoryChecks.Run(dir);
            ConversationTranscriptChecks.Run(dir);
            ConversationAutoDraftTriggerChecks.Run();
            ImageTrustChecks.Run();
            WeChatChecks.Run(dir);
            WeChatSandboxLauncherChecks.Run(dir);
            WeChatLiveStatusChecks.Run();
            WeChatFolderGuardChecks.Run(dir);
            WeChatInstanceChecks.Run(dir);
            GrantIdentityChecks.Run();
            ProfileAndSettings(dir);
            if(args.Length==2 && args[0]=="--live") { WeChatLiveStatusChecks.RunLoopback(); Live(dir,args[1]); }
            else if(args.Length==2 && args[0]=="--public-network") {
                var endpoint=PublicNetworkChecks.SelectEndpoint();
                if(endpoint==null) {
                    Console.WriteLine("UNTESTED: no direct host TCP control reached "+PublicNetworkChecks.Host+":443.");
                    return 77;
                }
                Console.WriteLine("PASS host TCP control reached "+PublicNetworkChecks.Host+":443; no application data sent");
                Live(dir,args[1],endpoint);
            }
            else if(args.Length!=0)return 2;
            return 0;
        } catch(Exception ex){Console.Error.WriteLine(ex.GetBaseException().Message);return 1;}
        finally {
            if(Path.GetDirectoryName(Path.GetFullPath(dir)).Equals(temp,StringComparison.OrdinalIgnoreCase) &&
                (File.GetAttributes(dir)&FileAttributes.ReparsePoint)==0) Directory.Delete(dir,true);
        }
    }
}
