// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using System.Text;
using System.Windows;
using AppShield.UI;

namespace AppShield
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                if (args.Length == 3 && args[0] == "--keep-job" && Guid.TryParseExact(args[1], "N", out var job)
                    && Guid.TryParseExact(args[2], "N", out var nonce))
                    return Native.NativeJob.Keep(job, nonce);
                var service = new AppService();
                if (args.Length == 0) return new Application().Run(new MainWindow(service));
                if (args.Length == 2 && args[0] == "--open-profile" && Guid.TryParseExact(args[1], "N", out var profile))
                {
                    try
                    {
                        var app = service.Profiles.SingleOrDefault(p => p.Id == profile)
                            ?? throw new InvalidOperationException("找不到该快捷方式的应用配置。");
                        if (app.IsWeChat) return WeChatLaunchDialog.ShowLaunch(service, app) == true ? 0 : 2;
                        service.Launch(app);
                        return 0;
                    }
                    catch (Exception ex) { MessageBox.Show(ex.Message, "AppShield 隔离启动", MessageBoxButton.OK, MessageBoxImage.Warning); return 1; }
                }
                Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
                Console.SetError(new System.IO.StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
                if (args.Length == 2 && (args[0] == "--prepare-wechat-sandbox" || args[0] == "--launch-wechat"))
                {
                    var profiles = service.Profiles.Where(p => p.IsWeChat).Take(2).ToArray();
                    if (profiles.Length != 1) { Console.Error.WriteLine("请先导入微信，并在界面中选择唯一目标。"); return 2; }
                    if (args[0] == "--prepare-wechat-sandbox")
                    {
                        service.ImportWeChatSandboxInstaller(profiles[0], args[1]);
                        Console.WriteLine("已核验并缓存微信沙盒安装包。");
                        return 0;
                    }
                    switch (args[1])
                    {
                        case "--sandbox-offline": Console.WriteLine(service.LaunchWeChatSandbox(profiles[0], false)); return 0;
                        case "--sandbox-network": Console.WriteLine(service.LaunchWeChatSandbox(profiles[0], true)); return 0;
                        case "--appcontainer": Console.WriteLine(service.LaunchAppContainer(profiles[0])); return 0;
                        default: Console.Error.WriteLine("可选 --sandbox-offline、--sandbox-network 或 --appcontainer。"); return 2;
                    }
                }
                if (args.Length != 1 || !args[0].StartsWith("--", StringComparison.Ordinal)) return 2;
                int separator = args[0].LastIndexOf('-');
                if (separator <= 2) return 2;
                string action = args[0].Substring(2, separator - 2);
                string product = args[0].Substring(separator + 1);
                bool weChat = product == "wechat";
                if (!weChat && product != "telegram") return 2;
                if (action == "import")
                {
                    var app = weChat ? service.ImportWeChat() : service.ImportTelegram();
                    Console.WriteLine(app.Name + " " + app.ProductVersion + " | " + app.Publisher);
                    Console.WriteLine("Registered persistent application profile.");
                    return 0;
                }
                if (action != "status" && action != "apply" && action != "revoke" && action != "launch") return 2;
                var matches = service.Profiles.Where(p => weChat ? p.IsWeChat : p.IsTelegram).Take(2).ToList();
                if (matches.Count == 0)
                {
                    Console.Error.WriteLine((weChat ? "WeChat" : "Telegram") + " profile is not registered.");
                    return 2;
                }
                if (weChat && matches.Count > 1)
                {
                    Console.Error.WriteLine("Multiple WeChat profiles are registered. Select the intended profile in AppShield.");
                    return 2;
                }
                var selected = matches[0];
                switch (action)
                {
                    case "apply": Console.WriteLine(service.Apply(selected)); return 0;
                    case "revoke": Console.WriteLine(service.Revoke(selected)); return 0;
                    case "launch":
                        if (weChat)
                        {
                            if (!Environment.UserInteractive)
                            {
                                Console.Error.WriteLine("请指定 --sandbox-offline、--sandbox-network 或 --appcontainer。");
                                return 2;
                            }
                            if (WeChatLaunchDialog.ShowLaunch(service, selected, null, out var detail) != true) return 2;
                            Console.WriteLine(detail);
                            return 0;
                        }
                        Console.WriteLine(service.Launch(selected)); return 0;
                    default:
                        var report = service.Inspect(selected);
                        Console.WriteLine("Engine ready: " + report.EngineReady + " | " + report.EngineDetail);
                        Console.WriteLine("Current revision applied: " + report.Applied);
                        Console.WriteLine(report.State + " | boxed=" + report.Boxed + " outside=" + report.Unboxed + " unknown=" + report.Unknown);
                        if (weChat) Console.WriteLine(report.Detail);
                        return 0;
                }
            }
            catch (Exception ex)
            {
                if (args.Length == 0) MessageBox.Show(ex.Message, "AppShield", MessageBoxButton.OK, MessageBoxImage.Error);
                else Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }
    }
}
