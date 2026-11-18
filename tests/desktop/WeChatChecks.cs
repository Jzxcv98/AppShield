// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.IO;
using AppShield;

internal static class WeChatChecks
{
    internal static void Run(string dir)
    {
        var service = new AppService(Path.Combine(dir, "wechat-profiles"));
        string renamed = Path.Combine(dir, "Weixin.exe");
        File.Copy(typeof(WeChatChecks).Assembly.Location, renamed);
        using (var image = SafeFiles.OpenImage(renamed))
        {
            ImageTrust.Describe(renamed, image, out string signer);
            DesktopChecks.Assert(signer == null && !service.AddExecutable(renamed).IsWeChat,
                "a renamed unsigned executable cannot acquire the WeChat profile");
        }

        string installed = WeChatIntegration.Detect();
        if (installed == null) return;
        var metadata = FileVersionInfo.GetVersionInfo(installed);
        DesktopChecks.Assert(!WeChatIntegration.IsOfficialClient(installed, metadata, null),
            "WeChat product metadata alone does not establish the publisher");
        var profile = service.ImportWeChat();
        DesktopChecks.Assert(profile.IsWeChat && profile.ExecutablePath == installed &&
            profile.ProductVersion == metadata.ProductVersion && profile.Folders.Count == 0,
            "installed signed WeChat imported with its version and no host directory grants");
        profile.AllowInternet = false;
        profile = service.Save(profile);
        var manual = service.AddExecutable(installed);
        var repeated = service.ImportWeChat();
        DesktopChecks.Assert(repeated.Id == profile.Id && manual.IsWeChat && manual.Id == profile.Id &&
            repeated.Revision == profile.Revision && !repeated.AllowInternet,
            "manual selection and rediscovery preserve the WeChat identity and saved restrictions");
    }
}
