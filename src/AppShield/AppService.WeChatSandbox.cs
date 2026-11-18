// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.IO;
using AppShield.Model;
using AppShield.Native;

namespace AppShield
{
    public sealed partial class AppService
    {
        public bool HasWeChatSandboxInstaller(AppProfile profile)
        {
            var p = RegisteredWeChat(profile);
            return new WeChatSandboxLauncher(store.Root).HasInstaller(p.ProductVersion);
        }

        public void ImportWeChatSandboxInstaller(AppProfile profile, string path)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            WithAppLock(profile.Id, () => {
                var p = RegisteredWeChat(profile);
                new WeChatSandboxLauncher(store.Root).ImportInstaller(path, p.ProductVersion);
                return true;
            });
        }

        public string LaunchWeChatSandbox(AppProfile profile, bool allowNetwork)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            return WithAppLock(profile.Id, () =>
            {
                var p = RegisteredWeChat(profile);
                using (var image = SafeFiles.OpenImage(p.ExecutablePath))
                {
                    AppShieldEngine.CheckHash(image, p);
                    ImageTrust.Describe(p.ExecutablePath, image, out var signer);
                    var meta = FileVersionInfo.GetVersionInfo(p.ExecutablePath);
                    if (!WeChatIntegration.IsOfficialClient(p.ExecutablePath, meta, signer) || meta.ProductVersion != p.ProductVersion)
                        throw new InvalidDataException("请重新导入本机安装的官方微信并核对版本。");
                }
                return new WeChatSandboxLauncher(store.Root).Launch(p.ProductVersion, allowNetwork);
            });
        }
    }
}
