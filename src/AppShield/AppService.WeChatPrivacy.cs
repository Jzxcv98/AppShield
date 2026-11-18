// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using AppShield.Model;
using AppShield.Native;

namespace AppShield.Model
{
    public sealed class WeChatNetworkTarget
    {
        public string Sid { get; internal set; }
        public string Label { get; internal set; }
        public bool HasOwnedRule { get; internal set; }
        public override string ToString() => Label;
    }
}

namespace AppShield
{
    public sealed partial class AppService
    {
        public WeChatLiveReport InspectRunningWeChat(AppProfile profile) =>
            WeChatLiveStatus.Read(RegisteredWeChat(profile));

        public int LaunchWeChatWithClipboardLimit(AppProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            return WithAppLock(profile.Id, () =>
            {
                var p = RegisteredWeChat(profile);
                RequireNoWeChatInstance(p);
                return WeChatClipboardJob.LaunchCurrentUser(p.ExecutablePath, p.ImageHash);
            });
        }

        private static string CurrentUserSid()
        {
            using (var self = WindowsIdentity.GetCurrent()) return self.User.Value;
        }

        private IEnumerable<string> DedicatedWeChatNetworkAccounts() =>
            accountGuard.List().Select(accountGuard.AccountSidFor).Where(s => s != null);

        public WeChatNetworkTarget[] WeChatNetworkTargets(AppProfile profile)
        {
            var p = RegisteredWeChat(profile);
            string current = CurrentUserSid();
            var recorded = new HashSet<string>(WeChatAccountNetwork.RecordedAccounts(p.Id, p.ExecutablePath).Select(s => s.Value));
            return new[] { current }.Concat(DedicatedWeChatNetworkAccounts()).Concat(recorded).Distinct().Select(s =>
            {
                string label;
                try { label = new SecurityIdentifier(s).Translate(typeof(NTAccount)).Value; }
                catch (IdentityNotMappedException) { label = s; }
                return new WeChatNetworkTarget { Sid = s, HasOwnedRule = recorded.Contains(s),
                    Label = s == current ? label + "（当前账户）" : label };
            }).ToArray();
        }

        private SecurityIdentifier NetworkTarget(AppProfile p, string sid)
        {
            if (sid != CurrentUserSid() && !DedicatedWeChatNetworkAccounts().Contains(sid) &&
                !WeChatAccountNetwork.RecordedAccounts(p.Id, p.ExecutablePath).Any(s => s.Value == sid))
                throw new InvalidOperationException("请使用当前 Windows 账户或已登记的专用账户。");
            return new SecurityIdentifier(sid);
        }

        public bool IsWeChatNetworkBlocked(AppProfile profile, string sid)
        {
            var p = RegisteredWeChat(profile);
            return WeChatAccountNetwork.IsApplied(p.Id, p.ExecutablePath, NetworkTarget(p, sid));
        }

        public void SetWeChatNetworkBlocked(AppProfile profile, string sid, bool blocked)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            WithAppLock(profile.Id, () =>
            {
                var p = RegisteredWeChat(profile);
                var account = NetworkTarget(p, sid);
                if (blocked)
                {
                    using (var image = SafeFiles.OpenImage(p.ExecutablePath))
                    {
                        AppShieldEngine.CheckHash(image, p);
                        ImageTrust.Describe(p.ExecutablePath, image, out string signer);
                        if (!WeChatIntegration.IsOfficialClient(p.ExecutablePath, FileVersionInfo.GetVersionInfo(p.ExecutablePath), signer))
                            throw new InvalidDataException("无法核对已登记的微信主程序。");
                        WeChatAccountNetwork.Apply(p.Id, p.ExecutablePath, account);
                    }
                }
                else WeChatAccountNetwork.Revoke(p.Id, p.ExecutablePath, account);
                return true;
            });
        }
    }
}
