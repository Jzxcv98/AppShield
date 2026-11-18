// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using System.Security;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Forms = System.Windows.Forms;

namespace AppShield.UI
{
    public partial class MainWindow
    {
        private sealed class AccountFolderRow
        {
            public string Path { get; set; }
            public string Account { get; set; }
            public string Sid { get; set; }
            public string Status { get; set; }
        }

        private async void OnSectionSelected(object sender, SelectionChangedEventArgs e)
        {
            if (e.Source != Sections || AccountTab == null || AccountPasswordBox == null) return;
            if (!AccountTab.IsSelected) AccountPasswordBox.Clear();
            UpdateButtons();
            if (AccountTab.IsSelected) await RefreshAccountFolders();
            else if (LiveTab.IsSelected) await RefreshLivePrivacy();
        }

        private void OnAccountFieldChanged(object sender, RoutedEventArgs e) => UpdateAccountButtons();

        private void UpdateAccountButtons()
        {
            if (AccountRevokeButton == null || AccountFolderList == null) return;
            bool active = !busy && AccountTab.IsSelected && Current?.Profile.IsWeChat == true;
            using (var value = AccountPasswordBox.SecurePassword)
                AccountLaunchButton.IsEnabled = AccountProtectButton.IsEnabled = active &&
                    !string.IsNullOrWhiteSpace(AccountNameBox.Text) && value.Length != 0;
            AccountRevokeButton.IsEnabled = active && AccountFolderList.SelectedItem is AccountFolderRow;
        }

        private async Task RefreshAccountFolders()
        {
            var row = Current;
            if (!AccountTab.IsSelected || row?.Profile.IsWeChat != true) return;
            try
            {
                var records = await Call(() => service.WeChatFolderProtections(row.Profile));
                if (closed || !AccountTab.IsSelected || row != Current) return;
                var previous = AccountFolderList.SelectedItem as AccountFolderRow;
                var folders = records.Select(r => new AccountFolderRow {
                    Path = r.Path, Account = r.Account, Sid = r.Sid, Status = r.Verified ? "已核实" : "需处理"
                }).ToArray();
                AccountFolderList.ItemsSource = folders;
                if (previous != null) AccountFolderList.SelectedItem = folders.FirstOrDefault(r =>
                    string.Equals(r.Path, previous.Path, StringComparison.OrdinalIgnoreCase) && r.Sid == previous.Sid);
                AccountFolderSummary.Text = folders.Length == 0 ? "尚未保护任何目录" : "已登记 " + folders.Length + " 个目录";
            }
            catch (Exception ex)
            {
                if (closed || !AccountTab.IsSelected || row != Current) return;
                AccountFolderList.ItemsSource = null;
                AccountFolderSummary.Text = "无法核实目录保护";
                Feedback(ex.Message);
            }
        }

        private async void OnAccountLaunch(object sender, RoutedEventArgs e)
        {
            var profile = Current?.Profile;
            if (profile?.IsWeChat != true || !AccountTab.IsSelected || busy) return;
            string account = AccountNameBox.Text.Trim();
            bool limitClipboard = AccountClipLimit.IsChecked == true;
            using (SecureString password = AccountPasswordBox.SecurePassword)
            {
                AccountPasswordBox.Clear();
                await Work(async () => {
                    int pid = await Call(() => service.LaunchWeChatAsAccount(profile, account, password, limitClipboard));
                    Feedback("已核对专用账户并启动微信，启动器 PID " + pid + "。");
                });
            }
        }

        private async void OnAccountProtect(object sender, RoutedEventArgs e)
        {
            var profile = Current?.Profile;
            if (profile?.IsWeChat != true || !AccountTab.IsSelected || busy) return;
            string account = AccountNameBox.Text.Trim();
            using (SecureString password = AccountPasswordBox.SecurePassword)
            using (var picker = new Forms.FolderBrowserDialog { Description = "选择要对该账户拒绝读取的目录", ShowNewFolderButton = false })
            {
                AccountPasswordBox.Clear();
                if (picker.ShowDialog(new WindowOwner(this)) != Forms.DialogResult.OK) return;
                string path = picker.SelectedPath;
                await Work(async () => {
                    try
                    {
                        await Call(() => { service.ProtectWeChatFolder(profile, path, account, password); return true; });
                        Feedback("已应用该账户的目录保护。");
                    }
                    finally { await RefreshAccountFolders(); }
                });
            }
        }

        private async void OnAccountUnprotect(object sender, RoutedEventArgs e)
        {
            var profile = Current?.Profile;
            var selected = AccountFolderList.SelectedItem as AccountFolderRow;
            if (profile?.IsWeChat != true || selected == null || !AccountTab.IsSelected || busy) return;
            AccountPasswordBox.Clear();
            await Work(async () => {
                try
                {
                    await Call(() => { service.UnprotectWeChatFolder(profile, selected.Path); return true; });
                    Feedback("已撤销所选目录保护。");
                }
                finally { await RefreshAccountFolders(); }
            });
        }
    }
}
