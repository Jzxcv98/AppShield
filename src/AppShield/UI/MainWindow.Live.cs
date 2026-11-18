// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using AppShield.Model;

namespace AppShield.UI
{
    public partial class MainWindow
    {
        private bool settingLiveTargets, refreshingLiveTargets;
        private bool? outboundBlocked;
        private int liveGeneration, targetGeneration;

        private void ClearLivePrivacy()
        {
            ++liveGeneration;
            ++targetGeneration;
            refreshingLiveTargets = false;
            outboundBlocked = null;
            LiveCounts.DataContext = null;
            LiveSampleNote.Text = "尚未采样";
            LiveNetworkTarget.ItemsSource = null;
            LiveNetworkState.Text = "规则状态待核实";
        }

        private void UpdateLiveButtons()
        {
            if (LiveClipButton == null) return;
            bool available = !busy && LiveTab.IsSelected && Current?.Profile.IsWeChat == true;
            LiveRefreshButton.IsEnabled = available;
            LiveNetworkTarget.IsEnabled = available && !refreshingLiveTargets && LiveNetworkTarget.Items.Count != 0;
            LiveBlockButton.IsEnabled = available && !refreshingLiveTargets && outboundBlocked == false;
            var target = LiveNetworkTarget.SelectedItem as WeChatNetworkTarget;
            LiveRevokeButton.IsEnabled = available && !refreshingLiveTargets &&
                (outboundBlocked == true || target?.HasOwnedRule == true);
            var sample = LiveCounts.DataContext as WeChatLiveReport;
            LiveClipButton.IsEnabled = available && sample != null && sample.CurrentUserProcesses == 0 &&
                sample.OtherUserProcesses == 0 && sample.OtherSessionProcesses == 0 && sample.UnverifiedProcesses == 0;
            LiveClipButton.ToolTip = LiveClipButton.IsEnabled ? null : "请先正常退出微信，然后刷新进程状态。";
        }

        private async Task RefreshLivePrivacy()
        {
            var row = Current;
            if (!LiveTab.IsSelected || row?.Profile.IsWeChat != true) return;
            int generation = ++liveGeneration;
            ++targetGeneration;
            refreshingLiveTargets = true;
            string previous = LiveNetworkTarget.SelectedValue as string;
            outboundBlocked = null;
            LiveCounts.DataContext = null;
            LiveSampleNote.Text = "正在采样…";
            LiveNetworkState.Text = "正在核对规则…";
            UpdateLiveButtons();
            try
            {
                var sample = await Call(() => service.InspectRunningWeChat(row.Profile));
                if (!LiveResultCurrent(row, generation)) return;
                LiveCounts.DataContext = sample;
                LiveSampleNote.Text = $"采样时间 {sample.SampleUtc.ToLocalTime():HH:mm:ss}　归属未确认的同名进程 {sample.UnverifiedProcesses} 个";
            }
            catch (Exception ex)
            {
                if (!LiveResultCurrent(row, generation)) return;
                LiveSampleNote.Text = "无法核实微信进程与连接：" + ex.Message;
            }
            try
            {
                var targets = await Call(() => service.WeChatNetworkTargets(row.Profile));
                if (!LiveResultCurrent(row, generation)) return;
                settingLiveTargets = true;
                try
                {
                    LiveNetworkTarget.ItemsSource = targets;
                    LiveNetworkTarget.SelectedItem = targets.FirstOrDefault(t => t.Sid == previous) ?? targets.FirstOrDefault();
                }
                finally { settingLiveTargets = false; }
                await RefreshLiveNetworkRule();
            }
            catch (Exception ex)
            {
                if (!LiveResultCurrent(row, generation)) return;
                LiveNetworkTarget.ItemsSource = null;
                LiveNetworkState.Text = "无法核实规则账户：" + ex.Message;
            }
            finally
            {
                if (generation == liveGeneration) refreshingLiveTargets = false;
                if (!closed) UpdateLiveButtons();
            }
        }

        private bool LiveResultCurrent(AppRow row, int generation) =>
            !closed && LiveTab.IsSelected && row == Current && generation == liveGeneration;

        private async void OnLiveTargetSelected(object sender, SelectionChangedEventArgs e)
        {
            if (!settingLiveTargets && e.Source == LiveNetworkTarget) await RefreshLiveNetworkRule();
        }

        private async Task RefreshLiveNetworkRule()
        {
            int generation = ++targetGeneration;
            var row = Current;
            var sid = LiveNetworkTarget.SelectedValue as string;
            outboundBlocked = null;
            UpdateLiveButtons();
            if (row?.Profile.IsWeChat != true || !LiveTab.IsSelected) return;
            if (sid == null) { LiveNetworkState.Text = "尚未选择已核验的本机账户"; return; }
            LiveNetworkState.Text = "正在核对规则…";
            try
            {
                bool blocked = await Call(() => service.IsWeChatNetworkBlocked(row.Profile, sid));
                if (generation != targetGeneration || row != Current || closed || !LiveTab.IsSelected) return;
                outboundBlocked = blocked;
                LiveNetworkState.Text = blocked ? "此账户和主程序的阻止规则已生效" : "此账户和主程序尚未启用 AppShield 出站阻止";
            }
            catch (Exception ex)
            {
                if (generation == targetGeneration && row == Current && !closed && LiveTab.IsSelected)
                    LiveNetworkState.Text = (LiveNetworkTarget.SelectedItem is WeChatNetworkTarget target && target.HasOwnedRule
                        ? "已登记规则的有效状态未知，可以撤销。" : "规则状态未知。") + ex.Message;
            }
            finally { if (!closed) UpdateLiveButtons(); }
        }

        private async void OnLiveRefresh(object sender, RoutedEventArgs e) => await Work(RefreshLivePrivacy);
        private async void OnLiveBlock(object sender, RoutedEventArgs e) => await ChangeLiveNetwork(true);
        private async void OnLiveRevoke(object sender, RoutedEventArgs e) => await ChangeLiveNetwork(false);

        private async Task ChangeLiveNetwork(bool block)
        {
            var profile = Current?.Profile;
            var sid = LiveNetworkTarget.SelectedValue as string;
            if (busy || refreshingLiveTargets || !LiveTab.IsSelected || profile?.IsWeChat != true || sid == null ||
                (block ? !LiveBlockButton.IsEnabled : !LiveRevokeButton.IsEnabled)) return;
            await Work(async () =>
            {
                try { await Call(() => { service.SetWeChatNetworkBlocked(profile, sid, block); return true; }); }
                finally { await RefreshLivePrivacy(); }
                var selected = LiveNetworkTarget.SelectedItem as WeChatNetworkTarget;
                if (selected?.Sid == sid && outboundBlocked == block && selected.HasOwnedRule == block)
                    Feedback(block ? "已核实新的出站阻止规则。" : "已核实出站阻止规则已撤销。");
                else if (!block && selected != null && !LiveNetworkTarget.Items.OfType<WeChatNetworkTarget>().Any(t => t.Sid == sid))
                    Feedback("已撤销该账户的出站规则，登记记录已移除。");
                else Feedback("更改后的规则状态尚未核实，请刷新核对。");
            });
        }

        private async void OnLiveClipLaunch(object sender, RoutedEventArgs e)
        {
            var profile = Current?.Profile;
            if (busy || !LiveTab.IsSelected || profile?.IsWeChat != true || !LiveClipButton.IsEnabled) return;
            await Work(async () =>
            {
                try
                {
                    int pid = await Call(() => service.LaunchWeChatWithClipboardLimit(profile));
                    Feedback("已使用剪贴板限制启动，启动器 PID " + pid + "。");
                }
                finally { await RefreshLivePrivacy(); }
            });
        }
    }
}
