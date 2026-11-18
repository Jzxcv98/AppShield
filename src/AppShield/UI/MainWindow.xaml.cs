// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Threading;
using AppShield.Model;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace AppShield.UI
{
    public partial class MainWindow : Window
    {
        private sealed class AppRow
        {
            public AppProfile Profile { get; set; }
            public bool Dirty { get; set; }
            public RuntimeReport Report { get; set; }
            public DateTime CheckedAt { get; set; }
            public string Outbox { get; set; }
            public string Inbox { get; set; }
            public string DisplayName => Profile.Name;
            public string FileName => Path.GetFileName(Profile.ExecutablePath);
        }

        private sealed class FolderRow
        {
            public FolderRule Rule { get; set; }
            public string Path => Rule.Path;
            public string ModeLabel => Rule.Writable ? "可读写" : "只读";
        }

        private sealed class WindowOwner : Forms.IWin32Window
        {
            public IntPtr Handle { get; }
            public WindowOwner(Window window) { Handle = new WindowInteropHelper(window).Handle; }
        }

        private readonly AppService service;
        private readonly ObservableCollection<AppRow> apps = new ObservableCollection<AppRow>();
        private readonly SemaphoreSlim backend = new SemaphoreSlim(1, 1);
        private readonly DispatcherTimer timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        private bool busy, inspecting, rendering, closed;
        private int inspectionNumber;
        private AppRow Current => AppList.SelectedItem as AppRow;

        public MainWindow(AppService service)
        {
            this.service = service ?? throw new ArgumentNullException(nameof(service));
            InitializeComponent();
            Width = Math.Min(Width, SystemParameters.WorkArea.Width);
            Height = Math.Min(Height, SystemParameters.WorkArea.Height);
            AppList.ItemsSource = apps;
            Loaded += OnLoaded;
            Closing += OnClosing;
            Deactivated += (sender, args) => AccountPasswordBox.Clear();
            Closed += (sender, args) => { closed = true; timer.Stop(); AccountPasswordBox.Clear(); ChatPanel.Detach(); };
            timer.Tick += async (sender, args) =>
            {
                if (IsActive && !busy && !inspecting) await InspectCurrent(false);
            };
            Activated += async (sender, args) =>
            {
                if (timer.IsEnabled && !busy && !inspecting && Current != null &&
                    DateTime.Now - Current.CheckedAt > TimeSpan.FromSeconds(3)) await InspectCurrent(false);
            };
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OnLoaded;
            await Work(async () =>
            {
                var profiles = await Call(() => service.Profiles.ToArray());
                foreach (var profile in profiles) apps.Add(new AppRow { Profile = profile });
                if (apps.Count > 0) AppList.SelectedIndex = 0;
                await InspectCurrent(true);
            });
            timer.Start();
        }

        private void OnClosing(object sender, CancelEventArgs e)
        {
            if (busy) { e.Cancel = true; Feedback("当前操作正在进行，请在结束后关闭窗口。"); return; }
            if (apps.Any(a => a.Dirty) && MessageBox.Show(this, "关闭后将放弃未保存的权限修改。", "关闭 AppShield？",
                    MessageBoxButton.OKCancel, MessageBoxImage.Question, MessageBoxResult.Cancel) != MessageBoxResult.OK)
                e.Cancel = true;
        }

        private async Task<T> Call<T>(Func<T> function)
        {
            await backend.WaitAsync();
            try { return await Task.Run(function); }
            finally { backend.Release(); }
        }

        private async Task Work(Func<Task> operation)
        {
            if (busy) return;
            busy = true;
            UpdateButtons();
            try { await operation(); }
            catch (Exception ex) { Feedback(ex.Message); }
            finally { busy = false; UpdateButtons(); }
        }

        private void Feedback(string value)
        {
            StatusMessage.Text = value ?? "";
            StatusMessage.ToolTip = StatusMessage.Text;
        }

        private async void OnRefresh(object sender, RoutedEventArgs e)
        {
            await Work(async () => {
                Feedback("");
                await InspectCurrent(true);
                if (AccountTab.IsSelected) await RefreshAccountFolders();
                if (LiveTab.IsSelected) await RefreshLivePrivacy();
            });
        }

        private async Task InspectCurrent(bool manual)
        {
            var row = Current;
            int number = ++inspectionNumber;
            // Inspect reloads the saved profile by identity; drafts remain with the UI.
            inspecting = true;
            try
            {
                var info = await Call(() =>
                {
                    if (row == null) return new { Report = service.Inspect(null), Outbox = "", Inbox = "" };
                    var id = row.Profile.Id;
                    return new { Report = service.Inspect(new AppProfile { Id = id }), Outbox = row.Outbox ?? service.OutgoingFolder(id),
                        Inbox = row.Inbox ?? service.IncomingFolder(id) };
                });
                if (closed || row != Current || number != inspectionNumber) return;
                var report = info.Report;
                EngineState.Text = report.EngineReady ? "引擎就绪" : "引擎未就绪";
                EngineState.ToolTip = report.EngineDetail;
                if (row != null)
                {
                    row.Report = report;
                    row.CheckedAt = DateTime.Now;
                    OutgoingPath.Text = row.Outbox = info.Outbox;
                    IncomingPath.Text = row.Inbox = info.Inbox;
                    ShowReport(row);
                }
                else Feedback(report.EngineDetail);
            }
            catch (Exception ex)
            {
                if (closed || row != Current || number != inspectionNumber) return;
                EngineState.Text = "状态查询失败";
                EngineState.ToolTip = ex.Message;
                if (row != null) { row.Report = null; ShowReport(row); }
                if (manual) Feedback(ex.Message);
            }
            finally
            {
                if (number == inspectionNumber) inspecting = false;
                if (!closed) UpdateButtons();
            }
        }

        private async void OnAppSelected(object sender, SelectionChangedEventArgs e)
        {
            if (e.Source != AppList) return;
            AccountPasswordBox.Clear();
            AccountNameBox.Clear();
            AccountClipLimit.IsChecked = false;
            ClearLivePrivacy();
            AccountFolderList.ItemsSource = null;
            Feedback("");
            ShowProfile();
            if (!busy) await InspectCurrent(true);
            if (AccountTab.IsSelected) await RefreshAccountFolders();
            if (LiveTab.IsSelected) await RefreshLivePrivacy();
        }

        private void ShowProfile()
        {
            var row = Current;
            bool hasAccountTab = row?.Profile.IsWeChat == true;
            if (!hasAccountTab && (AccountTab.IsSelected || LiveTab.IsSelected || ChatTab.IsSelected)) Sections.SelectedIndex = 0;
            AccountTab.Visibility = LiveTab.Visibility = ChatTab.Visibility = hasAccountTab ? Visibility.Visible : Visibility.Collapsed;
            ChatPanel.SetContext(service.StorageRoot, hasAccountTab ? row.Profile : null);
            EmptyPanel.Visibility = row == null ? Visibility.Visible : Visibility.Collapsed;
            DetailPanel.Visibility = row == null ? Visibility.Collapsed : Visibility.Visible;
            if (row == null) { UpdateButtons(); return; }
            rendering = true;
            try
            {
                var p = row.Profile;
                PermissionsTab.Header = p.IsWeChat ? "AppContainer 权限" : "权限设置";
                WeChatPolicyScope.Visibility = p.IsWeChat ? Visibility.Visible : Visibility.Collapsed;
                AppTitle.Text = p.Name;
                string profileKind = p.IsWeChat ? "微信专用配置" : p.IsTelegram ? "Telegram 专用配置" : "通用应用";
                AppIdentity.Text = string.Join("   ", new[] { profileKind,
                    string.IsNullOrEmpty(p.ProductVersion) ? null : "版本 " + p.ProductVersion,
                    string.IsNullOrEmpty(p.Publisher) ? null : p.Publisher }.Where(s => !string.IsNullOrEmpty(s)));
                AppPath.Text = p.ExecutablePath;
                TextInCheck.IsChecked = p.AllowTextIn;
                TextOutCheck.IsChecked = p.AllowTextOut;
                InternetCheck.IsChecked = p.AllowInternet;
                LoopbackCheck.IsChecked = !p.BlockLoopback;
                LanCheck.IsChecked = !p.BlockLan;
                ClipboardPolicy.Text = "Windows Job 限制直接读取及发布剪贴板文本。实测受管进程仍可清空原内容。";
                NetworkHint.Text = (p.IsTelegram || p.IsWeChat ? "聊天需要公网访问。" : "本机回环包括 localhost、127.0.0.1 与 ::1。")
                    + "当前支持离线、仅公网、公网加局域网。应用防火墙规则时 Windows 可能请求管理员确认。";
                LoopbackCheck.IsEnabled = !p.BlockLoopback;
                LoopbackCheck.ToolTip = "原生引擎保留系统回环隔离。";
                OutboundHint.Text = "将选中文件的副本放入传入目录。应用隔离启动后，可在文件选择器中使用此目录。";
                InboundHint.Text = "让应用把文件保存到交出目录，再选择文件和宿主保存位置。";
                TelegramPolicy.Visibility = p.IsTelegram ? Visibility.Visible : Visibility.Collapsed;
                OutgoingPath.Text = row.Outbox ?? "";
                IncomingPath.Text = row.Inbox ?? "";
                string launchDetails = "用户目录中的独立 EXE 默认只复制映像。如需同目录依赖，可显式授予安装目录只读权限。";
                if (p.IsWeChat) launchDetails = "隔离启动支持宿主专用账户和一次性 Windows 沙盒。运行中隐私与对话助手针对宿主上的微信。";
                if (p.IsTelegram) launchDetails = "Telegram 使用独立数据目录。7.3.3 的本地通信监听与 AppContainer 存在已知冲突。";
                ProfileDetails.Text = (string.IsNullOrEmpty(p.PackageFamilyName) ? "桌面可执行文件" : "商店应用包  " + p.PackageFamilyName)
                    + Environment.NewLine + launchDetails;
                ShowFolders(null);
                ShowReport(row);
            }
            catch (Exception ex) { Feedback(ex.Message); }
            finally { rendering = false; UpdateButtons(); }
        }

        private void ShowReport(AppRow row)
        {
            var report = row.Report;
            var last = PasteTargets.SelectedItem as TextTarget;
            PasteTargets.ItemsSource = report?.Targets;
            var targets = report?.Targets;
            if (targets != null && last != null)
                PasteTargets.SelectedItem = targets.FirstOrDefault(t => t.ProcessId == last.ProcessId &&
                    t.ProcessStartUtcTicks == last.ProcessStartUtcTicks && t.WindowHandle == last.WindowHandle);
            RuntimeState.Text = report?.State ?? "进程归属待核对";
            RuntimeDetails.Text = report == null ? "尚未取得当前进程状态。" :
                report.Detail + Environment.NewLine + "盒内 " + report.Boxed + "　盒外 " + report.Unboxed + "　未确认 " + report.Unknown;
            EngineDetails.Text = report?.EngineDetail ?? "请刷新引擎状态。";
            RuntimeState.ToolTip = RuntimeDetails.Text;
            UpdateButtons();
        }

        private void UpdateButtons()
        {
            if (LaunchButton == null) return;
            var row = Current;
            bool saved = row != null && !row.Dirty;
            bool ready = saved && row.Report != null && row.Report.EngineReady;
            BusyIndicator.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
            AppList.IsEnabled = AddExeButton.IsEnabled = AddTelegramButton.IsEnabled = RefreshButton.IsEnabled = !busy;
            AddWeChatButton.IsEnabled = !busy;
            Sections.IsEnabled = !busy;
            NativePolicyActions.Visibility = AccountTab.IsSelected || LiveTab.IsSelected || ChatTab.IsSelected ? Visibility.Collapsed : Visibility.Visible;
            UpdateAccountButtons();
            UpdateLiveButtons();
            SaveButton.IsEnabled = !busy && row != null && row.Dirty;
            ApplyButton.IsEnabled = !busy && ready;
            ApplyButton.ToolTip = !saved ? "先保存当前权限设置。" : !ready ? "请检查原生引擎状态。" : null;
            bool chooseMode = row?.Profile.IsWeChat == true;
            LaunchButton.Content = chooseMode ? "隔离启动…" : "隔离启动";
            LaunchButton.IsEnabled = !busy && (chooseMode || (ready && row.Report.Applied));
            LaunchButton.ToolTip = chooseMode ? "选择宿主专用账户或一次性 Windows 沙盒。" :
                !ready ? ApplyButton.ToolTip : row.Report.Applied ? null : "先应用当前版本的权限。";
            bool hasFolder = FolderList.SelectedItem != null;
            FolderModeButton.IsEnabled = RemoveFolderButton.IsEnabled = hasFolder;
            StageFileButton.IsEnabled = !busy && row != null;
            ExportFileButton.IsEnabled = !busy && row?.Inbox != null;
            PasteButton.IsEnabled = !busy && ready && row.Profile.AllowTextIn && PasteTargets.SelectedItem != null;
            StageTextButton.IsEnabled = !busy && saved && row.Profile.AllowTextIn;
            CopyTextButton.IsEnabled = !busy && saved && row.Inbox != null && row.Profile.AllowTextOut;
            if (row != null)
                DirtyState.Text = row.Dirty ? "有未保存的配置" : (row.Report == null ? "配置已保存" : "已保存　" + row.CheckedAt.ToString("HH:mm:ss") + " 核对");
        }

        private void SetDirty()
        {
            if (Current == null || rendering) return;
            Current.Dirty = true;
            Feedback("");
            UpdateButtons();
        }

        private void OnPolicyEdited(object sender, RoutedEventArgs e)
        {
            if (Current == null || rendering) return;
            var p = Current.Profile;
            p.AllowTextIn = TextInCheck.IsChecked == true;
            p.AllowTextOut = TextOutCheck.IsChecked == true;
            p.AllowInternet = InternetCheck.IsChecked == true;
            p.BlockLoopback = LoopbackCheck.IsChecked != true;
            p.BlockLan = LanCheck.IsChecked != true;
            SetDirty();
        }

        private void ShowFolders(FolderRule selected)
        {
            var rows = Current.Profile.Folders.Select(f => new FolderRow { Rule = f }).ToList();
            FolderList.ItemsSource = rows;
            FolderList.SelectedItem = rows.FirstOrDefault(f => f.Rule == selected);
            FolderSummary.Text = rows.Count == 0 ? "未授权目录" : rows.Count + " 个授权目录";
        }

        private void OnFolderSelected(object sender, SelectionChangedEventArgs e) => UpdateButtons();
        private void OnTargetSelected(object sender, SelectionChangedEventArgs e) => UpdateButtons();

        private void OnAddFolder(object sender, RoutedEventArgs e)
        {
            var p = Current?.Profile;
            if (p == null) return;
            using (var picker = new Forms.FolderBrowserDialog { Description = "选择要授权的宿主目录", ShowNewFolderButton = false })
            {
                if (picker.ShowDialog(new WindowOwner(this)) != Forms.DialogResult.OK) return;
                string path = picker.SelectedPath;
                var existing = p.Folders.FirstOrDefault(f => string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase));
                if (existing != null) { ShowFolders(existing); Feedback("该目录已在列表中。"); return; }
                var added = new FolderRule { Path = path, Writable = false };
                p.Folders.Add(added);
                ShowFolders(added);
                SetDirty();
            }
        }

        private void OnChangeFolder(object sender, RoutedEventArgs e)
        {
            if (!(FolderList.SelectedItem is FolderRow item)) return;
            item.Rule.Writable = !item.Rule.Writable;
            ShowFolders(item.Rule);
            SetDirty();
        }

        private void OnRemoveFolder(object sender, RoutedEventArgs e)
        {
            if (!(FolderList.SelectedItem is FolderRow item)) return;
            Current.Profile.Folders.Remove(item.Rule);
            ShowFolders(null);
            SetDirty();
        }

        private async Task SelectImported(AppProfile profile)
        {
            var row = apps.FirstOrDefault(a => a.Profile.Id == profile.Id);
            if (row == null) { row = new AppRow { Profile = profile }; apps.Add(row); }
            else if (!row.Dirty) row.Profile = profile;
            AppList.SelectedItem = row;
            ShowProfile();
            await InspectCurrent(true);
            Feedback("已登记 " + profile.Name + "。");
        }

        private async void OnAddExe(object sender, RoutedEventArgs e)
        {
            var picker = new OpenFileDialog { Title = "选择应用", Filter = "Windows 程序 (*.exe)|*.exe", CheckFileExists = true };
            if (picker.ShowDialog(this) != true) return;
            await Work(async () => await SelectImported(await Call(() => service.AddExecutable(picker.FileName))));
        }

        private async void OnImportTelegram(object sender, RoutedEventArgs e)
        {
            await Work(async () => await SelectImported(await Call(service.ImportTelegram)));
        }

        private async void OnImportWeChat(object sender, RoutedEventArgs e)
        {
            await Work(async () => await SelectImported(await Call(service.ImportWeChat)));
        }

        private async void OnSave(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row == null) return;
            await Work(async () =>
            {
                row.Profile = await Call(() => service.Save(row.Profile));
                row.Dirty = false;
                ShowProfile();
                await InspectCurrent(true);
                Feedback("配置已保存。可在引擎就绪时应用权限。");
            });
        }

        private async void OnDiscard(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row == null) return;
            if (row.Dirty && MessageBox.Show(this, "重新读取将放弃此应用未保存的权限修改。", "重新读取配置？",
                    MessageBoxButton.OKCancel, MessageBoxImage.Question, MessageBoxResult.Cancel) != MessageBoxResult.OK) return;
            await Work(async () =>
            {
                row.Profile = await Call(() => service.Profiles.First(p => p.Id == row.Profile.Id));
                row.Dirty = false;
                ShowProfile();
                await InspectCurrent(true);
                Feedback("已重新读取该应用的配置。");
            });
        }

        private async void OnApply(object sender, RoutedEventArgs e) => await RunEngineCommand(service.Apply);
        private async void OnRevoke(object sender, RoutedEventArgs e) => await RunEngineCommand(service.Revoke);
        private async void OnShortcut(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row == null) return;
            var choose = new SaveFileDialog { Title = "保存隔离启动快捷方式", Filter = "Windows 快捷方式 (*.lnk)|*.lnk",
                DefaultExt = ".lnk", FileName = Path.GetFileNameWithoutExtension(row.Profile.ExecutablePath) + " - AppShield.lnk",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), OverwritePrompt = false };
            if (choose.ShowDialog(this) != true) return;
            bool overwrite = File.Exists(choose.FileName);
            if (overwrite && MessageBox.Show(this, "覆盖已有快捷方式？" + Environment.NewLine + choose.FileName,
                "确认覆盖", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
            await Work(async () => {
                await Call(() => { service.CreateShortcut(row.Profile.Id, choose.FileName, overwrite); return true; });
                Feedback(row.Profile.IsWeChat ? "已创建快捷方式，双击后可选择微信启动方式。" : "已创建快捷方式，双击将按当前已应用权限启动。");
            });
        }
        private async void OnLaunch(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row?.Profile.IsWeChat != true) { await RunEngineCommand(service.Launch); return; }
            await Work(async () =>
            {
                var saved = await Call(() => service.Profiles.First(p => p.Id == row.Profile.Id));
                if (WeChatLaunchDialog.ShowLaunch(service, saved, this, out var detail) == true)
                {
                    await InspectCurrent(true);
                    Feedback(detail);
                }
            });
        }

        private async Task RunEngineCommand(Func<AppProfile, string> command)
        {
            var row = Current;
            if (row == null || row.Dirty) return;
            await Work(async () =>
            {
                string result;
                try { result = await Call(() => command(row.Profile)); }
                finally { await InspectCurrent(true); }
                Feedback(result);
            });
        }

        private async void OnStageFile(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row == null) return;
            var picker = new OpenFileDialog { Title = "选择传给 " + row.Profile.Name + " 的文件", CheckFileExists = true };
            if (picker.ShowDialog(this) != true) return;
            await Work(async () =>
            {
                var path = await Call(() => service.StageFile(row.Profile.Id, picker.FileName));
                Feedback("已放入传入目录：" + Path.GetFileName(path));
            });
        }

        private async void OnExportFile(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row == null) return;
            var source = new OpenFileDialog { Title = "选择交出目录中的文件", InitialDirectory = IncomingPath.Text, CheckFileExists = true };
            if (source.ShowDialog(this) != true) return;
            var destination = new SaveFileDialog { Title = "选择宿主保存位置", FileName = Path.GetFileName(source.FileName), OverwritePrompt = false };
            if (destination.ShowDialog(this) != true) return;
            bool overwrite = File.Exists(destination.FileName);
            if (overwrite && MessageBox.Show(this, "覆盖此文件？" + Environment.NewLine + destination.FileName,
                    "确认覆盖", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
            await Work(async () =>
            {
                await Call(() => { service.ExportFile(row.Profile.Id, source.FileName, destination.FileName, overwrite); return true; });
                Feedback("已导出文件：" + Path.GetFileName(destination.FileName));
            });
        }

        private async void OnPaste(object sender, RoutedEventArgs e)
        {
            var row = Current;
            var target = PasteTargets.SelectedItem as TextTarget;
            if (row == null || row.Dirty || !row.Profile.AllowTextIn || target == null) return;
            await Work(async () =>
            {
                var text = ReadClipboard();
                await Call(() => { service.PasteText(row.Profile.Id, target, text); return true; });
                Feedback("纯文本已交付选中的窗口。");
            });
        }

        private async void OnStageText(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row == null || row.Dirty || !row.Profile.AllowTextIn) return;
            await Work(async () =>
            {
                var text = ReadClipboard();
                var path = await Call(() => service.StageText(row.Profile.Id, text));
                Feedback("文本副本已放入传入目录：" + Path.GetFileName(path));
            });
        }

        private static string ReadClipboard()
        {
            var text = Clipboard.GetText(TextDataFormat.UnicodeText);
            if (string.IsNullOrEmpty(text)) throw new InvalidOperationException("主剪贴板中没有可交付的纯文本。");
            return text;
        }

        private async void OnCopyText(object sender, RoutedEventArgs e)
        {
            var row = Current;
            if (row == null || row.Dirty || !row.Profile.AllowTextOut) return;
            var picker = new OpenFileDialog { Title = "选择要复制到宿主剪贴板的 UTF-8 文件", InitialDirectory = IncomingPath.Text,
                Filter = "纯文本 (*.txt)|*.txt", CheckFileExists = true };
            if (picker.ShowDialog(this) != true) return;
            await Work(async () =>
            {
                var text = await Call(() => service.ReadIncomingText(row.Profile.Id, picker.FileName));
                Clipboard.SetText(text, TextDataFormat.UnicodeText);
                Feedback("所选文件的纯文本已复制到宿主剪贴板。");
            });
        }
    }
}
