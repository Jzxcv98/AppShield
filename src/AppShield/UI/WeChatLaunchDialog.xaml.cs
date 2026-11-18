// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using AppShield.Model;
using Microsoft.Win32;

namespace AppShield.UI
{
    public partial class WeChatLaunchDialog : Window
    {
        private readonly AppService service;
        private readonly AppProfile profile;
        private bool checking = true, launching, cachedInstaller;
        private string installerPath, result;

        internal WeChatLaunchDialog(AppService service, AppProfile profile)
        {
            this.service = service ?? throw new ArgumentNullException(nameof(service));
            this.profile = profile ?? throw new ArgumentNullException(nameof(profile));
            if (!profile.IsWeChat) throw new ArgumentException("请选择已登记的微信。", nameof(profile));
            InitializeComponent();
            MaxHeight = SystemParameters.WorkArea.Height;
            MaxWidth = SystemParameters.WorkArea.Width;
            Loaded += OnLoaded;
            Deactivated += (s,e) => Password.Clear();
            Closing += (s,e) => { if (launching) e.Cancel = true; };
            Closed += (s,e) => Password.Clear();
            UpdateMode();
        }

        public static bool? ShowLaunch(AppService service, AppProfile profile, Window owner = null) =>
            ShowLaunch(service, profile, owner, out _);

        internal static bool? ShowLaunch(AppService service, AppProfile profile, Window owner, out string detail)
        {
            var dialog = new WeChatLaunchDialog(service, profile);
            if (owner != null)
            {
                dialog.Owner = owner;
                dialog.ShowInTaskbar = false;
                dialog.WindowStartupLocation = WindowStartupLocation.CenterOwner;
            }
            var accepted = dialog.ShowDialog();
            detail = dialog.result;
            return accepted;
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OnLoaded;
            HostNotice.Text = "正在核对宿主微信实例…";
            try
            {
                cachedInstaller = await Task.Run(() => service.HasWeChatSandboxInstaller(profile));
                var report = await Task.Run(() => service.InspectRunningWeChat(profile));
                if (!IsVisible) return;
                bool running = report.CurrentUserProcesses + report.OtherUserProcesses + report.OtherSessionProcesses + report.UnverifiedProcesses > 0;
                if (running)
                {
                    HostNotice.Text = "发现已有或归属待确认的宿主微信实例。保留它时可启动一次性沙盒；改用专用账户须先自行退出宿主微信。";
                    SandboxMode.IsChecked = true;
                }
                else HostNotice.Text = "请为这次启动选择账户或来宾环境。";
            }
            catch (Exception)
            {
                if (IsVisible) HostNotice.Text = "宿主实例状态待核实。使用专用账户时，启动器会再次核对。";
            }
            finally { checking = false; if (IsVisible) UpdateMode(); }
        }

        private void OnModeChanged(object sender, RoutedEventArgs e)
        {
            if (StartButton == null) return;
            if (SandboxMode.IsChecked == true) Password.Clear();
            Feedback.Text = "";
            UpdateMode();
        }

        private void OnAccountEdited(object sender, RoutedEventArgs e)
        {
            if (StartButton != null) UpdateMode();
        }

        private void UpdateMode()
        {
            bool sandbox = SandboxMode.IsChecked == true;
            Credentials.Visibility = sandbox ? Visibility.Collapsed : Visibility.Visible;
            SandboxOptions.Visibility = sandbox ? Visibility.Visible : Visibility.Collapsed;
            InstallerInfo.Text = installerPath != null ? Path.GetFileName(installerPath) : cachedInstaller
                ? "已有此版本安装包，启动前将复核签名和摘要。" : "首次使用时选择官方安装包，之后复用。";
            InstallerInfo.ToolTip = installerPath;
            StartButton.Content = sandbox ? "启动 Windows 沙盒" : "以专用账户启动微信";
            Choices.IsEnabled = !checking && !launching;
            CancelButton.IsEnabled = !launching;
            using (var secret = Password.SecurePassword)
                StartButton.IsEnabled = !checking && !launching &&
                    (sandbox || (!string.IsNullOrWhiteSpace(Account.Text) && secret.Length != 0));
        }

        private string PickInstaller()
        {
            var picker = new OpenFileDialog { Title = "选择官方微信 Windows 安装包", Filter = "安装程序 (*.exe)|*.exe",
                CheckFileExists = true, Multiselect = false };
            return picker.ShowDialog(this) == true ? picker.FileName : null;
        }

        private void OnPick(object sender, RoutedEventArgs e)
        {
            if (launching || SandboxMode.IsChecked != true) return;
            var path = PickInstaller();
            if (path != null) { installerPath = path; Feedback.Text = ""; UpdateMode(); }
        }

        private async void OnStart(object sender, RoutedEventArgs e)
        {
            if (checking || launching || !StartButton.IsEnabled) return;
            launching = true;
            UpdateMode();
            try
            {
                if (SandboxMode.IsChecked == true)
                {
                    bool network = AllowNetwork.IsChecked == true;
                    Feedback.Text = "正在核对沙盒安装材料…";
                    string path = installerPath;
                    if (path == null && !await Task.Run(() => service.HasWeChatSandboxInstaller(profile)))
                    {
                        path = PickInstaller();
                        if (path == null) { Feedback.Text = "请选择安装包后重试。"; return; }
                        installerPath = path;
                    }
                    if (path != null) await Task.Run(() => service.ImportWeChatSandboxInstaller(profile, path));
                    Feedback.Text = "正在启动 Windows 沙盒…";
                    result = await Task.Run(() => service.LaunchWeChatSandbox(profile, network));
                }
                else
                {
                    var account = Account.Text.Trim();
                    using (var secret = Password.SecurePassword)
                    {
                        Password.Clear();
                        Feedback.Text = "正在核对账户并启动微信…";
                        int pid = await Task.Run(() => service.LaunchWeChatAsAccount(profile, account, secret));
                        result = "微信专用账户启动器已运行，PID " + pid + "。";
                    }
                }
                launching = false;
                DialogResult = true;
            }
            catch (Exception ex)
            {
                Feedback.Text = ex.Message;
            }
            finally
            {
                launching = false;
                if (IsVisible) UpdateMode();
            }
        }
    }
}
