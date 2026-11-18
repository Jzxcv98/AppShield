// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using AppShield;
using AppShield.Model;
using AppShield.UI;

internal static class WeChatLaunchDialogChecks
{
    private static void WaitUntil(Func<bool> ready)
    {
        var elapsed = Stopwatch.StartNew();
        while (!ready())
        {
            if (elapsed.Elapsed.TotalSeconds > 12) throw new TimeoutException("The launch UI did not settle.");
            var frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false));
            Dispatcher.PushFrame(frame);
            Thread.Sleep(20);
        }
    }

    internal static void Run(string directory)
    {
        var previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
        MainWindow window = null;
        try
        {
            var service = new AppService(Path.Combine(directory, "launch-ui-state"));
            var generic = service.AddExecutable(typeof(WeChatLaunchDialogChecks).Assembly.Location);
            // This fabricated import exercises UI routing only. Its unsigned image cannot pass
            // either production launch path, and this check never presses the final Start button.
            new ProfileStore(service.StorageRoot).Change(items => {
                items.Add(new AppProfile { Id = Guid.NewGuid(), Revision = 1, IsWeChat = true, Name = "Synthetic WeChat",
                    ExecutablePath = generic.ExecutablePath, ImageHash = generic.ImageHash, ImageLength = generic.ImageLength,
                    ImageWriteUtcTicks = generic.ImageWriteUtcTicks });
                return true;
            });
            window = new MainWindow(service) { WindowStartupLocation = WindowStartupLocation.Manual, Left = -10000,
                Top = -10000, ShowInTaskbar = false, ShowActivated = false };
            var list = (ListBox)window.FindName("AppList");
            var launch = (Button)window.FindName("LaunchButton");
            window.Show();
            WaitUntil(() => list.Items.Count == 2 && list.IsEnabled);
            DesktopChecks.Assert(!launch.IsEnabled, "generic app still requires an applied AppContainer policy");
            list.SelectedIndex = 1;
            WaitUntil(() => launch.IsEnabled);
            DesktopChecks.Assert(Equals(launch.Content, "隔离启动…"), "WeChat without an applied policy offers launch-mode selection");

            bool exercised = false;
            Exception dialogError = null;
            var poll = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(30) };
            var deadline = Stopwatch.StartNew();
            poll.Tick += (s,e) =>
            {
                var dialog = window.OwnedWindows.OfType<WeChatLaunchDialog>().SingleOrDefault();
                if (dialog == null) return;
                if (!((UIElement)dialog.FindName("Choices")).IsEnabled && deadline.Elapsed.TotalSeconds < 10) return;
                poll.Stop();
                try
                {
                    var accountMode = (RadioButton)dialog.FindName("AccountMode");
                    var sandboxMode = (RadioButton)dialog.FindName("SandboxMode");
                    var password = (PasswordBox)dialog.FindName("Password");
                    var start = (Button)dialog.FindName("StartButton");
                    accountMode.IsChecked = true;
                    DesktopChecks.Assert(!start.IsEnabled, "main launch button opened the mode picker and account launch waits for credentials");
                    ((TextBox)dialog.FindName("Account")).Text = "synthetic-user";
                    password.Password = "synthetic-only";
                    DesktopChecks.Assert(start.IsEnabled, "dedicated account fields enable the intended action");
                    sandboxMode.IsChecked = true;
                    using (var secret = password.SecurePassword)
                        DesktopChecks.Assert(start.IsEnabled && secret.Length == 0 &&
                            ((CheckBox)dialog.FindName("AllowNetwork")).IsChecked == false,
                            "switching to Sandbox clears credentials, requires no account, and defaults to offline");
                }
                catch (Exception ex) { dialogError = ex; }
                finally { exercised = true; dialog.DialogResult = false; }
            };
            poll.Start();
            try
            {
                launch.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                WaitUntil(() => exercised && list.IsEnabled);
                if (dialogError != null) throw dialogError;
            }
            finally { poll.Stop(); }
            list.SelectedIndex = 0;
            WaitUntil(() => !launch.IsEnabled);
        }
        finally
        {
            window?.Close();
            SynchronizationContext.SetSynchronizationContext(previous);
        }
    }
}
