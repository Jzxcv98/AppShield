# Telegram Desktop 启动检查

在交互式 Windows 桌面的普通 PowerShell 中运行。需要 Visual Studio C++ x64 工具和 Windows SDK。先用相同启动器验证合成 GUI 和提前退出的进程，再传入已确认的 Telegram Desktop 可执行文件。

微软商店版可从包清单取得当前安装的可执行文件。下面的查询只读软件元数据。

```powershell
$pkg = @(Get-AppxPackage -Name '*TelegramDesktop*')
if ($pkg.Count -ne 1) { throw 'Select the intended Telegram Desktop package first.' }
$manifest = Get-AppxPackageManifest -Package $pkg[0].PackageFullName
$entry = @($manifest.Package.Applications.Application | Where-Object {
    [IO.Path]::GetFileName([string]$_.Executable) -ieq 'Telegram.exe'
})
if ($entry.Count -ne 1) { throw 'Expected one Telegram Desktop application entry.' }
$telegramExe = Join-Path $pkg[0].InstallLocation $entry[0].Executable
```

```powershell
.\tools\telegram\Test-TelegramStartup.ps1 -SelfTest
.\tools\telegram\Test-TelegramStartup.ps1 -Executable $telegramExe -InstalledImage
.\tools\telegram\Test-TelegramStartup.ps1 -Executable $telegramExe
.\tools\telegram\Test-TelegramStartup.ps1 -Executable $telegramExe -InternetClient
```

`$telegramExe` 是本机安装文件的绝对路径。`-InstalledImage` 用于 WindowsApps 中的商店包，保留同目录的库和资源。其他安装形式可省略该参数，将选定的单个可执行文件复制到临时 profile 中。复制模式要求该文件能够单独运行。

每轮启动使用本次专用的空工作目录、`-workdir` 和 `-noupdate`，以及最小环境变量集。默认 AppContainer 的 capability 列表为空。`-InternetClient` 仅授予 Windows 的公网客户端 capability。启动器在目标恢复执行前核对进程映像、AppContainer SID、实际 token 的 capability 列表，以及只包含本轮进程的 Windows Job。也可在合成对照中加 `-InternetClient`。

需要对照普通宿主行为时，请使用可丢弃的 Windows 测试账户或虚拟机单独验证。Telegram 副本可能将该账户的协议处理器注册到临时可执行文件。

探针每半秒采样。十五秒结束时，根进程仍存活、同一可见非工具顶层窗口出现在最后三次采样中、且新工作目录出现普通 `tdata` 目录，才算通过。窗口必须没有 owner、面积大于零且不属于标准系统对话框类。若客户端把界面交给其他进程，则记录为未确认。

完成采样后关闭本轮 Job，仅在全新工作目录的固定日志名中匹配启动阶段，再回收临时 AppContainer profile。`other_instance_reply` 表示收到另一实例的回应，`ipc_listen_failed` 表示本地监听初始化失败，`qt_app_init` 表示进入 Qt 应用初始化。若日志报告不同的工作目录，启动检查失败。日志不可用时，`logged_workdir` 单列为 `unavailable`。输出仅含阶段、计数、布尔值和本轮临时定位标识，便于清理失败时定向重试。[Telegram 7.3.3 单实例逻辑](https://github.com/telegramdesktop/tdesktop/blob/v7.3.3/Telegram/SourceFiles/core/sandbox.cpp) · [日志处理](https://github.com/telegramdesktop/tdesktop/blob/v7.3.3/Telegram/SourceFiles/logs.cpp)

从 `pwsh -File` 运行时，完成相应观察且成功清理返回 0，启动失败、观察未确认或清理失败返回非零。客户端自身的数字退出码另行输出。此检查覆盖空白工作目录下的启动表现。账号登录、实际网络连通性和剪贴板权限需要另外验证。
