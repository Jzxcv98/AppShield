# 微信未登录验收

## 宿主桌面与运行时目录权限

AppShield 的“宿主文件保护”页通过单独的本机标准账户启动已登记的腾讯签名客户端。使用日常 Windows 账户打开的微信，需要先退出再从此页换身份启动。使用同一专用账户的进程会一直受该 SID 的 NTFS 权限约束，即使关闭管理器，已经应用的规则仍然有效。要恢复访问，在该页选中记录并撤销保护。

可以选择自己拥有的本地 NTFS 数据目录。AppShield 在目录上写入针对专用账户的拒绝规则，核对已有子项是否按预期继承，再按 NTFS 文件 ID 记录原目录以支持撤销。重解析点、硬链接及子项权限冲突可能使整目录校验失败。请查看列表里的核实状态。规则限制随后打开文件读取内容，不会收回应用已经打开的句柄、内存中的数据或先前复制的文件。此模式共享当前桌面、剪贴板和网络；其他目录按原有 Windows 权限处理。

开发验收在普通交互式 64 位 Windows PowerShell 5.1 中执行 `.\Test-WeChatHostAccount.ps1`（从本目录运行）。测试需要本机安装官方微信、构建好的 AppShield 和一次用于创建、回收临时标准账户的 UAC 授权；会修改本轮合成目录的权限。请先退出宿主上已经打开的微信。结束时回收本轮进程、权限、账户和用户配置文件。

## 已登录实例的联网对照

AppShield 在“运行中隐私”页只采样已核实主程序的账户、会话、进程数和已建立 TCP 数。规则通过 Windows 防火墙的程序与本地用户条件共同匹配。选中当前账户或已登记的专用账户后，可在微信运行期间阻止新外部出站连接，并单独撤销 AppShield 创建的规则。辅助 EXE、已有连接、本机回环及其他防火墙策略需要分别判断。

独立验收入口为 [Test-AccountNetwork.ps1](../../tests/wechat/Test-AccountNetwork.ps1)。它用两个合成映像及普通用户、LocalService 两个身份对同个公网端点作 TCP 握手对照；结束时撤销临时规则并回收测试材料。真实微信上的验收仅核对规则生效和撤销，以及进程和连接总数。[实机结果](../../docs/native-engine.md#已登录宿主微信的联网控制)

## 一次性 Windows 沙盒

在一次性来宾 Windows 中正常安装腾讯签名的客户端，核对主程序和扫码提示。适用 Windows 11 x64，使用系统的 Windows Sandbox 可选功能。宿主有重启待完成时，可先准备配置，并在重启后执行。[微软安装说明](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install)

### 准备可双击的配置

将 `$installer` 设为从官方渠道取得的 x64 安装包。脚本验证腾讯签名及独立取得的 SHA-256，默认摘要对应 4.2.0.53。后续版本应显式传入与该安装器相符的微软商店或 WinGet 清单摘要。[4.2.0.53 WinGet 清单](https://github.com/microsoft/winget-pkgs/blob/master/manifests/t/Tencent/WeChat/Universal/4.2.0.53/Tencent.WeChat.Universal.installer.yaml)

```powershell
.\tools\wechat\Test-WeChatWindowsSandbox.ps1 -Installer $installer -PrepareOnly -OutputDirectory .\.local\wechat-sandbox-ready
```

脚本在输出目录下新建本轮的子目录，打印两份配置的路径。

- `WeChat.wsb` 关闭网络，适合检查来宾安装、签名和启动。断网环境可能无法获取登录二维码，也可能缺少签名验证所需的证书链。
- `WeChat-NetworkEnabled.wsb` 启用 Windows Sandbox 的默认虚拟交换机，适合验证联网后的未登录界面。来宾可能可以访问局域网，两种配置均独立于 AppShield 原生引擎的防火墙规则。

双击所选配置即可开启沙盒。两份配置均关闭剪贴板、打印机、音视频输入和虚拟 GPU，仅只读共享同一份安装器和验收脚本。配置采用绝对路径；请将生成目录保留在原处。客体测试结束后，桌面和显示结果的命令窗口保持打开，关闭沙盒会清除来宾中的微信、结果和数据。宿主准备目录可以继续复用。[微软配置说明](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)

### 自动验收

```powershell
.\tools\wechat\Test-WeChatWindowsSandbox.ps1 -SelfTest
.\tools\wechat\Test-WeChatWindowsSandbox.ps1 -Installer $installer
.\tools\wechat\Test-WeChatWindowsSandbox.ps1 -Installer $installer -AllowNetwork
```

要验证宿主启动方式使用的剪贴板 Job，可先构建桌面检查，再运行 `.\tools\wechat\Test-WeChatWindowsSandbox.ps1 -Installer $installer -AllowNetwork -ClipboardJob`。验收在新来宾中运行普通扫码页对照，并在来宾内新建临时标准 Windows 账户，挂起启动同一份签名微信，绑定剪贴板限制后恢复执行。通过时，签名客户端的根进程及至少一个后代属于同一 Job，同一可见窗口持续三秒显示扫码提示。关闭来宾即回收其临时账户和数据。[剪贴板数据对照](../restricted/README.md#宿主微信的剪贴板限制)

有官方 `wsb.exe` 时，宿主启动本轮沙盒，用随机运行标识核对来宾结果，然后关闭本轮实例并回收临时材料。已有会话时停止本次自动测试。没有 CLI 时，启动器打开 `.wsb` 并给出配置路径；查看来宾控制台的最终结论。CLI 不提供来宾标准输出，自动验收用进程退出码传回少量状态，无须开放宿主可写文件夹。[微软命令行接口](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)

来宾先读取安装包并校验摘要，再尝试在共享目录新建本轮专属的空标记。Windows 明确拒绝写入后，才继续安装并核对 `Weixin.exe` 的签名、安装路径和产品信息。只有同一进程的同一可见窗口持续三秒显示已知的扫码提示，结果才为 `PASS_SCAN_PROMPT`。界面检查只匹配固定文字，不点击登录或采集二维码。来宾将文件权限对照和界面检查结果保存在 `%LOCALAPPDATA%\AppShieldWeChatTest\result.json`，宿主通过 CLI 核对回执和共享目录。本次联网实测已通过；账号认证、聊天和附件收发仍待单独验证。[实机结果](../../docs/native-engine.md#微信未登录验收)

## 宿主 Windows 专用账户验收

在非提升的 64 位 Windows PowerShell 5.1 中构建 AppShield 后，先退出宿主中已在运行的微信，再执行以下命令。测试会请求 UAC，用于创建和回收本轮临时的非管理员 Windows 账户。微信由普通用户的 AppShield 启动，显示在原 Windows 会话中。测试期间无需扫码。

```powershell
.\tools\Build-AppShield.ps1
.\tools\wechat\Test-WeChatHostAccount.ps1
```

验收覆盖三组观察：

- Windows 核验微信主进程的实际映像、账户 SID 和桌面会话；同一可见窗口持续三秒出现已知的扫码提示。
- 以微信实际主令牌及合成文件的安全描述符调用 Windows Authz，分别判断文件内容是否可读。保护开始前允许、应用后拒绝、撤销后恢复。
- 同一专用账户中的独立探针持续运行，实际重新打开上述文件，验证三次访问结果以及共享目录可写；宿主复核原件和 ACL。测试过程中没有要求微信读取文件或动用真实聊天数据。

试验结束后停用并回收本轮专用账户、该 SID 的进程和 Windows 用户配置，随后清除本轮合成目录。若 Windows 报告清理失败，使用输出中本轮的 GUID 执行 `Test-WeChatHostAccount.ps1 -Recover <GUID>`。
