# AppShield

AppShield 是用于 Windows 11 x64 的免费开源桌面权限管理器。通用隔离启动为每个应用配置独立的 Windows AppContainer 身份、目录和网络权限。微信还支持专用 Windows 标准账户，可在当前桌面启动并动态限制指定目录的读取。产品运行无需 Sandboxie、订阅或 Supporter Certificate。

## 运行桌面程序

需要 .NET Framework 4.8.1。源码构建需要 Visual Studio 的 MSBuild 和 4.8.1 targeting pack。

```powershell
.\tools\Build-AppShield.ps1
.\build\AppShield\AppShield.exe
```

选择“添加 EXE”，或导入已安装的微信、Telegram。通用 AppContainer 模式需要先保存并应用权限；启动前会再次核对映像、ACL、防火墙、令牌和 Job。运行详情中可以撤销已应用权限。

**微信 4.2.0.53 的“隔离启动…”会打开环境选择窗。** 选“宿主桌面 · 专用 Windows 账户”可使用该账户自己的持久配置和已登记的 NTFS 文件保护。选“一次性 Windows 沙盒”可与已打开的宿主微信并行运行。首次使用时选择腾讯官方 x64 安装包；AppShield 核对版本对应的 SHA-256 和腾讯签名，之后可复用缓存。沙盒默认断网，要使用在线扫码页请勾选联网。来宾使用默认虚拟交换机，可能访问局域网，默认关闭宿主剪贴板、音视频输入和打印机共享；关闭沙盒会清除来宾数据。

宿主对话助手按 Windows 账户及窗口验证身份。如果要摘录当前账户已有的聊天，可继续使用手动启动的微信，或退出后在“运行中隐私”选择当前账户的剪贴板受限启动。专用账户的聊天窗口及独立沙盒中的微信都不属于当前账户的摘录范围。

“收发中转”向目标应用提供选中文件的副本，从该应用的接收目录导出文件。采用受支持 Windows 编辑控件的目标可以直接接收一次纯文本，其他目标可以使用独立 UTF-8 文件。

### 对话助手

导入微信，打开“对话助手”，即可在本机提取当前单聊。选择“提取当前对话”，正常切回微信并打开需要的聊天即可。核对按发言方排好的预览后，可以复制到自己使用的 GPT，也可以另存为 UTF-8 文本；整个摘录流程无需 API 密钥。

想回复之前的话题时，也可从本机记录摘出相关段落。持续记录与 GPT 自动备稿单独启用，实际发送由用户在微信中完成。[摘录、旧对话和可选 API 设置](docs/conversation-assistant.md)

### 在当前 Windows 桌面保护文件

导入微信后，打开“宿主文件保护”。使用一个专门给微信使用的本机标准 Windows 账户，输入其账户名和 Windows 密码。没有专用账户时，可在 Windows“设置 → 账户 → 其他用户”中创建标准账户。选中要拒绝读取的本地 NTFS 目录，然后用页面内的专用账户启动按钮打开微信。新版微信使用该账户自己的用户配置，AppShield 不保存密码。

微信运行期间可以添加或撤销目录规则。Windows 对该账户下所有程序随后打开的文件执行目录权限检查。原先已打开的句柄、已读内容、桌面剪贴板和网络另有各自的边界。其他目录继续按原有 Windows 权限访问。已用日常 Windows 账户打开的微信，需要退出一次，才能换用专用账户。[使用与验收](tools/wechat/README.md)

### 查看和控制正在运行的微信

导入微信后打开“运行中隐私”。刷新可查看已核验的微信主程序进程数，以及采样时由这些进程持有的已建立 TCP 连接数。页面区分当前账户、其他账户及其他桌面会话；采样不保存远端地址。

选择 Windows 账户，点击“阻止新出站连接”即可应用该账户与微信主程序路径共同限定的防火墙规则；点击“撤销阻止”恢复。应用和撤销可能需要 Windows UAC。规则覆盖这个程序映像的新外部出站流量；单独的辅助程序、本机回环和已有连接需要分别判断。已登记的规则会跨 AppShield 重启保留。

若要限制微信读取和发布系统剪贴板，请先自行退出微信，在“运行中隐私”页选择当前账户的剪贴板受限启动；也可以在“宿主文件保护”页勾选剪贴板选项，然后用专用账户启动。限制在微信执行前应用，随进程树生效到退出，关闭 AppShield 后继续有效。退出微信并按通常方式启动即可恢复默认行为。Windows Job 仍允许进程清空剪贴板。[剪贴板实测](docs/native-engine.md#微信剪贴板受限启动)

需要双击使用时，可在“运行详情”中创建隔离启动快捷方式。微信快捷方式同样显示启动环境选择窗。其他程序的受管快捷方式按已保存的 AppContainer 策略启动。

## 已知兼容性

- 普通用户文件的可见性取决于 Windows ACL。AppContainer 可以读取系统本来就向应用包开放的资源。应用的工作目录和账号数据按身份持久保存。
- Windows Job 的剪贴板限制能阻止受测进程取得宿主文本和发布新文本。在专用窗口站中，受限进程仍能清空原内容。[剪贴板实测](tools/restricted/)
- 商店版 Telegram Desktop 7.3.3.0 已能登记并应用独立权限。受管副本的本地 IPC 监听失败，不能在当前原生后端登录聊天。[引擎实现与测试](docs/native-engine.md)
- 微信 4.2.0.53 x64 使用“宿主文件保护”已在当前桌面通过未登录扫码页及运行时文件拒读、撤销验收。独立 Windows 沙盒也能显示扫码页。通用 AppContainer 启动仍会提前退出。[实机对照](docs/native-engine.md#微信未登录验收)

## 自研文件系统驱动

实验性文件过滤器使用本仓库中的 C 源码和 Microsoft Filter Manager。桌面程序的默认文件控制使用 AppContainer 和 ACL。驱动分开构建，供独立测试 Windows 验收。

```powershell
.\tools\Build-AppShieldDriver.ps1
.\build\driver\FilterLab.exe policy-test
```

脚本使用固定版本与摘要的 Microsoft WDK 构建未签名 x64 驱动。内核动态执行、正式签名和分发尚待完成。[驱动范围与实验步骤](driver/AppShieldFilter/)

## 开发验证

```powershell
.\tools\Build-AppShield.ps1 -Test
.\tools\Build-AppShield.ps1 -LiveTest
.\tools\Build-AppShield.ps1 -PublicNetworkTest
python tools/check_public_tree.py
```

`-LiveTest` 需要普通交互式 Windows 会话、MSVC x64 和 Windows SDK。它使用随机测试身份及合成文件，系统会为该 SID 的测试防火墙规则请求授权。完成后回收测试资源。[贡献指南](CONTRIBUTING.md) · [GPL-3.0-only 许可证](LICENSE)
