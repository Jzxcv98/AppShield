# 早期隔离引擎对照实验

下文保留 Sandboxie Plus 与 Windows AppContainer 的早期选型和第一次 Telegram 实测记录。当前桌面程序使用 AppShield 原生引擎，自有文件过滤驱动已独立编译。[当前实现及证据](native-engine.md)

AppShield 的目标是在同一个 Windows 11 桌面上按应用管理隐私权限。用户可从任意 EXE 开始登记应用，WeChat 和 Telegram 是首批兼容性目标。每个应用默认有独立的沙盒身份、持久配置和数据目录。只有宿主侧的用户操作可以向指定应用交付文本或文件。

## 从选择 EXE 到验证实际运行状态

1. 用户选择程序。对于普通桌面软件，保存可执行文件路径、签名状态和版本。对于商店软件，还应识别包身份及正常激活入口。引导程序、实际主进程和更新器可能是不同的文件。
2. 用户设置这个应用的权限。文件分为私有、只读、可读写和一次性交付副本。剪贴板分别处理宿主到应用、应用到宿主的单次传递。网络分别处理公网、本机回环和局域网。界面按所选引擎及版本标明每项能否执行。
3. 从 AppShield 启动后，核对承载实际窗口的进程及相关子进程属于哪个沙盒。如果新启动请求被转交给盒外的已运行实例，界面指出该实例未受保护。对希望直接双击启动的应用，单独验证强制入盒规则。同名程序匹配、包激活和更新后的新程序均会影响覆盖范围。[Sandboxie 强制启动语义](https://sandboxie-plus.github.io/sandboxie-docs/Content/ForceProcess/)

这些实验开展时，仓库仅包含临时探针。后续的正式桌面程序已实现持久配置和运行状态查询。

## 技术选择

早期优先评估了用户单独安装的 Sandboxie Plus，并用合成程序比较了原生 AppContainer。下表记录当时查到的接口和验证问题。目前的产品选择见[原生引擎记录](native-engine.md)。

| 能力 | 上游提供什么 | 选型还需要的证据 |
| --- | --- | --- |
| 启动及归属 | Sandboxie 的 `Start.exe /box:<name>` 指定沙盒，`/box:<name> /listpids` 列出当前会话中的成员。 | 以可信宿主发起启动，核对存活的目标进程。客户端可能只启动引导程序，后续进程和更新后的可执行文件需再次核对。一次成员匹配仅证明当时的归属。[命令行文档](https://sandboxie-plus.github.io/sandboxie-docs/Content/StartCommandLine/) |
| 私有文件和授权目录 | Privacy Mode 对多数非系统位置隐藏宿主内容。规则可以授予目录只读或直接访问。规则优先级及程序自身所在位置会影响最终效果。 | 对同一组临时文件测宿主可读、沙盒拒读、白名单可读，以及宿主原件是否真的被改写。两个应用的授权目录应分别验证。[隐私模式](https://sandboxie-plus.github.io/sandboxie-docs/PlusContent/privacy-mode/) · [文件访问规则](https://sandboxie-plus.github.io/sandboxie-docs/Content/ResourceAccessSettings/) |
| 主剪贴板和单次粘贴 | `OpenClipboard=n` 会限制被引擎接管的若干读写和清空操作。上游另介绍了每个沙盒的独立剪贴板，产品页面未列出适用版本、证书档位及宿主投递接口。 | 在专用桌面用合成文本检查后台读取，再观察显式投递能否准确送到一个目标。还需要验证另一个沙盒和下一次宿主复制。首选操作是宿主按钮。[剪贴板规则](https://sandboxie-plus.github.io/sandboxie-docs/Content/OpenClipboard/) · [Box Clipboard](https://sandboxie-plus.com/box-clipboard/) |
| 网络 | Sandboxie 通过全局 WFP 组件按沙盒执行网络规则，默认配置关闭 WFP。 | 在测试机启用后，对 IPv4 和 IPv6 回环、本地共享以及正常外网通信分别取证。单凭一个连接失败无法判断拦截是否生效，需先从宿主确认测试服务可达。[WFP 文档](https://sandboxie-plus.github.io/sandboxie-docs/PlusContent/WFPSupport/) |
| 原生 AppContainer | Windows 可用每个应用的 SID 和 capability 列表启动受限子进程，并用文件 ACL 授予所需访问。 | 先验证合成文件的读取，再测试客户端启动、子进程、持久化和更新。原生文件测试的结果只覆盖受测程序与文件。[微软启动接口](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) |

## 许可和分发

AppShield 的原创代码采用 GPL-3.0-only。Sandboxie 上游的核心、QSbieAPI 和 SandMan 各有许可条款。本阶段使用另外安装的发行版，发行包、驱动、上游 UI 和证书均由使用者从上游取得。若日后改变集成方式或随包分发，应按所选版本重新核对。[上游 v1.19.0 许可](https://github.com/sandboxie-plus/Sandboxie/blob/v1.19.0/LICENSE.Plus)

实现独立界面时，可先通过 `SbieIni.exe` 管理命名沙盒的规则，使用 `Start.exe` 启动，再用进程查询 API 核对归属。需要更紧密的集成时，可评估按 LGPL 条款使用独立的 QSbieAPI 库。若修改 GPL 核心文件并分发相应二进制，应保留适用许可和版权声明并提供对应源码。直接修改 SandMan 界面另受自定义条款约束，包括自行编译二进制公开分发时的名称、署名、完整源码和作者禁止非官方分发的权利。[配置接口](https://sandboxie-plus.github.io/sandboxie-docs/Content/SbieIniCommandLine/) · [运行和查询接口](https://sandboxie-plus.github.io/sandboxie-docs/Content/SBIEDLLAPI/) · [组件许可](https://github.com/sandboxie-plus/Sandboxie/blob/v1.19.0/LICENSE.Plus)

Privacy Mode 要求支持者证书。商业使用适用上游 Business Certificate 条款，其中包括限时、最多三台设备的商业评估例外。评估条款与具体功能的解锁条件需要分别核对。WFP 列在上游免费版功能中。选定部署版本时应核实其是否包含所需的剪贴板能力。[Privacy Mode](https://sandboxie-plus.github.io/sandboxie-docs/PlusContent/privacy-mode/) · [版本与功能对照](https://sandboxie-plus.com/sandboxie/featurecomparison/) · [许可原文](https://github.com/sandboxie-plus/Sandboxie/blob/v1.19.0/LICENSE.Plus)

## 当前观测

- 当时在 Windows 11 上查询 `SbieSvc` 与 `SbieDrv` 均返回 1060。标准安装目录缺少启动器和 API DLL，因此该轮只完成了宿主负对照。后续工程采用 Windows 原生隔离机制。
- 在 Windows 11 Pro 26H2（build 26300.9974）的普通宿主进程中，原生文件测试通过。两个合成文件从相同的仅用户可读写 ACL 开始，宿主在授权前后都能读到二者。子进程两次都验证了自己的 AppContainer SID：授权前两条读取均收到 `ERROR_ACCESS_DENIED`，仅向共享文件添加该 SID 的读取权后，子进程读到了共享标记，私有文件依然返回拒绝访问。探针随后成功删除临时 profile。[原生探针](../tools/native/Test-AppContainerFileAccess.ps1)
- 原生启动试验还发现两个前提。在本身已处于 AppContainer 中的托管进程里尝试嵌套启动，Windows 返回错误 87。在普通进程中仅派生 SID 而未创建 profile 时，同一测试返回错误 2。可复现脚本采用普通 Windows 终端，并通过 `CreateAppContainerProfile` 创建本轮专属 profile。[微软 AppContainer 启动说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- Windows Server CI 运行文件权限回归、合成测试并编译 Telegram 启动探针。实际桌面客户端的兼容性由交互式 Windows 11 实验记录。

### Telegram Desktop 7.3.3.0（Microsoft Store，x64）

在 Windows 11 Pro 26H2（build 26300.9974）上通过商店应用入口启动已安装的签名版本。启动前没有 Telegram 进程。启动后，窗口有响应，出现了会话列表专有的可见主菜单按钮，并观察到该进程有已建立的 TCP 连接。由此确认宿主恢复了现有登录界面。清单声明 `Windows.FullTrustApplication`，Windows 查询返回 `TokenIsAppContainer=0`。观察界面时只匹配预设控件，不采集窗口标题、账号标识或聊天内容。[该版本会话列表的主菜单控件](https://github.com/telegramdesktop/tdesktop/blob/v7.3.3/Telegram/SourceFiles/dialogs/dialogs_widget.cpp#L1598-L1614)

隔离检查使用每轮新建的空工作目录。原登录实例在试验期间继续运行。合成正对照在指定 AppContainer 中创建了稳定可见窗口，提前退出的合成负对照则正确返回失败观察。尝试从商店安装原址创建带自定义 AppContainer SID 的 Telegram 进程时，`CreateProcessW` 返回 Win32 错误 87，程序还没有开始执行。[启动探针](../tools/telegram/)

为排除“只复制 EXE 就无法运行”的可能，另用普通宿主令牌启动相同 EXE 的副本，使用相同的最小环境、空工作目录和独立 Job。这个进程在 15 秒观察结束时仍有稳定窗口，界面匹配到 Telegram 欢迎页。临时日志确认使用了指定目录、本地监听已通过且 Qt 应用开始初始化。测试结束后回收了该副本及目录。

该宿主对照揭示了一个副作用。Telegram 在首次使用空工作目录时会注册 `tg`、`tonsite`、`ton` 三种协议。普通权限的副本把这三个协议和对应 `tdesktop.*` 类的图标及打开命令指向了临时 EXE。已将 12 个受影响的值按官方格式指向已签名的正式安装，核对了每个值，并验证指定商店包打开 `tg://settings` 能进入正式客户端的设置页。未指定应用时，Windows 返回应用选择器，实验未写入用户的永久默认选择。实验前未保存注册表快照，无法证明旧值逐字一致。项目已移除普通宿主副本启动功能，今后如需重复这种对照，应在一次性 Windows 用户环境或虚拟机中进行。[Telegram 注册时机与参数](https://github.com/telegramdesktop/tdesktop/blob/v7.3.3/Telegram/SourceFiles/core/application.cpp) · [对应版本的 Windows 注册实现](https://github.com/desktop-app/lib_base/blob/95a543e426e35938dd632139d0bb828b268c3b4c/base/platform/win/base_url_scheme_win.cpp)

将同一个签名 EXE 单独复制到临时 profile 后，Windows 能创建 Telegram 进程。探针在恢复执行前核实了映像、AppContainer SID 和实际能力列表。零附加能力与只授予 `internetClient` 的两次运行都创建了独立的 `tdata` 目录，随后在首个 500 毫秒采样内以退出码 0 结束，没有观察到主窗口。两次的临时启动日志都匹配到“当前实例开始启动本地服务”和“Qt 本地监听失败”，均未匹配到已有实例回复或应用初始化。这个版本的客户端在监听失败时会主动退出。[Telegram 7.3.3 启动分支](https://github.com/telegramdesktop/tdesktop/blob/v7.3.3/Telegram/SourceFiles/core/sandbox.cpp#L395-L437)

已定位的失败点是本地 IPC 监听。Telegram 在 Windows 上构造的服务名带 `Global\` 前缀，微软为 AppContainer 中的命名管道记录了 `LOCAL\` 命名要求。这个差异是根因线索，当前探针尚未单独验证命名与访问控制各自的影响。这套原生配置没有通过 Telegram 可用性验证，隔离内登录、聊天、附件和剪贴板均待测。[Telegram 的 Windows 服务命名](https://github.com/telegramdesktop/tdesktop/blob/v7.3.3/Telegram/SourceFiles/platform/win/specific_win.cpp#L374-L376) · [微软命名管道说明](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)

## 当时计划的后续试验

在装有适用引擎的独立 Windows 11 测试环境中，为两个应用各建一个持久测试盒。先用合成探针核对归属和数据边界，记录 Windows 构建、引擎版本和所选配置。通过后再用测试账号观察登录、中文输入、附件双向传输，以及关闭、重启和更新后的账号数据与进程归属。只有相应行为已通过的版本和配置才适合显示为已验证。
