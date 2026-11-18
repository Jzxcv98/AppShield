# Windows 私有窗口站剪贴板对照

从普通交互式 Windows PowerShell 运行，需要 MSVC x64 工具和 Windows SDK。探针在本轮专用的窗口站内运行合成客户端。

```powershell
.\tools\restricted\Test-Clipboard.ps1 -BuildOnly
.\tools\restricted\Test-Clipboard.ps1 -ClipboardStationUac
```

`-ClipboardStationUac` 让辅助进程创建、持有随机命名的非交互窗口站及桌面。普通用户进程负责设定合成标记、启动子进程和观察结果。每次打开剪贴板前都核对窗口站不可见、站名和桌面名与本轮匹配。[微软窗口站创建权限](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowstationw) · [Windows Job UI 限制](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions)

| 私有测试站内的进程 | 读取原标记 | 清空原内容 | 发布新标记 |
| --- | --- | --- | --- |
| 普通进程 | 成功 | 成功 | 成功 |
| 加入限制读写剪贴板及桌面的 Job | 被阻止 | 成功 | 被阻止 |
| 核实 AppContainer SID 后加入相同 Job | 被阻止 | 成功 | 被阻止 |
| 在该专用站对测试 SID 设置 `WINSTA_ACCESSCLIPBOARD` 拒绝规则后重新启动 AppContainer + Job | 被阻止 | 成功 | 被阻止 |

三组受限子进程均创建了消息窗口。它们能打开并清空合成剪贴板，随后宿主的 Unicode 文本格式消失且序号改变。程序会针对原内容未得到保留返回非零。每轮关闭专属窗口站、桌面和 Job，并删除本轮新建的 AppContainer profile。

## 宿主微信的剪贴板限制

从仓库根目录运行以下对照。第一项验证 AppShield 关闭匿名 Job 句柄后，合成进程和新建子进程仍具有 `READCLIPBOARD | WRITECLIPBOARD`（0x6）。第二项在专属不可见窗口站里使用同一个产品绑定方法，普通对照能读写合成文本，受管进程不能读回或发布该文本，但仍能清空它。该项创建临时窗口站时需要 UAC 确认。

```powershell
.\tools\Build-AppShield.ps1 -Test
.\build\checks\DesktopChecks.exe --wechat-clipboard-test
.\tools\restricted\Test-Clipboard.ps1 -WeChatClipboardJob
```
