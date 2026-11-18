# AppShield 文件过滤器

这是 AppShield 自己的 GPL-3.0-only Windows Filter Manager 驱动，目前用于验证本地文件打开边界。应用已有的文件句柄、注册表、剪贴板、网络和 GUI 需要各自的执行机制。驱动尚未在内核中运行验证，桌面程序不能据此将应用标为「已保护」。

## 编译与离线检查

从仓库根目录运行：

```powershell
.\tools\Build-AppShieldDriver.ps1
.\build\driver\FilterLab.exe policy-test
.\build\driver\FilterLab.exe baseline-test
```

构建目标为 x64 Windows 11 24H2 或更新版本。默认生成未签名的 `AppShieldFilter.sys` 和用户态测试程序。WDK InfVerif 使用临时 altitude 做语法校验，安装模板保留占位符。驱动发布需要适用的微软分配 altitude 和签名。构建过程保持本机驱动服务、启动安全设置和现有软件配置原状。[微软 minifilter altitude 说明](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers) · [Windows 驱动签名](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)

## 协议与进程身份

驱动公开 `\AppShieldFilterPort`，协议版本见 [Protocol.h](Protocol.h)。通信端口的默认安全描述符仅授予 SYSTEM 和管理员访问权，并核对每次消息的调用进程。将来提供给标准用户的产品应经受信任的后台服务验证目标身份及授权，再访问此端口。[微软通信端口安全描述符](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltbuilddefaultsecuritydescriptor)

1. 可信启动器先连接端口，使用受限的普通用户令牌，关闭句柄继承，在暂停态创建新程序，同时控制其 Job 生命周期。
2. 启动器向驱动提交该进程的真实句柄和不可变的目录规则。驱动在消息调用者的句柄表中解析对象，只接受由当前 broker 本次连接期间亲自创建的进程，拒绝绑定外部实例。启动器以同一进程句柄读回绑定状态，再恢复执行。绑定失败时应终止该暂停进程。
3. 子进程在创建回调中继承策略；内核同时检查实际创建者和声明的父进程，两者策略冲突则拒绝创建。进程退出时移除绑定。控制器断开不撤销已经绑定的策略。运行中的进程不能换绑策略；权限变更通过重新启动生效。

## 文件规则

每份策略最多包含 24 个本地卷目录。控制器用已打开的目录句柄取得 `VOLUME_NAME_NT | FILE_NAME_NORMALIZED` 路径。驱动按目录组件边界、精确大小写和最长匹配选择规则，等长重复项取交集。未匹配的访问默认拒绝。[共享规则实现](PathPolicy.h)

- 受管进程在 Filter Manager 已附加的卷上发起打开时，过滤器仅接受 NTFS 上 `FILE_OPEN` 方式打开已有目录或文件。它在打开之前检查访问掩码，在打开完成后重新查询规范名称与对象信息。只读规则允许读取和执行，可读写规则还允许写入获准的现有文件。未能核对完整对象、重解析结果、命名数据流和多硬链接文件均被拒绝。[打开控制](Filter.c)
- 已批准的打开操作得到流句柄上下文。受管主体读取、写入或枚举目录时，驱动核对策略归属。文件系统的分页读写由缓存和内存管理器处理，权限判定依赖最初的受控打开。
- 当前版本拒绝新建、删除、重命名、覆写方式打开，以及改变安全描述符等操作。可写文件应预先创建，应用通过 `OPEN_EXISTING` 打开后写入。真正的应用数据目录通常需要创建数据库、临时文件及原子重命名，尚缺少这些语义。Windows 系统文件也可能包含多个硬链接，可能影响程序加载。
- 文件过滤器覆盖附加实例所收到的文件操作。提权或服务代理、未附加的卷、已存在的映射区、已打开的外部进程及跨进程句柄传递，需要独立控制和验证。由内核在启动前代为映射的程序映像属于启动器的信任范围，broker 应独立验证并固定该映像。持有既有文件句柄的对象授权按打开时的策略处理，硬链接计数也只在授予句柄时检查。过滤器不会撤销其他进程早已映射的 Section。当前实验不能证明未知桌面应用形成完整隔离边界。

## 独立 Windows 驱动测试环境

在已经合法加载本驱动的专用测试 Windows 中，从有权访问通信端口的终端运行：

```powershell
.\build\driver\FilterLab.exe status
.\build\driver\FilterLab.exe verify
```

`status` 查询协议版本与绑定数量。驱动缺失、访问被拒绝或协议不符时返回非零。`verify` 仅运行控制器自己的合成子程序，使用随机临时目录。宿主先读取标记，用同一个取消管理员组权限、完整性不高于中等的令牌跑一次未受管对照，确认它原本能读取私有文件、能以写访问打开共享文件。随后用相同令牌挂起创建受管子进程，在恢复执行前绑定并核对策略，关闭 broker 连接，再核对私有文件拒读、共享文件可读、只读文件拒写、已有可写文件能更新。测试孙进程等到父进程退出并完成绑定回收后才检查自己的继承权限。未通过这些实际步骤时，发行说明只能记为未执行或失败。正式发行前还应在隔离测试机运行 Driver Verifier，验证并发、过滤器卸载、挂载变化和文件系统兼容性。
